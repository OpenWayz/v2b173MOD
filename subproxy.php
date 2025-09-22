<?php
/**
 * subproxy.php
 * 通用订阅抓取 -> 解析 -> 生成 Clash YAML 并下载
 *
 * 说明：
 *  - 使用 UA "clash" 请求订阅源（部分订阅源要求 UA 为 clash）
 *  - 简单校验 URL 与 SSRF 防护（阻止内网/保留地址）
 *  - 支持 vmess/trojan/vless（尽力解析常见字段），可根据需要扩展 ss/ssr
 */

// 允许跨域（如果前端 fetch）
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

function respondError($message, $code = 400) {
    http_response_code($code);
    header("Content-Type: text/plain; charset=utf-8");
    echo $message;
    exit;
}

// 获取 url
if (!isset($_GET['url']) || !trim($_GET['url'])) {
    respondError("Missing url parameter", 400);
}
$url = trim($_GET['url']);

// 必须以 http 或 https 开头
if (!preg_match('#^https?://#i', $url)) {
    respondError("Invalid URL schema", 400);
}

// 简单 SSRF 防护：解析主机并判断解析到的 IP 是否为私有/保留地址
$host = parse_url($url, PHP_URL_HOST);
if (!$host) {
    respondError("Invalid host", 400);
}

// 解析 DNS（取第一个 A 记录）
$resolved = gethostbyname($host);
if ($resolved === $host) {
    // 解析失败或仍是域名（DNS 未解析到 IP），我们允许继续（某些环境可能返回域名）
    // 但尽量尝试解析另一些记录（可选）
} else {
    // 检查是否为私网 IP
    if (filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = sprintf("%u", ip2long($resolved));
        $privateRanges = [
            ['start' => ip2long('10.0.0.0'),      'end' => ip2long('10.255.255.255')],
            ['start' => ip2long('127.0.0.0'),     'end' => ip2long('127.255.255.255')],
            ['start' => ip2long('172.16.0.0'),    'end' => ip2long('172.31.255.255')],
            ['start' => ip2long('192.168.0.0'),   'end' => ip2long('192.168.255.255')],
            ['start' => ip2long('169.254.0.0'),   'end' => ip2long('169.254.255.255')],
            ['start' => ip2long('100.64.0.0'),    'end' => ip2long('100.127.255.255')], // CGNAT
        ];
        foreach ($privateRanges as $r) {
            if ($long >= $r['start'] && $long <= $r['end']) {
                respondError("Host resolves to a private/reserved IP (blocked)", 403);
            }
        }
    }
    // IPv6 检查可按需添加
}

// 使用 curl 请求订阅地址（UA = "clash"）
function fetchUrl($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_ENCODING, ""); // 支持 gzip
    curl_setopt($ch, CURLOPT_USERAGENT, "clash"); // 按你要求使用 "clash"
    $data = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    return [$code, $data, $err];
}

list($code, $body, $err) = fetchUrl($url);
if ($code !== 200 || $body === false || $body === null || trim($body) === '') {
    respondError("Failed to fetch subscription (HTTP {$code}) : {$err}", 502);
}

// 若内容看起来像是完整的 Clash YAML（包含 proxies 或 proxy-groups），直接返回它
$trimmed = trim($body);
if (stripos($trimmed, "proxies:") !== false || stripos($trimmed, "proxy-groups:") !== false) {
    $yamlOut = $trimmed;
    $filename = "clash-config-" . date("YmdHis") . ".yaml";
    header("Content-Type: application/x-yaml; charset=utf-8");
    header("Content-Disposition: attachment; filename=\"{$filename}\"");
    echo $yamlOut;
    exit;
}

// 有些订阅是 base64 编码（单行或多行），尝试解 base64
$maybe = trim($body);
// 如果只有 base64 字符且长度较长，尝试 decode
if (preg_match('/^[A-Za-z0-9\/+\r\n=]+$/', $maybe) && strlen($maybe) > 50) {
    $decoded = base64_decode($maybe, true);
    if ($decoded !== false && strlen(trim($decoded)) > 0) {
        $body = $decoded;
    }
}

// 按行解析所有节点
$lines = preg_split('/\r?\n/', trim($body));
$nodes = [];

foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '') continue;

    // vmess:// base64json
    if (stripos($line, "vmess://") === 0) {
        $b = substr($line, 8);
        $json = base64_decode($b, true);
        if ($json === false) continue;
        $o = json_decode($json, true);
        if (!$o) continue;
        $name = $o['ps'] ?? ($o['add'] . ':' . ($o['port'] ?? ''));
        $network = $o['net'] ?? 'tcp';
        $tls = (!empty($o['tls']) && ($o['tls'] === 'tls' || $o['tls'] === '1')) ? true : false;
        $wsPath = $o['path'] ?? ($o['host'] ?? '');
        $headersHost = $o['host'] ?? '';
        $nodes[] = [
            'name' => $name,
            'type' => 'vmess',
            'server' => $o['add'] ?? '',
            'port' => isset($o['port']) ? (int)$o['port'] : 0,
            'uuid' => $o['id'] ?? '',
            'alterId' => isset($o['aid']) ? (int)$o['aid'] : 0,
            'cipher' => $o['scy'] ?? 'auto',
            'network' => $network,
            'ws-path' => $wsPath,
            'ws-headers-host' => $headersHost,
            'tls' => $tls,
        ];
        continue;
    }

    // trojan://password@host:port?query#name
    if (stripos($line, "trojan://") === 0) {
        $tmp = $line;
        // remove scheme
        $after = substr($tmp, 9);
        // parse via parse_url by adding scheme
        $u = parse_url($line);
        // parse query
        $qs = [];
        if (!empty($u['query'])) parse_str($u['query'], $qs);
        $name = isset($u['fragment']) ? urldecode($u['fragment']) : ($u['host'] ?? 'trojan');
        $network = (isset($qs['type']) && $qs['type'] === 'ws') ? 'ws' : 'tcp';
        $wsPath = $qs['path'] ?? ($qs['wsPath'] ?? '');
        $nodes[] = [
            'name' => $name,
            'type' => 'trojan',
            'server' => $u['host'] ?? '',
            'port' => isset($u['port']) ? (int)$u['port'] : 443,
            'password' => isset($u['user']) ? $u['user'] : (isset($u['pass']) ? $u['pass'] : ''),
            'network' => $network,
            'ws-path' => $wsPath,
            'tls' => true,
            'sni' => $qs['sni'] ?? ($u['host'] ?? ''),
        ];
        continue;
    }

    // vless://uuid@host:port?query#name
    if (stripos($line, "vless://") === 0) {
        $u = parse_url($line);
        $qs = [];
        if (!empty($u['query'])) parse_str($u['query'], $qs);
        $name = isset($u['fragment']) ? urldecode($u['fragment']) : ($u['host'] ?? 'vless');
        $network = (isset($qs['type']) && $qs['type'] === 'ws') ? 'ws' : 'tcp';
        $wsPath = $qs['path'] ?? '';
        $nodes[] = [
            'name' => $name,
            'type' => 'vless',
            'server' => $u['host'] ?? '',
            'port' => isset($u['port']) ? (int)$u['port'] : 443,
            'uuid' => $u['user'] ?? '',
            'network' => $network,
            'ws-path' => $wsPath,
            'tls' => true,
            'sni' => $qs['sni'] ?? ($u['host'] ?? ''),
        ];
        continue;
    }

    // 其它行：可能是 plain vmess json list, 或者 ss/ssr（未实现）
    // 如果单行是 JSON 数组/对象，尝试解析成 vmess array
    if ($line[0] === '{' || $line[0] === '[') {
        $tmp = json_decode($line, true);
        if ($tmp) {
            // 如果数组，尝试按 vmess-like 结构导出
            if (isset($tmp['add']) && isset($tmp['port'])) {
                // single vmess json
                $o = $tmp;
                $nodes[] = [
                    'name' => $o['ps'] ?? ($o['add'] . ':' . ($o['port'] ?? '')),
                    'type' => 'vmess',
                    'server' => $o['add'] ?? '',
                    'port' => isset($o['port']) ? (int)$o['port'] : 0,
                    'uuid' => $o['id'] ?? '',
                    'alterId' => isset($o['aid']) ? (int)$o['aid'] : 0,
                    'cipher' => $o['scy'] ?? 'auto',
                    'network' => $o['net'] ?? 'tcp',
                    'ws-path' => $o['path'] ?? '',
                    'tls' => (!empty($o['tls']) && ($o['tls']=='tls')) ? true : false,
                ];
            }
        }
        continue;
    }

    // 未识别，跳过
}

// 如果没有解析出节点，返回错误
if (empty($nodes)) {
    respondError("No supported nodes found in subscription", 422);
}

// ====== 节点过滤逻辑 ======

// 生成 YAML 字符串（简单版，兼容 Clash）
function yaml_escape($s) {
    // 简单转义双引号和反斜杠
    $s = str_replace('"', '\"', $s);
    return $s;
}

$yaml = "";
$yaml .= "port: 7890\n";
$yaml .= "socks-port: 7891\n";
$yaml .= "allow-lan: false\n";
$yaml .= "mode: Rule\n";
$yaml .= "log-level: info\n\n";

$yaml .= "proxies:\n";
foreach ($nodes as $n) {
    $name = yaml_escape($n['name']);
    $yaml .= "  - name: \"{$name}\"\n";
    $type = $n['type'];
    $yaml .= "    type: {$type}\n";
    $yaml .= "    server: {$n['server']}\n";
    $yaml .= "    port: {$n['port']}\n";
    if ($type === 'vmess') {
        $yaml .= "    uuid: {$n['uuid']}\n";
        if (!empty($n['alterId'])) $yaml .= "    alterId: {$n['alterId']}\n";
        $yaml .= "    cipher: {$n['cipher']}\n";
        $yaml .= "    tls: " . ($n['tls'] ? 'true' : 'false') . "\n";
        $yaml .= "    network: {$n['network']}\n";
        if (!empty($n['ws-path']) || !empty($n['ws-headers-host'])) {
            $yaml .= "    ws-opts:\n";
            if (!empty($n['ws-path'])) $yaml .= "      path: \"{$n['ws-path']}\"\n";
            $yaml .= "      headers:\n";
            $hostHeader = $n['ws-headers-host'] ?: $n['server'];
            $yaml .= "        Host: \"{$hostHeader}\"\n";
        }
    } elseif ($type === 'trojan') {
        $yaml .= "    password: \"{$n['password']}\"\n";
        $yaml .= "    sni: \"{$n['sni']}\"\n";
        $yaml .= "    tls: true\n";
        $yaml .= "    network: {$n['network']}\n";
        if (!empty($n['ws-path'])) {
            $yaml .= "    ws-opts:\n";
            $yaml .= "      path: \"{$n['ws-path']}\"\n";
            $yaml .= "      headers:\n";
            $yaml .= "        Host: \"{$n['server']}\"\n";
        }
    } elseif ($type === 'vless') {
        $yaml .= "    uuid: {$n['uuid']}\n";
        $yaml .= "    tls: true\n";
        $yaml .= "    network: {$n['network']}\n";
        if (!empty($n['ws-path'])) {
            $yaml .= "    ws-opts:\n";
            $yaml .= "      path: \"{$n['ws-path']}\"\n";
            $yaml .= "      headers:\n";
            $yaml .= "        Host: \"{$n['server']}\"\n";
        }
    } else {
        // fallback: just dump raw
    }
    $yaml .= "\n";
}

// proxy-groups
$yaml .= "proxy-groups:\n";
$yaml .= "  - name: \"Auto\"\n";
$yaml .= "    type: select\n";
$yaml .= "    proxies:\n";
foreach ($nodes as $n) {
    $nm = yaml_escape($n['name']);
    $yaml .= "      - \"{$nm}\"\n";
}
$yaml .= "\n";

// rules
$yaml .= "rules:\n";
$yaml .= "  - MATCH,Auto\n";

// 输出下载
$filename = "clash-config-" . date("YmdHis") . ".yaml";
header("Content-Type: application/x-yaml; charset=utf-8");
header("Content-Disposition: attachment; filename=\"{$filename}\"");
echo $yaml;
exit;
