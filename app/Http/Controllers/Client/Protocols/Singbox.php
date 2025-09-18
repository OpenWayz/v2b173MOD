<?php
namespace App\Http\Controllers\Client\Protocols;

use App\Models\User;
use App\Utils\Helper;

class Singbox
{
    public $flag = 'sing';
    private $servers;
    private $user;
    private $config;

    public function __construct($user, $servers, array $options = null)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $appName = config('v2board.app_name', 'V2Board');
        $this->config = $this->loadConfig();
        $proxies = $this->buildProxies();
        $outbounds = $this->addProxies($proxies);
        $this->config['outbounds'] = $outbounds;
        $user = $this->user;

        return response(json_encode($this->config, JSON_UNESCAPED_SLASHES), 200)
            ->header('Content-Type', 'application/json')
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24')
            ->header('Profile-Title', 'base64:' . base64_encode($appName))
            ->header('Content-Disposition', 'attachment; filename="' . $appName . '"');
    }

    protected function loadConfig()
    {
        $defaultConfig = base_path('resources/rules/default.sing-box.json');
        $customConfig = base_path('resources/rules/custom.sing-box.json');
        $jsonData = file_exists($customConfig) ? file_get_contents($customConfig) : file_get_contents($defaultConfig);

        return json_decode($jsonData, true);
    }

    protected function buildProxies()
    {
        $proxies = [];
    
        foreach ($this->servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                $ssConfig = $this->buildShadowsocks($this->user['uuid'], $item);
                $proxies[] = $ssConfig;
            }
            if ($item['type'] === 'trojan') {
                $trojanConfig = $this->buildTrojan($this->user['uuid'], $item);
                $proxies[] = $trojanConfig;
            }
            if ($item['type'] === 'vmess') {
                $vmessConfig = $this->buildVmess($this->user['uuid'], $item);
                $proxies[] = $vmessConfig;
            }
            if ($item['type'] === 'vless') {
                $vlessConfig = $this->buildVless($this->user['uuid'], $item);
                $proxies[] = $vlessConfig;
            }
            if ($item['type'] === 'hysteria') {
                $hysteriaConfig = $this->buildHysteria($this->user['uuid'], $item, $this->user);
                $proxies[] = $hysteriaConfig;
            }
        }
    
        return $proxies;
    }

    protected function addProxies($proxies)
    {
        foreach ($this->config['outbounds'] as &$outbound) {
            if (($outbound['type'] === 'selector' && $outbound['tag'] === '节点选择') || ($outbound['type'] === 'urltest' && $outbound['tag'] === '自动选择') || ($outbound['type'] === 'selector' && strpos($outbound['tag'], '#') === 0 )) {
                array_push($outbound['outbounds'], ...array_column($proxies, 'tag'));
            }
        }
        unset($outbound);
        $outbounds = array_merge($this->config['outbounds'], $proxies);
        return $outbounds;
    }

    protected function buildShadowsocks($password, $server)
    {
        if (strpos($server['cipher'], '2022-blake3') !== false) {
            $length = $server['cipher'] === '2022-blake3-aes-128-gcm' ? 16 : 32;
            $serverKey = Helper::getShadowsocksServerKey($server['created_at'], $length);
            $userKey = Helper::uuidToBase64($password, $length);
            $password = "{$serverKey}:{$userKey}";
        }
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'shadowsocks';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['method'] = $server['cipher'];
        $array['password'] = $password;
        $array['domain_resolver'] = 'local';

        return $array;
    }


    protected function buildVmess($uuid, $server)
    {
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'vmess';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['uuid'] = $uuid;
        $array['security'] = 'auto';
        $array['alter_id'] = 0;
        $array['transport']= [];
        $array['domain_resolver'] = 'local';

        if ($server['tls']) {
            $tlsConfig = [];
            $tlsConfig['enabled'] = true;
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'] ?? [];
                $tlsConfig['insecure'] = $tlsSettings['allowInsecure'] ? true : false;
                $tlsConfig['server_name'] = $tlsSettings['serverName'] ?? null;
            }
            $array['tls'] = $tlsConfig;
        }
        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type']) && $tcpSettings['header']['type'] == 'http') $array['transport']['type'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['headers']['Host'])) $array['transport']['host'] = $tcpSettings['header']['request']['headers']['Host'];
            if (isset($tcpSettings['header']['request']['path'][0])) $array['transport']['path'] = $tcpSettings['header']['request']['path'][0];
        }
        if ($server['network'] === 'ws') {
            $array['transport']['type'] ='ws';
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path'])) $array['transport']['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host'])) $array['transport']['headers'] = ['Host' => array($wsSettings['headers']['Host'])];
                $array['transport']['max_early_data'] = 2048;
                $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
                if (isset($wsSettings['security'])) {
                    $array['security'] = $wsSettings['security'];
                }
            }
        }
        if ($server['network'] === 'grpc') {
            $array['transport']['type'] ='grpc';
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                if (isset($grpcSettings['serviceName'])) $array['transport']['service_name'] = $grpcSettings['serviceName'];
            }
        }

        return $array;
    }


    protected function buildTrojan($password, $server) 
    {
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'trojan';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['password'] = $password;
        $array['domain_resolver'] = 'local';

        $array['tls'] = [
            'enabled' => true,
            'insecure' => $server['allow_insecure'] ? true : false,
            'server_name' => $server['server_name']
        ];

        return $array;
    }
}
