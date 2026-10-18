<?php

namespace App\Http\Controllers\Passport;

use App\Http\Requests\Passport\CommSendEmailVerify;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use App\Utils\Helper;
use Illuminate\Support\Facades\Cache;
use App\Jobs\SendEmailJob;
use App\Models\InviteCode;
use App\Utils\Dict;
use App\Utils\CacheKey;
use ReCaptcha\ReCaptcha;
use Illuminate\Support\Facades\RateLimiter;

class CommController extends Controller
{
    private function isEmailVerify()
    {
        return response([
            'data' => (int)config('v2board.email_verify', 0) ? 1 : 0
        ]);
    }

    public function sendEmailVerify(CommSendEmailVerify $request)
    {
        $ip = $request->ip();
        if (RateLimiter::tooManyAttempts($ip, 3)) {
            abort(429, __('Too many requests, please try again later.'));
        }
        RateLimiter::hit($ip, 60);
        
        if ((int)config('v2board.recaptcha_enable', 0)) {
            $recaptcha = new ReCaptcha(config('v2board.recaptcha_key'));
            $recaptchaResp = $recaptcha->verify($request->input('recaptcha_data'));
            if (!$recaptchaResp->isSuccess()) {
                abort(500, __('Invalid code is incorrect'));
            }
        }
        $email = $request->input('email');
        $cacheKeyEmail = strtolower(trim((string)$email));
        if (Cache::get(CacheKey::get('LAST_SEND_EMAIL_VERIFY_TIMESTAMP', $cacheKeyEmail))) {
            abort(500, __('Email verification code has been sent, please request again later'));
        }
        $code = (string)rand(100000, 999999);
        $subject = config('v2board.app_name', 'V2Board') . __('Email verification code');

        SendEmailJob::dispatch([
            'email' => $email,
            'subject' => $subject,
            'template_name' => 'verify',
            'template_value' => [
                'name' => config('v2board.app_name', 'V2Board'),
                'code' => $code,
                'url' => config('v2board.app_url')
            ]
        ]);

        Cache::put(CacheKey::get('EMAIL_VERIFY_CODE', $cacheKeyEmail), $code, 300);
        Cache::put(CacheKey::get('LAST_SEND_EMAIL_VERIFY_TIMESTAMP', $cacheKeyEmail), time(), 60);
        return response([
            'data' => true
        ]);
    }

    public function pv(Request $request)
    {
        $inviteCode = InviteCode::where('code', $request->input('invite_code'))->first();
        if ($inviteCode) {
            $inviteCode->pv = $inviteCode->pv + 1;
            $inviteCode->save();
        }

        return response([
            'data' => true
        ]);
    }

    private function getEmailSuffix()
    {
        $suffix = config('v2board.email_whitelist_suffix', Dict::EMAIL_WHITELIST_SUFFIX_DEFAULT);
        if (!is_array($suffix)) {
            return preg_split('/,/', $suffix);
        }
        return $suffix;
    }
}
