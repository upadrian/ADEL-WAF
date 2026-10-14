<?php

declare(strict_types=1);

namespace AdelWAF\Integration;

use AdelWAF\Config\Config;
use AdelWAF\Http\Request;
use AdelWAF\Response\BlockResponder;
use AdelWAF\Waf;

/**
 * Entry point for auto_prepend_file and for any framework: Bootstrap::run().
 * Fail-open: an internal WAF error is logged and the request continues untouched.
 */
final class Bootstrap
{
    public static function run(?string $configPath = null, ?string $baseDir = null): void
    {
        if (PHP_SAPI === 'cli' || defined('ADEL_WAF_RUNNING')) {
            return;
        }
        define('ADEL_WAF_RUNNING', true);

        try {
            $config = Config::load($configPath, $baseDir);
            if ($config->mode() === 'off') {
                return;
            }
            $request = Request::fromGlobals(
                array_map('strval', (array) $config->get('trusted_proxies', [])),
                (string) $config->get('client_ip_header', 'X-Forwarded-For'),
                (int) $config->get('limits.max_body_bytes', 1048576),
            );
            $waf = Waf::fromConfig($config);
            $decision = $waf->handle($request);
            if ($decision->blocks()) {
                (new BlockResponder(
                    $config->get('response.template'),
                    (bool) $config->get('response.security_headers', false),
                ))->send($request, $decision);
            }
        } catch (\Throwable $e) {
            error_log('[adel-waf] internal error, failing open: ' . $e->getMessage());
        }
    }
}
