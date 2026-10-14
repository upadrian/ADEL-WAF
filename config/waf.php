<?php

/**
 * AdelWAF configuration. Copy to one of:
 *   - the path in the ADEL_WAF_CONFIG environment variable
 *   - waf.local.php next to prepend.php
 *   - ~/.config/adel-waf/waf.php
 * Only list what you want to change; everything else uses the defaults (see Config::defaults()).
 * Validate with:  php bin/adel-waf check-config
 */

return [
    // 'off' | 'monitor' (log only, never blocks - start here) | 'block'
    'mode' => 'monitor',

    // Logs, bans, counters and downloaded rule packs. Keep it OUTSIDE public_html.
    'state_dir' => null, // default: ~/.adel-waf

    'excluded_hosts' => [],
    'excluded_paths' => [],      // fnmatch globs, e.g. '/webhooks/*'
    'allowlist' => [],           // IPs / CIDRs that bypass everything, e.g. your office
    'denylist' => [],

    // Honour X-Forwarded-For only from these peers. Behind Cloudflare: ['cloudflare'].
    'trusted_proxies' => [],

    // 'auto' tries Redis then falls back to files. Use 'file' to never touch Redis.
    'storage' => [
        'driver' => 'auto',
        'prefix' => 'adelwaf:',   // keep unique per account on shared Redis
        'redis' => ['host' => '127.0.0.1', 'port' => 6379, 'socket' => null, 'password' => null, 'database' => 0, 'timeout' => 0.1],
    ],

    'rules' => [
        'threshold' => 5,         // block when the summed score reaches this
        'paranoia' => 1,          // 1 = fewest false positives, 3 = strictest
        'disable' => [],          // rule ids to switch off, e.g. ['xss-007']
        'scores' => [],           // ['sqli-003' => 3]
        'custom' => [],
        // Signed updates: 'source' => 'https://example.org/adel-waf-rules/stable', 'public_keys' => ['<base64 ed25519>']
    ],

    // Skip rules for known-safe inputs, e.g. an admin rich-text editor.
    'exclusions' => [
        // ['path' => '/admin/*', 'param' => 'content', 'rules' => ['xss']],
    ],

    'rate_limits' => [
        // ['name' => 'login', 'paths' => ['/login', '/admin/login'], 'methods' => ['POST'], 'limit' => 10, 'window' => 60, 'ban' => 900],
        // ['name' => 'global', 'limit' => 300, 'window' => 60],
    ],

    'ban' => ['duration' => 3600, 'ban_on_block_score' => 0], // >0: auto-ban IPs whose blocked request scores at least that

    'logging' => ['enabled' => true, 'redis_events' => false],
    'notify' => ['enabled' => false, 'email' => '', 'max_per_hour' => 5],
];
