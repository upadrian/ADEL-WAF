<?php

declare(strict_types=1);

namespace AdelWAF\Config;

use InvalidArgumentException;

/**
 * Resolved, validated configuration. Built only from files (PHP array / JSON)
 * plus optional drop-ins in config.d/*.json. Never reads request data.
 */
final class Config
{
    public const CONTRACT_VERSION = 1;

    /** @var array<string,mixed> */
    private array $data;

    private string $source;

    /** @param array<string,mixed> $data */
    private function __construct(array $data, string $source)
    {
        $this->data = $data;
        $this->source = $source;
    }

    /** @return array<string,mixed> */
    public static function defaults(): array
    {
        return [
            // off | monitor | block
            'mode' => 'monitor',
            // Where logs, bans, counters and downloaded rule packs live. null = ~/.adel-waf or sys temp.
            'state_dir' => null,
            'excluded_hosts' => [],
            'excluded_paths' => [],
            // {path: fnmatch, param: fnmatch, rules: [rule id | category | '*']}
            'exclusions' => [],
            'allowlist' => [],
            'denylist' => [],
            // CIDRs or the alias "cloudflare". Forwarded headers are only honoured from these peers.
            'trusted_proxies' => [],
            'client_ip_header' => 'X-Forwarded-For',
            'storage' => [
                // auto | redis | file | memory | none
                'driver' => 'auto',
                'prefix' => 'adelwaf:',
                'redis' => [
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'socket' => null,
                    'password' => null,
                    'database' => 0,
                    'timeout' => 0.1,
                ],
            ],
            'rules' => [
                'threshold' => 5,
                'paranoia' => 1,
                'disable' => [],
                'scores' => [],
                'custom' => [],
                // Updates
                'source' => null,
                'public_keys' => [],
                'require_signature' => true,
                'keep_versions' => 5,
            ],
            'limits' => [
                'max_args' => 1000,
                'max_value_len' => 8192,
                'max_body_bytes' => 1048576,
                'max_uri_len' => 8192,
                'normalize_depth' => 3,
                'allowed_methods' => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            ],
            // [{name, limit, window, paths?: [fnmatch], methods?: [..], ban?: seconds}]
            'rate_limits' => [],
            'ban' => ['duration' => 3600, 'ban_on_block_score' => 0],
            'uploads' => ['inspect_content' => true],
            'logging' => [
                'enabled' => true,
                'path' => null,
                'max_bytes' => 10485760,
                'keep' => 5,
                'redis_events' => false,
                'redis_events_max' => 10000,
            ],
            'notify' => ['enabled' => false, 'email' => '', 'max_per_hour' => 5],
            'response' => [
                'block_status' => 403,
                'rate_limit_status' => 429,
                'template' => null,
                'security_headers' => false,
            ],
        ];
    }

    /** @param array<string,mixed> $overrides */
    public static function fromArray(array $overrides, string $source = 'array'): self
    {
        $data = self::merge(self::defaults(), $overrides);
        self::validate($data);

        return new self($data, $source);
    }

    /**
     * Search order: explicit path > ADEL_WAF_CONFIG env > waf.local.php next to $baseDir > ~/.config/adel-waf/waf.php.
     * Missing config falls back to defaults (monitor mode).
     */
    public static function load(?string $path = null, ?string $baseDir = null): self
    {
        $candidates = [];
        if ($path !== null) {
            $candidates[] = $path;
        }
        $env = getenv('ADEL_WAF_CONFIG');
        if ($env === false && isset($_SERVER['ADEL_WAF_CONFIG'])) {
            $env = (string) $_SERVER['ADEL_WAF_CONFIG'];
        }
        if (is_string($env) && $env !== '') {
            $candidates[] = $env;
        }
        if ($baseDir !== null) {
            $candidates[] = rtrim($baseDir, '/\\') . '/waf.local.php';
            $candidates[] = rtrim($baseDir, '/\\') . '/waf.local.json';
        }
        $home = self::homeDir();
        if ($home !== null) {
            $candidates[] = $home . '/.config/adel-waf/waf.php';
            $candidates[] = $home . '/.config/adel-waf/waf.json';
        }

        foreach ($candidates as $file) {
            if (is_file($file)) {
                $data = self::readFile($file);
                $dropins = dirname($file) . '/config.d';
                if (is_dir($dropins)) {
                    $files = glob($dropins . '/*.json') ?: [];
                    sort($files);
                    foreach ($files as $extra) {
                        $data = self::merge($data, self::readFile($extra));
                    }
                }

                return self::fromArray($data, $file);
            }
        }

        return self::fromArray([], 'defaults');
    }

    /** @return array<string,mixed> */
    private static function readFile(string $file): array
    {
        if (str_ends_with($file, '.json')) {
            $decoded = json_decode((string) file_get_contents($file), true);
            if (!is_array($decoded)) {
                throw new InvalidArgumentException("Invalid JSON config: $file");
            }

            return $decoded;
        }
        $data = (static function (string $f) {
            return require $f;
        })($file);
        if (!is_array($data)) {
            throw new InvalidArgumentException("Config file must return an array: $file");
        }

        return $data;
    }

    /**
     * @param array<string,mixed> $base
     * @param array<string,mixed> $over
     * @return array<string,mixed>
     */
    private static function merge(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            if (is_array($v) && isset($base[$k]) && is_array($base[$k]) && self::isAssoc($v) && self::isAssoc($base[$k])) {
                $base[$k] = self::merge($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }

        return $base;
    }

    /** @param array<mixed> $a */
    private static function isAssoc(array $a): bool
    {
        return $a !== [] && array_keys($a) !== range(0, count($a) - 1);
    }

    /** @param array<string,mixed> $d */
    private static function validate(array $d): void
    {
        if (!in_array($d['mode'], ['off', 'monitor', 'block'], true)) {
            throw new InvalidArgumentException('mode must be off, monitor or block');
        }
        if (!in_array($d['storage']['driver'], ['auto', 'redis', 'file', 'memory', 'none'], true)) {
            throw new InvalidArgumentException('storage.driver must be auto, redis, file, memory or none');
        }
        if (!is_int($d['rules']['threshold']) || $d['rules']['threshold'] < 1) {
            throw new InvalidArgumentException('rules.threshold must be a positive integer');
        }
        if (!in_array($d['rules']['paranoia'], [1, 2, 3], true)) {
            throw new InvalidArgumentException('rules.paranoia must be 1, 2 or 3');
        }
        foreach ($d['rate_limits'] as $i => $rl) {
            if (!is_array($rl) || !isset($rl['name'], $rl['limit'], $rl['window'])
                || (int) $rl['limit'] < 1 || (int) $rl['window'] < 1) {
                throw new InvalidArgumentException("rate_limits[$i] needs name, limit >= 1 and window >= 1");
            }
        }
        foreach (['allowlist', 'denylist', 'trusted_proxies', 'excluded_hosts', 'excluded_paths', 'exclusions'] as $k) {
            if (!is_array($d[$k])) {
                throw new InvalidArgumentException("$k must be an array");
            }
        }
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function get(string $path, $default = null)
    {
        $cur = $this->data;
        foreach (explode('.', $path) as $part) {
            if (!is_array($cur) || !array_key_exists($part, $cur)) {
                return $default;
            }
            $cur = $cur[$part];
        }

        return $cur;
    }

    /** @return array<string,mixed> */
    public function all(): array
    {
        return $this->data;
    }

    public function source(): string
    {
        return $this->source;
    }

    public function hash(): string
    {
        return substr(sha1((string) json_encode($this->data)), 0, 12);
    }

    public function mode(): string
    {
        return (string) $this->data['mode'];
    }

    /** Resolve (and create, 0700) the state directory. Never inside the web root by default. */
    public function stateDir(): string
    {
        $dir = $this->data['state_dir'];
        if (!is_string($dir) || $dir === '') {
            $home = self::homeDir();
            $dir = $home !== null ? $home . '/.adel-waf' : sys_get_temp_dir() . '/adel-waf-' . substr(sha1(__DIR__), 0, 8);
        }
        $dir = rtrim(str_replace('\\', '/', $dir), '/');
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }

        return $dir;
    }

    public static function homeDir(): ?string
    {
        foreach (['HOME', 'USERPROFILE'] as $v) {
            $h = getenv($v);
            if (is_string($h) && $h !== '' && is_dir($h)) {
                return rtrim(str_replace('\\', '/', $h), '/');
            }
        }
        if (function_exists('posix_getpwuid') && function_exists('posix_getuid')) {
            $pw = @posix_getpwuid(posix_getuid());
            if (is_array($pw) && isset($pw['dir']) && is_dir($pw['dir'])) {
                return rtrim($pw['dir'], '/');
            }
        }

        return null;
    }
}
