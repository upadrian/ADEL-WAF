<?php

declare(strict_types=1);

namespace AdelWAF\Storage;

/**
 * Redis backend (ext-redis, or Predis when installed). Every key is namespaced with the
 * configured prefix so several accounts can share one Redis instance.
 * Key schema (documented contract): {prefix}c:* counters, {prefix}ban:{ip} bans, {prefix}list:events.
 */
final class RedisStorage implements StorageInterface
{
    /** @var \Redis|\Predis\Client */
    private $r;

    private bool $native;

    /**
     * @param array<string,mixed> $cfg host, port, socket, password, database, timeout
     * @throws \RuntimeException when no client is available or the connection fails
     */
    public function __construct(array $cfg, private string $prefix)
    {
        $timeout = (float) ($cfg['timeout'] ?? 0.1);
        if (class_exists(\Redis::class)) {
            $this->native = true;
            $r = new \Redis();
            $ok = !empty($cfg['socket'])
                ? @$r->connect((string) $cfg['socket'])
                : @$r->connect((string) ($cfg['host'] ?? '127.0.0.1'), (int) ($cfg['port'] ?? 6379), $timeout);
            if (!$ok) {
                throw new \RuntimeException('Redis connect failed');
            }
            $r->setOption(\Redis::OPT_READ_TIMEOUT, max($timeout, 0.05));
            if (!empty($cfg['password'])) {
                $r->auth($cfg['password']);
            }
            if (!empty($cfg['database'])) {
                $r->select((int) $cfg['database']);
            }
            $this->r = $r;
            $r->ping();
        } elseif (class_exists(\Predis\Client::class)) {
            $this->native = false;
            $params = !empty($cfg['socket'])
                ? ['scheme' => 'unix', 'path' => $cfg['socket']]
                : ['scheme' => 'tcp', 'host' => $cfg['host'] ?? '127.0.0.1', 'port' => $cfg['port'] ?? 6379];
            $params['timeout'] = $timeout;
            $params['read_write_timeout'] = max($timeout, 0.05);
            if (!empty($cfg['password'])) {
                $params['password'] = $cfg['password'];
            }
            if (!empty($cfg['database'])) {
                $params['database'] = (int) $cfg['database'];
            }
            $this->r = new \Predis\Client($params);
            $this->r->ping();
        } else {
            throw new \RuntimeException('Neither ext-redis nor predis/predis is available');
        }
    }

    public static function available(): bool
    {
        return class_exists(\Redis::class) || class_exists(\Predis\Client::class);
    }

    public function incr(string $key, int $ttl): int
    {
        $k = $this->prefix . $key;
        $n = (int) $this->r->incr($k);
        if ($n === 1 && $ttl > 0) {
            $this->r->expire($k, $ttl);
        }

        return $n;
    }

    public function get(string $key): ?string
    {
        $v = $this->r->get($this->prefix . $key);

        return $v === false || $v === null ? null : (string) $v;
    }

    public function set(string $key, string $value, int $ttl = 0): void
    {
        $k = $this->prefix . $key;
        if ($ttl > 0) {
            $this->r->setex($k, $ttl, $value);
        } else {
            $this->r->set($k, $value);
        }
    }

    public function delete(string $key): void
    {
        $this->r->del([$this->prefix . $key]);
    }

    public function scan(string $prefix): array
    {
        $out = [];
        $match = $this->prefix . $prefix . '*';
        $strip = strlen($this->prefix);
        if ($this->native) {
            $it = null;
            while (($keys = $this->r->scan($it, $match, 200)) !== false) {
                foreach ($keys as $k) {
                    $v = $this->r->get($k);
                    if ($v !== false) {
                        $out[substr($k, $strip)] = (string) $v;
                    }
                }
                if ($it === 0 || $it === null) {
                    break;
                }
            }
        } else {
            foreach (new \Predis\Collection\Iterator\Keyspace($this->r, $match, 200) as $k) {
                $v = $this->r->get($k);
                if ($v !== null) {
                    $out[substr($k, $strip)] = (string) $v;
                }
            }
        }

        return $out;
    }

    public function push(string $list, string $value, int $max): void
    {
        $k = $this->prefix . 'list:' . $list;
        $this->r->lpush($k, $value);
        $this->r->ltrim($k, 0, max($max - 1, 0));
    }

    public function driver(): string
    {
        return 'redis';
    }
}
