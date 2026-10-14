<?php

declare(strict_types=1);

namespace AdelWAF\Protection;

use AdelWAF\Http\Cidr;
use AdelWAF\Storage\StorageInterface;

/**
 * Dynamic bans, stored as `ban:{ip}` => JSON in the storage backend (documented contract,
 * so an external tool can read/write the same keys in Redis).
 */
final class BanList
{
    public const PREFIX = 'ban:';

    public function __construct(private StorageInterface $storage)
    {
    }

    /** @return array<string,mixed>|null record as written by the WAF or an external tool (fields may be missing) */
    public function find(string $ip): ?array
    {
        $raw = $this->storage->get(self::PREFIX . $ip);
        if ($raw === null) {
            return null;
        }
        $rec = json_decode($raw, true);

        return is_array($rec) ? $rec : ['ip' => $ip, 'reason' => 'ban', 'source' => 'external', 'created' => 0, 'expires' => 0];
    }

    public function ban(string $ip, string $reason, int $seconds, string $source = 'waf'): void
    {
        if (!Cidr::isValidIp($ip)) {
            throw new \InvalidArgumentException("Invalid IP: $ip");
        }
        $now = time();
        $this->storage->set(self::PREFIX . $ip, (string) json_encode([
            'ip' => $ip,
            'reason' => $reason,
            'source' => $source,
            'created' => $now,
            'expires' => $seconds > 0 ? $now + $seconds : 0,
        ]), $seconds);
    }

    public function unban(string $ip): void
    {
        $this->storage->delete(self::PREFIX . $ip);
    }

    /** @return list<array<string,mixed>> */
    public function all(): array
    {
        $out = [];
        foreach ($this->storage->scan(self::PREFIX) as $raw) {
            $rec = json_decode($raw, true);
            if (is_array($rec)) {
                $out[] = $rec;
            }
        }
        usort($out, static fn ($a, $b) => ($b['created'] ?? 0) <=> ($a['created'] ?? 0));

        return $out;
    }
}
