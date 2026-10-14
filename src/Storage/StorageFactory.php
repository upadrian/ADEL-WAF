<?php

declare(strict_types=1);

namespace AdelWAF\Storage;

use AdelWAF\Config\Config;

final class StorageFactory
{
    /** Seconds Redis is skipped after a failed connection (circuit breaker). */
    private const BREAKER_TTL = 30;

    public static function create(Config $config): StorageInterface
    {
        $driver = (string) $config->get('storage.driver', 'auto');
        $prefix = (string) $config->get('storage.prefix', 'adelwaf:');
        $state = $config->stateDir();

        if ($driver === 'none' || $driver === 'memory') {
            return new ArrayStorage();
        }
        if ($driver === 'redis' || $driver === 'auto') {
            $breaker = $state . '/redis.down';
            $open = is_file($breaker) && (time() - (int) @filemtime($breaker)) < self::BREAKER_TTL;
            if (!$open && RedisStorage::available()) {
                try {
                    $s = new RedisStorage((array) $config->get('storage.redis', []), $prefix);
                    @unlink($breaker);

                    return $s;
                } catch (\Throwable $e) {
                    @file_put_contents($breaker, (string) time());
                    if ($driver === 'redis') {
                        // Explicit redis requested but down: degrade to files rather than fail open blind.
                    }
                }
            }
        }

        return new FileStorage($state . '/store');
    }
}
