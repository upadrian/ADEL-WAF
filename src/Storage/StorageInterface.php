<?php

declare(strict_types=1);

namespace AdelWAF\Storage;

/**
 * Minimal key/value contract used for counters, bans and events.
 * Keys are logical (no backend prefix). A ttl of 0 means "never expires".
 */
interface StorageInterface
{
    /** Atomically increment a counter; the ttl starts when the key is created. */
    public function incr(string $key, int $ttl): int;

    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttl = 0): void;

    public function delete(string $key): void;

    /** @return array<string,string> live entries whose key starts with $prefix */
    public function scan(string $prefix): array;

    /** Append to a capped list (newest first). Backends may ignore it. */
    public function push(string $list, string $value, int $max): void;

    public function driver(): string;
}
