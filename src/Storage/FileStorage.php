<?php

declare(strict_types=1);

namespace AdelWAF\Storage;

/**
 * Concurrency-safe file storage for hosts without Redis. One small JSON file per key,
 * sharded by hash prefix, written under flock. Expired entries are purged probabilistically.
 */
final class FileStorage implements StorageInterface
{
    private string $dir;

    public function __construct(string $dir, private int $gcDivisor = 200)
    {
        $this->dir = rtrim(str_replace('\\', '/', $dir), '/');
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
        if ($this->gcDivisor > 0 && random_int(1, $this->gcDivisor) === 1) {
            $this->gc();
        }
    }

    private function path(string $key): string
    {
        $h = sha1($key);

        return $this->dir . '/' . substr($h, 0, 2) . '/' . $h . '.json';
    }

    public function incr(string $key, int $ttl): int
    {
        $path = $this->path($key);
        $this->ensureDir($path);
        $fh = @fopen($path, 'c+');
        if ($fh === false) {
            return 1;
        }
        try {
            flock($fh, LOCK_EX);
            $rec = json_decode((string) stream_get_contents($fh), true);
            $now = time();
            if (!is_array($rec) || ($rec['e'] ?? 0) !== 0 && $rec['e'] <= $now) {
                $rec = ['k' => $key, 'v' => '0', 'e' => $ttl > 0 ? $now + $ttl : 0];
            }
            $rec['v'] = (string) ((int) $rec['v'] + 1);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) json_encode($rec));
            fflush($fh);

            return (int) $rec['v'];
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    public function get(string $key): ?string
    {
        $rec = $this->read($this->path($key));

        return $rec === null ? null : (string) $rec['v'];
    }

    public function set(string $key, string $value, int $ttl = 0): void
    {
        $path = $this->path($key);
        $this->ensureDir($path);
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $rec = ['k' => $key, 'v' => $value, 'e' => $ttl > 0 ? time() + $ttl : 0];
        if (@file_put_contents($tmp, json_encode($rec)) !== false) {
            @rename($tmp, $path);
            @unlink($tmp);
        }
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }

    public function scan(string $prefix): array
    {
        $out = [];
        foreach (glob($this->dir . '/*/*.json') ?: [] as $file) {
            $rec = $this->read($file);
            if ($rec !== null && str_starts_with((string) $rec['k'], $prefix)) {
                $out[(string) $rec['k']] = (string) $rec['v'];
            }
        }

        return $out;
    }

    public function push(string $list, string $value, int $max): void
    {
        // Events go to the JSONL log file in file mode; capped lists are a Redis feature.
    }

    public function driver(): string
    {
        return 'file';
    }

    /** @return array{k:string,v:string,e:int}|null */
    private function read(string $path): ?array
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $rec = json_decode($raw, true);
        if (!is_array($rec) || !isset($rec['k'], $rec['v'])) {
            return null;
        }
        if (($rec['e'] ?? 0) !== 0 && $rec['e'] <= time()) {
            @unlink($path);

            return null;
        }

        return $rec;
    }

    private function ensureDir(string $path): void
    {
        $d = dirname($path);
        if (!is_dir($d)) {
            @mkdir($d, 0700, true);
        }
    }

    private function gc(): void
    {
        foreach (glob($this->dir . '/*/*.json') ?: [] as $file) {
            $this->read($file); // read() removes expired entries
        }
    }
}
