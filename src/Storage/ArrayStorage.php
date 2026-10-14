<?php

declare(strict_types=1);

namespace AdelWAF\Storage;

/** In-process storage: tests, and "memory" driver (per-request only). */
final class ArrayStorage implements StorageInterface
{
    /** @var array<string,array{0:string,1:int}> */
    private array $data = [];

    /** @var array<string,list<string>> */
    public array $lists = [];

    /** Injectable clock for tests. */
    public ?int $now = null;

    private function now(): int
    {
        return $this->now ?? time();
    }

    public function incr(string $key, int $ttl): int
    {
        $cur = $this->live($key);
        $n = $cur === null ? 1 : (int) $cur + 1;
        $exp = $cur === null ? ($ttl > 0 ? $this->now() + $ttl : 0) : $this->data[$key][1];
        $this->data[$key] = [(string) $n, $exp];

        return $n;
    }

    public function get(string $key): ?string
    {
        return $this->live($key);
    }

    public function set(string $key, string $value, int $ttl = 0): void
    {
        $this->data[$key] = [$value, $ttl > 0 ? $this->now() + $ttl : 0];
    }

    public function delete(string $key): void
    {
        unset($this->data[$key]);
    }

    public function scan(string $prefix): array
    {
        $out = [];
        foreach (array_keys($this->data) as $k) {
            if (str_starts_with((string) $k, $prefix) && ($v = $this->live((string) $k)) !== null) {
                $out[(string) $k] = $v;
            }
        }

        return $out;
    }

    public function push(string $list, string $value, int $max): void
    {
        $this->lists[$list] ??= [];
        array_unshift($this->lists[$list], $value);
        $this->lists[$list] = array_slice($this->lists[$list], 0, $max);
    }

    public function driver(): string
    {
        return 'memory';
    }

    private function live(string $key): ?string
    {
        if (!isset($this->data[$key])) {
            return null;
        }
        [$v, $exp] = $this->data[$key];
        if ($exp !== 0 && $exp <= $this->now()) {
            unset($this->data[$key]);

            return null;
        }

        return $v;
    }
}
