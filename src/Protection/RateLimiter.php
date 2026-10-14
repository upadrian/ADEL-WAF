<?php

declare(strict_types=1);

namespace AdelWAF\Protection;

use AdelWAF\Http\Request;
use AdelWAF\Storage\StorageInterface;

/** Fixed-window per-IP counters. Rules apply only to the paths/methods they list. */
final class RateLimiter
{
    /** @param list<array<string,mixed>> $limits */
    public function __construct(private StorageInterface $storage, private array $limits)
    {
    }

    /**
     * Counts the request against every matching limit.
     *
     * @return array{name:string,limit:int,window:int,count:int,ban:int}|null the first limit exceeded
     */
    public function hit(Request $request): ?array
    {
        $path = $request->path();
        $exceeded = null;
        foreach ($this->limits as $rl) {
            if (!empty($rl['methods']) && !in_array($request->method, array_map('strtoupper', (array) $rl['methods']), true)) {
                continue;
            }
            if (!empty($rl['paths'])) {
                $ok = false;
                foreach ((array) $rl['paths'] as $glob) {
                    if (fnmatch((string) $glob, $path)) {
                        $ok = true;
                        break;
                    }
                }
                if (!$ok) {
                    continue;
                }
            }
            $window = (int) $rl['window'];
            $bucket = intdiv(time(), $window);
            $count = $this->storage->incr(sprintf('c:rl:%s:%s:%d', $rl['name'], $request->ip, $bucket), $window);
            if ($count > (int) $rl['limit'] && $exceeded === null) {
                $exceeded = [
                    'name' => (string) $rl['name'],
                    'limit' => (int) $rl['limit'],
                    'window' => $window,
                    'count' => $count,
                    'ban' => (int) ($rl['ban'] ?? 0),
                ];
            }
        }

        return $exceeded;
    }
}
