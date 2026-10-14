<?php

declare(strict_types=1);

namespace AdelWAF\Logging;

use AdelWAF\Config\Config;
use AdelWAF\Decision;
use AdelWAF\Http\Request;
use AdelWAF\Storage\StorageInterface;

/** JSON Lines event log (schema/event.schema.json), size-rotated, optional Redis list sink. */
final class EventLogger
{
    public function __construct(
        private Config $config,
        private StorageInterface $storage,
        private string $rulesetVersion,
    ) {
    }

    public function path(): string
    {
        $p = $this->config->get('logging.path');
        if (is_string($p) && $p !== '') {
            return $p;
        }
        $dir = $this->config->stateDir() . '/logs';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }

        return $dir . '/events.jsonl';
    }

    /** @return array<string,mixed> */
    public function build(Request $request, Decision $d): array
    {
        return [
            'contract_version' => Config::CONTRACT_VERSION,
            'ts' => gmdate('c'),
            'block_id' => $d->blockId,
            'action' => $d->action,
            'category' => $d->category,
            'reason' => $d->reason,
            'score' => $d->score,
            'status' => $d->status,
            'ip' => $request->ip,
            'host' => substr($request->host, 0, 255),
            'method' => $request->method,
            'uri' => substr($request->uri, 0, 2048),
            'user_agent' => substr($request->headers['user-agent'] ?? '', 0, 512),
            'matches' => $d->matches,
            'ruleset' => $this->rulesetVersion,
            'engine' => \AdelWAF\Detection\Engine::VERSION,
            'config_hash' => $this->config->hash(),
        ];
    }

    public function log(Request $request, Decision $d): void
    {
        if (!(bool) $this->config->get('logging.enabled', true)) {
            return;
        }
        // json_encode escapes control characters, so CR/LF injection through UA/URI is impossible.
        $line = json_encode($this->build($request, $d), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($line === false) {
            return;
        }
        $path = $this->path();
        $this->rotate($path);
        @file_put_contents($path, $line . "\n", FILE_APPEND | LOCK_EX);

        if ((bool) $this->config->get('logging.redis_events', false)) {
            $this->storage->push('events', $line, (int) $this->config->get('logging.redis_events_max', 10000));
        }
    }

    private function rotate(string $path): void
    {
        $max = (int) $this->config->get('logging.max_bytes', 10485760);
        clearstatcache(true, $path);
        if ($max <= 0 || !is_file($path) || (int) @filesize($path) < $max) {
            return;
        }
        $keep = max(1, (int) $this->config->get('logging.keep', 5));
        @unlink($path . '.' . $keep);
        for ($i = $keep - 1; $i >= 1; $i--) {
            if (is_file($path . '.' . $i)) {
                @rename($path . '.' . $i, $path . '.' . ($i + 1));
            }
        }
        @rename($path, $path . '.1');
    }
}
