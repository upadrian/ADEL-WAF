<?php

declare(strict_types=1);

namespace AdelWAF;

use AdelWAF\Config\Config;
use AdelWAF\Detection\Engine;
use AdelWAF\Detection\RuleSet;
use AdelWAF\Http\Cidr;
use AdelWAF\Http\Request;
use AdelWAF\Logging\EventLogger;
use AdelWAF\Notify\Notifier;
use AdelWAF\Protection\BanList;
use AdelWAF\Protection\RateLimiter;
use AdelWAF\Storage\StorageFactory;
use AdelWAF\Storage\StorageInterface;

/** Orchestrates allow/deny lists, bans, rate limits and rule scoring into a Decision. */
final class Waf
{
    private BanList $bans;
    private Engine $engine;
    private EventLogger $logger;
    private Notifier $notifier;
    private RateLimiter $limiter;
    private RuleSet $ruleSet;

    public function __construct(private Config $config, private StorageInterface $storage, ?RuleSet $ruleSet = null)
    {
        $this->ruleSet = $ruleSet ?? RuleSet::fromConfig($config);
        $this->bans = new BanList($storage);
        $this->limiter = new RateLimiter($storage, (array) $config->get('rate_limits', []));
        $this->engine = new Engine(
            $this->ruleSet,
            (int) $config->get('rules.paranoia', 1),
            (int) $config->get('limits.max_value_len', 8192),
            (int) $config->get('limits.normalize_depth', 3),
            (array) $config->get('exclusions', []),
        );
        $this->logger = new EventLogger($config, $storage, $this->ruleSet->versionString());
        $this->notifier = new Notifier($config, $storage);
    }

    public static function fromConfig(Config $config): self
    {
        return new self($config, StorageFactory::create($config));
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function bans(): BanList
    {
        return $this->bans;
    }

    public function storage(): StorageInterface
    {
        return $this->storage;
    }

    public function ruleSet(): RuleSet
    {
        return $this->ruleSet;
    }

    /** Evaluate, log and (in monitor mode) downgrade. Does not send any response. */
    public function handle(Request $request): Decision
    {
        $decision = $this->evaluate($request);
        if ($decision->action === Decision::ALLOW) {
            return $decision;
        }
        if ($this->config->mode() === 'monitor') {
            $decision->action = Decision::MONITOR;
        }
        $decision->blockId = bin2hex(random_bytes(6));
        if ($decision->blocks()) {
            $this->maybeBan($request, $decision);
        }
        $this->logger->log($request, $decision);
        $this->notifier->notify($request, $decision);

        return $decision;
    }

    private function evaluate(Request $r): Decision
    {
        if ($this->config->mode() === 'off') {
            return Decision::allow();
        }
        if (in_array($r->host, array_map('strtolower', (array) $this->config->get('excluded_hosts', [])), true)) {
            return Decision::allow();
        }
        foreach ((array) $this->config->get('excluded_paths', []) as $glob) {
            if (fnmatch((string) $glob, $r->path())) {
                return Decision::allow();
            }
        }
        if (Cidr::matchesAny($r->ip, array_map('strval', (array) $this->config->get('allowlist', [])))) {
            return Decision::allow();
        }
        if (Cidr::matchesAny($r->ip, array_map('strval', (array) $this->config->get('denylist', [])))) {
            return new Decision(Decision::BLOCK, 'IP is on the deny list', 'denylist', 0, $this->status());
        }
        if (($ban = $this->bans->find($r->ip)) !== null) {
            $left = (int) ($ban['expires'] ?? 0) > 0 ? max(0, (int) $ban['expires'] - time()) : 0;

            return new Decision(Decision::BLOCK, 'IP is banned: ' . (string) ($ban['reason'] ?? ''), 'banned', 0, $this->status(), [], '', $left);
        }

        $hit = $this->limiter->hit($r);
        if ($hit !== null) {
            if ($hit['ban'] > 0 && $this->config->mode() === 'block') {
                $this->bans->ban($r->ip, 'rate limit: ' . $hit['name'], $hit['ban'], 'rate-limit');
            }

            return new Decision(
                Decision::BLOCK,
                sprintf('Rate limit "%s" exceeded (%d/%ds)', $hit['name'], $hit['limit'], $hit['window']),
                'rate_limit',
                0,
                (int) $this->config->get('response.rate_limit_status', 429),
                [],
                '',
                $hit['window'],
            );
        }

        $result = $this->engine->inspect($r);
        $score = $result['score'];
        $matches = $result['matches'];
        foreach ($this->structuralMatches($r) as $m) {
            $score += $m['score'];
            $matches[] = $m;
        }
        $threshold = (int) $this->config->get('rules.threshold', 5);
        if ($score >= $threshold) {
            return new Decision(
                Decision::BLOCK,
                'Anomaly score ' . $score . ' >= ' . $threshold,
                $this->topCategory($matches),
                $score,
                $this->status(),
                $matches,
            );
        }

        return Decision::allow();
    }

    /** @return list<array<string,mixed>> */
    private function structuralMatches(Request $r): array
    {
        $out = [];
        $m = static fn (string $id, string $cat, int $score, string $name): array
            => ['id' => $id, 'category' => $cat, 'score' => $score, 'target' => 'request', 'name' => $name, 'sample' => ''];

        if (!in_array($r->method, (array) $this->config->get('limits.allowed_methods', []), true)) {
            $out[] = $m('lim-001', 'protocol', 5, 'method');
        }
        if (strlen($r->uri) > (int) $this->config->get('limits.max_uri_len', 8192)) {
            $out[] = $m('lim-002', 'protocol', 5, 'uri-length');
        }
        $args = count($r->query) + count($r->body);
        if ($args > (int) $this->config->get('limits.max_args', 1000)) {
            $out[] = $m('lim-003', 'protocol', 5, 'arg-count');
        }
        if ((bool) $this->config->get('uploads.inspect_content', true)) {
            foreach ($r->files as $f) {
                if ($f['tmp'] !== '' && is_readable($f['tmp'])) {
                    $head = (string) @file_get_contents($f['tmp'], false, null, 0, 4096);
                    if (preg_match('/<\?(?:php|=)/i', $head) === 1) {
                        $out[] = $m('upl-003', 'upload', 5, $f['name']);
                    }
                }
            }
        }

        return $out;
    }

    /** @param list<array<string,mixed>> $matches */
    private function topCategory(array $matches): string
    {
        $totals = [];
        foreach ($matches as $m) {
            $totals[$m['category']] = ($totals[$m['category']] ?? 0) + $m['score'];
        }
        arsort($totals);

        return (string) (array_key_first($totals) ?? 'anomaly');
    }

    private function status(): int
    {
        return (int) $this->config->get('response.block_status', 403);
    }

    private function maybeBan(Request $r, Decision $d): void
    {
        $threshold = (int) $this->config->get('ban.ban_on_block_score', 0);
        if ($threshold > 0 && $d->score >= $threshold && $d->category !== 'banned') {
            $this->bans->ban($r->ip, 'score ' . $d->score . ' (' . $d->category . ')', (int) $this->config->get('ban.duration', 3600));
        }
    }
}
