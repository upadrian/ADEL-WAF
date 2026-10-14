<?php

declare(strict_types=1);

namespace AdelWAF\Console;

use AdelWAF\Config\Config;
use AdelWAF\Detection\Engine;
use AdelWAF\Detection\RuleSet;
use AdelWAF\Logging\EventLogger;
use AdelWAF\Rules\Updater\RulesUpdater;
use AdelWAF\Scanner\MalwareScanner;
use AdelWAF\Storage\StorageFactory;
use AdelWAF\Protection\BanList;

/** Management CLI: the stable surface external admin tools drive (use --json for machine output). */
final class Application
{
    /** @param list<string> $argv */
    public function run(array $argv): int
    {
        array_shift($argv);
        $opts = [];
        $args = [];
        foreach ($argv as $a) {
            if (str_starts_with($a, '--')) {
                $parts = explode('=', substr($a, 2), 2);
                $opts[$parts[0]] = $parts[1] ?? true;
            } else {
                $args[] = $a;
            }
        }
        $cmd = array_shift($args) ?? 'help';
        $json = isset($opts['json']);

        try {
            $config = Config::load(isset($opts['config']) ? (string) $opts['config'] : null);

            switch ($cmd) {
                case 'check-config':
                    return $this->out($json, [
                        'ok' => true,
                        'source' => $config->source(),
                        'hash' => $config->hash(),
                        'mode' => $config->mode(),
                        'state_dir' => $config->stateDir(),
                        'storage' => StorageFactory::create($config)->driver(),
                        'config' => $config->all(),
                    ], $json ? null : "Config OK ({$config->source()}) hash={$config->hash()} mode={$config->mode()} storage=" . StorageFactory::create($config)->driver());

                case 'status':
                    $rs = RuleSet::fromConfig($config);
                    $storage = StorageFactory::create($config);
                    $data = [
                        'contract_version' => Config::CONTRACT_VERSION,
                        'engine' => Engine::VERSION,
                        'mode' => $config->mode(),
                        'config_hash' => $config->hash(),
                        'storage' => $storage->driver(),
                        'ruleset' => $rs->versions(),
                        'rules' => count($rs->rules()),
                        'bans' => count((new BanList($storage))->all()),
                        'log' => (new EventLogger($config, $storage, ''))->path(),
                        'rules_state' => (new RulesUpdater($config))->status(),
                    ];

                    return $this->out($json, $data, $this->kv($data));

                case 'contract':
                    return $this->out($json, ['contract_version' => Config::CONTRACT_VERSION, 'engine' => Engine::VERSION], 'contract_version=' . Config::CONTRACT_VERSION);

                case 'ban':
                    $ip = $args[0] ?? '';
                    $secs = isset($args[1]) ? (int) $args[1] : (int) $config->get('ban.duration', 3600);
                    (new BanList(StorageFactory::create($config)))->ban($ip, $args[2] ?? 'manual', $secs, 'cli');

                    return $this->out($json, ['ok' => true, 'ip' => $ip, 'seconds' => $secs], "Banned $ip for {$secs}s");

                case 'unban':
                    (new BanList(StorageFactory::create($config)))->unban($args[0] ?? '');

                    return $this->out($json, ['ok' => true, 'ip' => $args[0] ?? ''], 'Unbanned ' . ($args[0] ?? ''));

                case 'list':
                    $bans = (new BanList(StorageFactory::create($config)))->all();
                    $text = $bans === [] ? 'No active bans' : implode("\n", array_map(
                        static fn ($b) => sprintf('%-39s %-12s expires=%s  %s', $b['ip'], $b['source'], $b['expires'] ? gmdate('c', (int) $b['expires']) : 'never', $b['reason']),
                        $bans,
                    ));

                    return $this->out($json, ['bans' => $bans], $text);

                case 'rules:update':
                    $source = $args[0] ?? (string) $config->get('rules.source', '');
                    if ($source === '') {
                        throw new \RuntimeException('Usage: rules:update <dir|url> [--dry-run] [--insecure]  (or set rules.source)');
                    }
                    $label = (new RulesUpdater($config))->update($source, isset($opts['dry-run']), isset($opts['insecure']));

                    return $this->out($json, ['ok' => true, 'version' => $label, 'dry_run' => isset($opts['dry-run'])], (isset($opts['dry-run']) ? 'Valid pack: ' : 'Installed ') . $label);

                case 'rules:rollback':
                    $label = (new RulesUpdater($config))->rollback();

                    return $this->out($json, ['ok' => true, 'version' => $label], "Rolled back to $label");

                case 'rules:status':
                    $s = (new RulesUpdater($config))->status();

                    return $this->out($json, $s, $this->kv($s));

                case 'scan':
                    $dir = $args[0] ?? '';
                    if (!is_dir($dir)) {
                        throw new \RuntimeException('Usage: scan <directory> [--min-score=5]');
                    }
                    $hits = (new MalwareScanner())->scan($dir, (int) ($opts['min-score'] ?? 5));
                    $text = $hits === [] ? 'No suspicious files found' : implode("\n", array_map(
                        static fn ($h) => sprintf('[%2d] %s  (%s)', $h['score'], $h['file'], implode(', ', $h['findings'])),
                        $hits,
                    ));
                    $this->out($json, ['suspicious' => $hits], $text);

                    return $hits === [] ? 0 : 3;

                case 'stats':
                    return $this->stats($config, $json);

                case 'help':
                default:
                    fwrite(STDOUT, self::HELP);

                    return $cmd === 'help' ? 0 : 1;
            }
        } catch (\Throwable $e) {
            if ($json) {
                fwrite(STDOUT, json_encode(['ok' => false, 'error' => $e->getMessage()], JSON_PRETTY_PRINT) . "\n");
            } else {
                fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
            }

            return 1;
        }
    }

    private function stats(Config $config, bool $json): int
    {
        $log = (new EventLogger($config, StorageFactory::create($config), ''))->path();
        $ips = $rules = $cats = [];
        $total = 0;
        $fh = @fopen($log, 'r');
        while ($fh && ($line = fgets($fh)) !== false) {
            $e = json_decode($line, true);
            if (!is_array($e)) {
                continue;
            }
            $total++;
            $ips[$e['ip'] ?? '?'] = ($ips[$e['ip'] ?? '?'] ?? 0) + 1;
            $cats[$e['category'] ?? '?'] = ($cats[$e['category'] ?? '?'] ?? 0) + 1;
            foreach ((array) ($e['matches'] ?? []) as $m) {
                $rules[$m['id'] ?? '?'] = ($rules[$m['id'] ?? '?'] ?? 0) + 1;
            }
        }
        if ($fh) {
            fclose($fh);
        }
        arsort($ips);
        arsort($rules);
        arsort($cats);
        $data = ['events' => $total, 'top_ips' => array_slice($ips, 0, 10, true), 'top_rules' => array_slice($rules, 0, 10, true), 'categories' => $cats];

        return $this->out($json, $data, $this->kv($data));
    }

    /** @param array<string,mixed> $data */
    private function out(bool $json, array $data, ?string $text): int
    {
        fwrite(STDOUT, ($json ? json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) : $text) . "\n");

        return 0;
    }

    /** @param array<string,mixed> $d */
    private function kv(array $d, string $indent = ''): string
    {
        $lines = [];
        foreach ($d as $k => $v) {
            $lines[] = is_array($v) ? "$indent$k:\n" . $this->kv($v, $indent . '  ') : "$indent$k: " . (is_bool($v) ? ($v ? 'true' : 'false') : (string) $v);
        }

        return implode("\n", $lines);
    }

    private const HELP = <<<'TXT'
adel-waf — management CLI (add --json for machine-readable output, --config=FILE to choose a config)

  check-config                 validate config, print resolved source/hash/storage
  status                       engine, mode, ruleset versions, storage, ban count
  contract                     print supported contract version
  ban <ip> [seconds] [reason]  ban an IP
  unban <ip>                   remove a ban
  list                         list active bans
  rules:update <dir|url>       install a signed ruleset pack (--dry-run, --insecure)
  rules:rollback               switch back to the previous ruleset
  rules:status                 show installed ruleset versions
  scan <dir> [--min-score=5]   offline web-shell/malware scan (exit 3 when suspicious files found)
  stats                        top rules / IPs / categories from the event log

TXT;
}
