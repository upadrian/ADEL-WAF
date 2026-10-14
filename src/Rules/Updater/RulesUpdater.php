<?php

declare(strict_types=1);

namespace AdelWAF\Rules\Updater;

use AdelWAF\Config\Config;
use AdelWAF\Detection\Engine;
use AdelWAF\Detection\Rule;

/**
 * Installs signed ruleset packs under <state_dir>/rules/versions/<name>-<version>/ and flips the
 * `current` pointer atomically. Never runs in a web request.
 *
 * Pack layout: manifest.json (+ manifest.sig, base64 ed25519 detached signature over manifest.json),
 * and the files named in manifest.files / manifest.extra, each with its sha256.
 */
final class RulesUpdater
{
    public function __construct(private Config $config)
    {
    }

    private function root(): string
    {
        $r = $this->config->stateDir() . '/rules';
        if (!is_dir($r . '/versions')) {
            @mkdir($r . '/versions', 0700, true);
        }

        return $r;
    }

    /**
     * @param string $source local directory or http(s) URL of the pack directory
     * @return string installed version label
     * @throws \RuntimeException on any validation failure (current pack stays active)
     */
    public function update(string $source, bool $dryRun = false, bool $skipSignature = false): string
    {
        $isUrl = (bool) preg_match('#^https?://#i', $source);
        $fetch = fn (string $name): string => $isUrl ? $this->download(rtrim($source, '/') . '/' . $name) : $this->readLocal($source, $name);

        $manifestRaw = $fetch('manifest.json');
        $manifest = json_decode($manifestRaw, true);
        if (!is_array($manifest) || !isset($manifest['name'], $manifest['version'], $manifest['files']) || !is_array($manifest['files'])) {
            throw new \RuntimeException('Invalid manifest.json');
        }
        if (!preg_match('/^[a-z0-9_-]+$/i', (string) $manifest['name']) || !preg_match('/^\d+\.\d+\.\d+([\w.-]*)$/', (string) $manifest['version'])) {
            throw new \RuntimeException('Invalid pack name or version');
        }
        if (isset($manifest['min_engine']) && version_compare(Engine::VERSION, (string) $manifest['min_engine'], '<')) {
            throw new \RuntimeException(sprintf('Pack requires engine >= %s (running %s)', $manifest['min_engine'], Engine::VERSION));
        }

        $this->verifySignature($manifestRaw, $fetch, $skipSignature);

        $files = [];
        foreach (array_merge($manifest['files'], (array) ($manifest['extra'] ?? [])) as $name => $sha) {
            $name = (string) $name;
            if ($name !== basename($name) || !preg_match('/^[\w.-]+\.json$/', $name)) {
                throw new \RuntimeException("Illegal file name in manifest: $name");
            }
            $content = $fetch($name);
            if (!hash_equals(strtolower((string) $sha), hash('sha256', $content))) {
                throw new \RuntimeException("sha256 mismatch for $name");
            }
            $files[$name] = $content;
        }
        foreach (array_keys($manifest['files']) as $name) {
            $this->validateRules($files[(string) $name]);
        }

        $label = $manifest['name'] . '-' . $manifest['version'];
        if ($dryRun) {
            return $label;
        }

        $root = $this->root();
        $dest = $root . '/versions/' . $label;
        $tmp = $dest . '.tmp' . bin2hex(random_bytes(3));
        mkdir($tmp, 0700, true);
        file_put_contents($tmp . '/manifest.json', $manifestRaw);
        foreach ($files as $name => $content) {
            file_put_contents($tmp . '/' . $name, $content);
        }
        if (is_dir($dest)) {
            $this->rmdir($dest);
        }
        rename($tmp, $dest);

        $current = is_file($root . '/current') ? trim((string) file_get_contents($root . '/current')) : '';
        if ($current !== '' && $current !== $label) {
            $this->atomicWrite($root . '/previous', $current);
        }
        $this->atomicWrite($root . '/current', $label);
        $this->prune($root, (int) $this->config->get('rules.keep_versions', 5), $label, $current);

        return $label;
    }

    /** @return string version label now active */
    public function rollback(): string
    {
        $root = $this->root();
        $prev = is_file($root . '/previous') ? trim((string) file_get_contents($root . '/previous')) : '';
        if ($prev === '' || !is_file($root . '/versions/' . basename($prev) . '/manifest.json')) {
            throw new \RuntimeException('No previous ruleset to roll back to');
        }
        $cur = is_file($root . '/current') ? trim((string) file_get_contents($root . '/current')) : '';
        $this->atomicWrite($root . '/current', $prev);
        if ($cur !== '') {
            $this->atomicWrite($root . '/previous', $cur);
        }

        return $prev;
    }

    /** @return array{current:?string,previous:?string,installed:list<string>} */
    public function status(): array
    {
        $root = $this->root();
        $read = static fn (string $f): ?string => is_file($f) ? trim((string) file_get_contents($f)) : null;
        $installed = array_map('basename', glob($root . '/versions/*', GLOB_ONLYDIR) ?: []);
        sort($installed);

        return ['current' => $read($root . '/current'), 'previous' => $read($root . '/previous'), 'installed' => $installed];
    }

    private function verifySignature(string $manifestRaw, callable $fetch, bool $skip): void
    {
        if ($skip || !(bool) $this->config->get('rules.require_signature', true)) {
            return;
        }
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new \RuntimeException('ext-sodium is required to verify pack signatures');
        }
        $keys = (array) $this->config->get('rules.public_keys', []);
        if ($keys === []) {
            throw new \RuntimeException('rules.public_keys is empty: configure a trusted ed25519 public key (base64) or disable rules.require_signature');
        }
        $sig = base64_decode(trim($fetch('manifest.sig')), true);
        if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new \RuntimeException('Malformed manifest.sig');
        }
        foreach ($keys as $key) {
            $pk = base64_decode((string) $key, true);
            if ($pk !== false && strlen($pk) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                && sodium_crypto_sign_verify_detached($sig, $manifestRaw, $pk)) {
                return;
            }
        }
        throw new \RuntimeException('Signature verification failed');
    }

    /** Schema + compile test + ReDoS probe on every rule. */
    public function validateRules(string $json): void
    {
        $list = json_decode($json, true);
        if (!is_array($list) || $list === []) {
            throw new \RuntimeException('Rule file is not a non-empty JSON array');
        }
        $seen = [];
        $oldLimit = ini_set('pcre.backtrack_limit', '200000');
        $oldJit = ini_set('pcre.jit', '0'); // JIT ignores backtrack_limit; disable for a deterministic probe
        try {
            foreach ($list as $i => $raw) {
                if (!is_array($raw)) {
                    throw new \RuntimeException("Rule #$i is not an object");
                }
                try {
                    $rule = Rule::fromArray($raw);
                } catch (\InvalidArgumentException $e) {
                    throw new \RuntimeException("Rule #$i: " . $e->getMessage());
                }
                if (isset($seen[$rule->id])) {
                    throw new \RuntimeException("Duplicate rule id {$rule->id}");
                }
                $seen[$rule->id] = true;
                if ($rule->score < 0 || $rule->score > 20 || !in_array($rule->paranoia, [1, 2, 3], true)) {
                    throw new \RuntimeException("Rule {$rule->id}: score/paranoia out of range");
                }
                if (array_diff($rule->targets, ['uri', 'args', 'cookies', 'headers', 'files', 'body']) !== []) {
                    throw new \RuntimeException("Rule {$rule->id}: unknown target");
                }
                if (!$rule->compiles()) {
                    throw new \RuntimeException("Rule {$rule->id}: pattern does not compile");
                }
                foreach ([str_repeat('a', 6000) . '!', str_repeat("a' ", 2500) . '!', str_repeat('<a ', 2500) . '!', str_repeat('1 ', 3000) . '!', str_repeat('a', 40) . '!'] as $probe) {
                    $t = microtime(true);
                    if (@preg_match($rule->pattern, $probe) === false || microtime(true) - $t > 0.25) {
                        throw new \RuntimeException("Rule {$rule->id}: pattern is too expensive (possible ReDoS)");
                    }
                }
            }
        } finally {
            if ($oldLimit !== false) {
                ini_set('pcre.backtrack_limit', $oldLimit);
            }
            if ($oldJit !== false) {
                ini_set('pcre.jit', $oldJit);
            }
        }
    }

    private function readLocal(string $dir, string $name): string
    {
        $f = rtrim($dir, '/\\') . '/' . $name;
        $c = @file_get_contents($f);
        if ($c === false) {
            throw new \RuntimeException("Cannot read $f");
        }

        return $c;
    }

    private function download(string $url): string
    {
        $ctx = stream_context_create(['http' => ['timeout' => 15, 'follow_location' => 1, 'max_redirects' => 3, 'user_agent' => 'adel-waf/' . Engine::VERSION]]);
        $c = @file_get_contents($url, false, $ctx, 0, 5 * 1024 * 1024);
        if ($c === false) {
            throw new \RuntimeException("Download failed: $url");
        }

        return $c;
    }

    private function atomicWrite(string $path, string $content): void
    {
        $tmp = $path . '.' . bin2hex(random_bytes(3)) . '.tmp';
        file_put_contents($tmp, $content);
        rename($tmp, $path);
    }

    private function prune(string $root, int $keep, string ...$protect): void
    {
        $dirs = glob($root . '/versions/*', GLOB_ONLYDIR) ?: [];
        usort($dirs, static fn ($a, $b) => filemtime($b) <=> filemtime($a));
        foreach (array_slice($dirs, max($keep, 2)) as $d) {
            if (!in_array(basename($d), $protect, true)) {
                $this->rmdir($d);
            }
        }
    }

    private function rmdir(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $f) {
            is_dir($f) ? $this->rmdir($f) : @unlink($f);
        }
        @rmdir($dir);
    }
}
