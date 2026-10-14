<?php

declare(strict_types=1);

namespace AdelWAF\Detection;

use AdelWAF\Config\Config;

/**
 * Layered rules: bundled pack -> updated pack in state_dir -> config overrides.
 * A pack is a directory with manifest.json + one or more rule files listed in it.
 */
final class RuleSet
{
    /** @var array<string,Rule> */
    private array $rules = [];

    /** @var array<string,string> pack name => version */
    private array $versions = [];

    public static function bundledDir(): string
    {
        return dirname(__DIR__, 2) . '/rules/default';
    }

    public static function activeDir(Config $config): ?string
    {
        $state = $config->stateDir() . '/rules';
        $ptr = $state . '/current';
        if (!is_file($ptr)) {
            return null;
        }
        $ver = trim((string) file_get_contents($ptr));
        $dir = $state . '/versions/' . basename($ver);

        return $ver !== '' && is_file($dir . '/manifest.json') ? $dir : null;
    }

    public static function fromConfig(Config $config): self
    {
        $set = new self();
        $set->loadPack(self::bundledDir());
        $active = self::activeDir($config);
        if ($active !== null) {
            try {
                $set->loadPack($active);
            } catch (\Throwable $e) {
                // A broken downloaded pack must never disable the bundled one.
            }
        }
        foreach ((array) $config->get('rules.custom', []) as $custom) {
            if (is_array($custom)) {
                $rule = Rule::fromArray($custom);
                if ($rule->compiles()) {
                    $set->rules[$rule->id] = $rule;
                }
            }
        }
        foreach ((array) $config->get('rules.scores', []) as $id => $score) {
            if (isset($set->rules[(string) $id])) {
                $set->rules[(string) $id]->score = (int) $score;
            }
        }
        foreach ((array) $config->get('rules.disable', []) as $id) {
            unset($set->rules[(string) $id]);
        }

        return $set;
    }

    public function loadPack(string $dir): void
    {
        $manifest = json_decode((string) file_get_contents($dir . '/manifest.json'), true);
        if (!is_array($manifest) || !isset($manifest['name'], $manifest['version'], $manifest['files'])) {
            throw new \RuntimeException("Invalid manifest in $dir");
        }
        foreach (array_keys((array) $manifest['files']) as $file) {
            $list = json_decode((string) file_get_contents($dir . '/' . basename((string) $file)), true);
            if (!is_array($list)) {
                throw new \RuntimeException("Invalid rule file $file");
            }
            foreach ($list as $raw) {
                $rule = Rule::fromArray($raw);
                if ($rule->compiles()) {
                    $this->rules[$rule->id] = $rule;
                }
            }
        }
        $this->versions[(string) $manifest['name']] = (string) $manifest['version'];
    }

    /** @return array<string,Rule> */
    public function rules(): array
    {
        return $this->rules;
    }

    /** @return array<string,string> */
    public function versions(): array
    {
        return $this->versions;
    }

    public function versionString(): string
    {
        $parts = [];
        foreach ($this->versions as $n => $v) {
            $parts[] = "$n@$v";
        }

        return implode(',', $parts);
    }

    public function add(Rule $rule): void
    {
        $this->rules[$rule->id] = $rule;
    }
}
