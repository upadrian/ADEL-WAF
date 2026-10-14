<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Config\Config;
use AdelWAF\Http\Request;
use AdelWAF\Storage\ArrayStorage;
use AdelWAF\Waf;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/adelwaf-test-' . bin2hex(random_bytes(4));
        mkdir($this->tmp, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->rrmdir($this->tmp);
    }

    protected function rrmdir(string $d): void
    {
        foreach (glob($d . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (in_array(basename($f), ['.', '..'], true)) {
                continue;
            }
            is_dir($f) ? $this->rrmdir($f) : @unlink($f);
        }
        @rmdir($d);
    }

    /** @param array<string,mixed> $cfg */
    protected function waf(array $cfg = [], ?ArrayStorage $storage = null): Waf
    {
        $config = Config::fromArray($cfg + ['mode' => 'block', 'state_dir' => $this->tmp]);

        return new Waf($config, $storage ?? new ArrayStorage());
    }

    /**
     * @param array<string,mixed> $query
     * @param array<string,mixed> $body
     * @param array<string,string> $headers
     */
    protected function req(array $query = [], array $body = [], string $uri = '/', string $ip = '203.0.113.9', string $method = 'GET', array $headers = ['user-agent' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0']): Request
    {
        return new Request($method, 'example.com', $uri . ($query ? '?' . http_build_query($query) : ''), $ip, $query, $body, [], $headers);
    }
}
