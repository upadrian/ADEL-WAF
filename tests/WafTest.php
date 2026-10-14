<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Decision;
use AdelWAF\Response\BlockResponder;
use AdelWAF\Storage\ArrayStorage;

final class WafTest extends TestCase
{
    public function testMonitorModeLogsButNeverBlocks(): void
    {
        $waf = $this->waf(['mode' => 'monitor']);
        $d = $waf->handle($this->req(['q' => '<script>alert(1)</script>']));
        $this->assertSame(Decision::MONITOR, $d->action);
        $this->assertFileExists($this->tmp . '/logs/events.jsonl');
        $line = json_decode((string) file($this->tmp . '/logs/events.jsonl')[0], true);
        $this->assertSame('monitor', $line['action']);
        $this->assertSame(1, $line['contract_version']);
        $this->assertStringContainsString('default@', $line['ruleset']);
    }

    public function testOffModeAllowsEverything(): void
    {
        $this->assertFalse($this->waf(['mode' => 'off'])->handle($this->req(['q' => '<script>']))->blocks());
    }

    public function testCleanRequestIsNotLogged(): void
    {
        $this->waf()->handle($this->req(['q' => 'hello']));
        $this->assertFileDoesNotExist($this->tmp . '/logs/events.jsonl');
    }

    public function testAllowAndDenyLists(): void
    {
        $waf = $this->waf(['allowlist' => ['198.51.100.0/24'], 'denylist' => ['192.0.2.0/24']]);
        $this->assertFalse($waf->handle($this->req(['q' => '<script>alert(1)</script>'], [], '/', '198.51.100.20'))->blocks());
        $d = $waf->handle($this->req(['q' => 'hello'], [], '/', '192.0.2.77'));
        $this->assertTrue($d->blocks());
        $this->assertSame('denylist', $d->category);
    }

    public function testExcludedHostAndPath(): void
    {
        $waf = $this->waf(['excluded_paths' => ['/webhooks/*'], 'excluded_hosts' => ['skip.test']]);
        $this->assertFalse($waf->handle($this->req(['q' => '<script>alert(1)</script>'], [], '/webhooks/stripe'))->blocks());
        $r = new \AdelWAF\Http\Request('GET', 'skip.test', '/?q=%3Cscript%3E', '203.0.113.9', ['q' => '<script>']);
        $this->assertFalse($waf->handle($r)->blocks());
    }

    public function testRateLimitReturns429AndBans(): void
    {
        $storage = new ArrayStorage();
        $waf = $this->waf(['rate_limits' => [['name' => 'login', 'paths' => ['/login'], 'limit' => 3, 'window' => 60, 'ban' => 600]]], $storage);
        for ($i = 0; $i < 3; $i++) {
            $this->assertFalse($waf->handle($this->req([], [], '/login'))->blocks());
        }
        $d = $waf->handle($this->req([], [], '/login'));
        $this->assertTrue($d->blocks());
        $this->assertSame(429, $d->status);
        $this->assertSame('rate_limit', $d->category);
        // the ban now applies to every path
        $d2 = $waf->handle($this->req([], [], '/other'));
        $this->assertTrue($d2->blocks());
        $this->assertSame('banned', $d2->category);
        // other IPs unaffected
        $this->assertFalse($waf->handle($this->req([], [], '/login', '203.0.113.200'))->blocks());
        $waf->bans()->unban('203.0.113.9');
        $this->assertFalse($waf->handle($this->req([], [], '/other'))->blocks());
    }

    public function testAutoBanOnHighScore(): void
    {
        $waf = $this->waf(['ban' => ['duration' => 600, 'ban_on_block_score' => 5]]);
        $waf->handle($this->req(['q' => '<script>alert(1)</script>']));
        $d = $waf->handle($this->req(['q' => 'hello']));
        $this->assertSame('banned', $d->category);
    }

    public function testBanRecordShape(): void
    {
        $waf = $this->waf();
        $waf->bans()->ban('203.0.113.9', 'manual', 60, 'cli');
        $rec = $waf->bans()->find('203.0.113.9');
        $this->assertSame('cli', $rec['source']);
        $this->assertGreaterThan(time(), $rec['expires']);
        $this->assertCount(1, $waf->bans()->all());
        $this->expectException(\InvalidArgumentException::class);
        $waf->bans()->ban('not-an-ip', 'x', 1);
    }

    public function testStructuralLimits(): void
    {
        $waf = $this->waf();
        $this->assertTrue($waf->handle($this->req([], [], '/', '203.0.113.9', 'TRACE'))->blocks());
        $this->assertTrue($waf->handle($this->req([], [], '/' . str_repeat('a', 9000)))->blocks());
    }

    public function testBlockPageEscapesAndDoesNotEchoRequestData(): void
    {
        $r = $this->req(['q' => '<script>alert(1)</script>'], [], '/"><img src=x onerror=alert(1)>', '203.0.113.9', 'GET', ['user-agent' => '<script>ua</script>']);
        $d = new Decision(Decision::BLOCK, 'x', 'xss', 5, 403, [], '<b>id</b>');
        $html = (new BlockResponder())->render($r, $d);
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringNotContainsString('onerror', $html);
        $this->assertStringContainsString('&lt;b&gt;id&lt;/b&gt;', $html);
        $this->assertStringContainsString('203.0.113.9', $html);
    }

    public function testInvalidConfigIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        \AdelWAF\Config\Config::fromArray(['mode' => 'nope']);
    }

    public function testCustomRule(): void
    {
        $waf = $this->waf(['rules' => ['custom' => [[
            'id' => 'custom-1', 'category' => 'custom', 'pattern' => '~forbidden-word~i', 'score' => 5, 'targets' => ['args'],
        ]]]]);
        $this->assertTrue($waf->handle($this->req(['q' => 'a FORBIDDEN-WORD b']))->blocks());
    }
}
