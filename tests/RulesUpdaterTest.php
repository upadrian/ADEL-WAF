<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Config\Config;
use AdelWAF\Rules\Updater\RulesUpdater;

final class RulesUpdaterTest extends TestCase
{
    /** @param list<array<string,mixed>>|null $rules */
    private function makePack(string $dir, string $version = '2.1.0', ?array $rules = null, string $minEngine = '2.0.0'): void
    {
        @mkdir($dir, 0777, true);
        $rules ??= [['id' => 'new-001', 'category' => 'custom', 'pattern' => '~zzz-evil~i', 'score' => 5, 'targets' => ['args']]];
        $json = json_encode($rules);
        file_put_contents("$dir/request.json", $json);
        file_put_contents("$dir/manifest.json", json_encode([
            'name' => 'default', 'version' => $version, 'min_engine' => $minEngine,
            'files' => ['request.json' => hash('sha256', (string) $json)],
        ]));
    }

    private function updater(array $extra = []): RulesUpdater
    {
        return new RulesUpdater(Config::fromArray(['state_dir' => $this->tmp . '/state', 'rules' => ['require_signature' => false] + ($extra['rules'] ?? [])]));
    }

    public function testInstallActivatesAndEngineUsesIt(): void
    {
        $this->makePack($this->tmp . '/pack');
        $label = $this->updater()->update($this->tmp . '/pack');
        $this->assertSame('default-2.1.0', $label);

        $config = Config::fromArray(['mode' => 'block', 'state_dir' => $this->tmp . '/state']);
        $waf = new \AdelWAF\Waf($config, new \AdelWAF\Storage\ArrayStorage());
        $this->assertTrue($waf->handle($this->req(['q' => 'zzz-evil']))->blocks(), 'new rule active');
        $this->assertTrue($waf->handle($this->req(['q' => '<script>alert(1)</script>']))->blocks(), 'bundled rules still active');
        $this->assertStringContainsString('default@2.1.0', $waf->ruleSet()->versionString());
    }

    public function testTamperedFileIsRejectedAndNothingChanges(): void
    {
        $this->makePack($this->tmp . '/pack');
        file_put_contents($this->tmp . '/pack/request.json', '[]');
        $u = $this->updater();
        try {
            $u->update($this->tmp . '/pack');
            $this->fail('expected failure');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('sha256', $e->getMessage());
        }
        $this->assertNull($u->status()['current']);
    }

    public function testInvalidRegexIsRejected(): void
    {
        $this->makePack($this->tmp . '/pack', '2.1.0', [['id' => 'bad', 'category' => 'x', 'pattern' => '~(unclosed~', 'score' => 5, 'targets' => ['args']]]);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('does not compile');
        $this->updater()->update($this->tmp . '/pack');
    }

    public function testCatastrophicRegexIsRejected(): void
    {
        $this->makePack($this->tmp . '/pack', '2.1.0', [['id' => 'redos', 'category' => 'x', 'pattern' => '~^(a+)+$~', 'score' => 5, 'targets' => ['args']]]);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('too expensive');
        $this->updater()->update($this->tmp . '/pack');
    }

    public function testTooNewMinEngineIsRejected(): void
    {
        $this->makePack($this->tmp . '/pack', '3.0.0', null, '9.0.0');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('requires engine');
        $this->updater()->update($this->tmp . '/pack');
    }

    public function testRollback(): void
    {
        $u = $this->updater();
        $this->makePack($this->tmp . '/p1', '2.1.0');
        $this->makePack($this->tmp . '/p2', '2.2.0');
        $u->update($this->tmp . '/p1');
        $u->update($this->tmp . '/p2');
        $this->assertSame('default-2.2.0', $u->status()['current']);
        $this->assertSame('default-2.1.0', $u->rollback());
        $this->assertSame('default-2.1.0', $u->status()['current']);
    }

    public function testDryRunInstallsNothing(): void
    {
        $this->makePack($this->tmp . '/pack');
        $u = $this->updater();
        $this->assertSame('default-2.1.0', $u->update($this->tmp . '/pack', true));
        $this->assertNull($u->status()['current']);
    }

    public function testSignatureVerification(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('ext-sodium missing');
        }
        $this->makePack($this->tmp . '/pack');
        $kp = sodium_crypto_sign_keypair();
        $pub = base64_encode(sodium_crypto_sign_publickey($kp));
        $manifest = (string) file_get_contents($this->tmp . '/pack/manifest.json');
        file_put_contents($this->tmp . '/pack/manifest.sig', base64_encode(sodium_crypto_sign_detached($manifest, sodium_crypto_sign_secretkey($kp))));

        $cfg = fn (string $key) => new RulesUpdater(Config::fromArray(['state_dir' => $this->tmp . '/state', 'rules' => ['require_signature' => true, 'public_keys' => [$key]]]));
        $this->assertSame('default-2.1.0', $cfg($pub)->update($this->tmp . '/pack'));

        $otherPub = base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->expectExceptionMessage('Signature verification failed');
        $cfg($otherPub)->update($this->tmp . '/pack');
    }

    public function testUnsignedRefusedWhenNoKeysConfigured(): void
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            $this->markTestSkipped('ext-sodium missing');
        }
        $this->makePack($this->tmp . '/pack');
        $this->expectExceptionMessage('rules.public_keys is empty');
        (new RulesUpdater(Config::fromArray(['state_dir' => $this->tmp . '/state'])))->update($this->tmp . '/pack');
    }

    public function testBundledPackValidates(): void
    {
        $u = $this->updater();
        $u->validateRules((string) file_get_contents(\AdelWAF\Detection\RuleSet::bundledDir() . '/request.json'));
        $this->assertTrue(true);
    }
}
