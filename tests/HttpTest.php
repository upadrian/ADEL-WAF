<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Http\Cidr;
use AdelWAF\Http\ClientIp;
use PHPUnit\Framework\TestCase;

final class HttpTest extends TestCase
{
    public function testCidr(): void
    {
        $this->assertTrue(Cidr::matches('10.1.2.3', '10.0.0.0/8'));
        $this->assertFalse(Cidr::matches('11.1.2.3', '10.0.0.0/8'));
        $this->assertTrue(Cidr::matches('192.168.1.5', '192.168.1.5'));
        $this->assertTrue(Cidr::matches('192.168.1.130', '192.168.1.128/25'));
        $this->assertFalse(Cidr::matches('192.168.1.127', '192.168.1.128/25'));
        $this->assertTrue(Cidr::matches('2606:4700::1', '2606:4700::/32'));
        $this->assertFalse(Cidr::matches('2606:4701::1', '2606:4700::/32'));
        $this->assertFalse(Cidr::matches('::1', '10.0.0.0/8'));
        $this->assertFalse(Cidr::matches('garbage', '10.0.0.0/8'));
    }

    public function testForwardedHeaderIgnoredFromUntrustedPeer(): void
    {
        $this->assertSame('198.51.100.7', ClientIp::resolve('198.51.100.7', '1.2.3.4', []));
        $this->assertSame('198.51.100.7', ClientIp::resolve('198.51.100.7', '1.2.3.4', ['10.0.0.0/8']));
    }

    public function testForwardedHeaderHonouredFromTrustedProxy(): void
    {
        $this->assertSame('1.2.3.4', ClientIp::resolve('10.0.0.5', '1.2.3.4', ['10.0.0.0/8']));
        // spoofed leftmost value is skipped: rightmost untrusted hop wins
        $this->assertSame('5.6.7.8', ClientIp::resolve('10.0.0.5', '9.9.9.9, 5.6.7.8, 10.0.0.9', ['10.0.0.0/8']));
        $this->assertSame('10.0.0.5', ClientIp::resolve('10.0.0.5', 'not-an-ip', ['10.0.0.0/8']));
    }

    public function testCloudflareAlias(): void
    {
        $this->assertSame('203.0.113.50', ClientIp::resolve('104.16.1.1', '203.0.113.50', ['cloudflare']));
        $this->assertSame('203.0.113.1', ClientIp::resolve('203.0.113.1', '8.8.8.8', ['cloudflare']));
    }
}
