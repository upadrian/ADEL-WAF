<?php

declare(strict_types=1);

namespace AdelWAF\Http;

/**
 * Resolves the real client IP. Forwarded headers are honoured only when the
 * TCP peer (REMOTE_ADDR) is a configured trusted proxy.
 */
final class ClientIp
{
    // Cloudflare published ranges (https://www.cloudflare.com/ips/). Verify/refresh periodically.
    public const CLOUDFLARE = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /**
     * @param list<string> $trusted CIDRs or "cloudflare"
     */
    public static function resolve(string $remoteAddr, ?string $forwardedHeaderValue, array $trusted): string
    {
        $remote = Cidr::isValidIp($remoteAddr) ? $remoteAddr : '0.0.0.0';
        if ($trusted === [] || $forwardedHeaderValue === null || $forwardedHeaderValue === '') {
            return $remote;
        }
        $nets = [];
        foreach ($trusted as $t) {
            if (strtolower($t) === 'cloudflare') {
                $nets = array_merge($nets, self::CLOUDFLARE);
            } else {
                $nets[] = $t;
            }
        }
        if (!Cidr::matchesAny($remote, $nets)) {
            return $remote;
        }
        // Walk right-to-left, skipping trusted hops; first untrusted hop is the client.
        $hops = array_map('trim', explode(',', $forwardedHeaderValue));
        for ($i = count($hops) - 1; $i >= 0; $i--) {
            $hop = $hops[$i];
            if (!Cidr::isValidIp($hop)) {
                return $remote;
            }
            if (!Cidr::matchesAny($hop, $nets)) {
                return $hop;
            }
        }

        return $remote;
    }
}
