<?php

declare(strict_types=1);

namespace AdelWAF\Http;

/** IPv4/IPv6 CIDR matching without extensions beyond core. */
final class Cidr
{
    public static function matches(string $ip, string $cidr): bool
    {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }
        if (!str_contains($cidr, '/')) {
            $netBin = @inet_pton($cidr);

            return $netBin !== false && $netBin === $ipBin;
        }
        [$net, $bits] = explode('/', $cidr, 2);
        $netBin = @inet_pton($net);
        if ($netBin === false || strlen($netBin) !== strlen($ipBin) || !ctype_digit($bits)) {
            return false;
        }
        $bits = (int) $bits;
        if ($bits > strlen($netBin) * 8) {
            return false;
        }
        $full = intdiv($bits, 8);
        if ($full > 0 && substr($ipBin, 0, $full) !== substr($netBin, 0, $full)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;

        return (ord($ipBin[$full]) & $mask) === (ord($netBin[$full]) & $mask);
    }

    /** @param list<string> $cidrs */
    public static function matchesAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $c) {
            if (self::matches($ip, $c)) {
                return true;
            }
        }

        return false;
    }

    public static function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
