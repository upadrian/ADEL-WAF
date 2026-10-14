<?php

declare(strict_types=1);

namespace AdelWAF\Detection;

/** Canonicalises a value so evasion tricks (multi-encoding, comments, case, null bytes) collapse. */
final class Normalizer
{
    public static function normalize(string $v, int $depth = 3): string
    {
        for ($i = 0; $i < $depth; $i++) {
            $prev = $v;
            $v = urldecode($v);
            $v = html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $v = str_replace("\0", '', $v);
            if ($v === $prev) {
                break;
            }
        }
        // Inline SQL/C comments act as whitespace: UN/**/ION, /*!50000select*/
        $v = (string) preg_replace('~/\*!?\d*|\*/~', ' ', $v);
        // Unicode / odd whitespace and control characters -> single space
        $n = preg_replace('~[\s\x{00A0}\x{2000}-\x{200B}\x{FEFF}]+~u', ' ', $v);
        // Invalid UTF-8 makes the /u pattern fail; never fall back to an empty string.
        $v = $n ?? (string) preg_replace('~\s+~', ' ', $v);
        $lower = function_exists('mb_strtolower') ? mb_strtolower($v, 'UTF-8') : strtolower($v);

        return $lower;
    }
}
