<?php

declare(strict_types=1);

namespace AdelWAF\Detection;

final class Rule
{
    /**
     * @param list<string> $targets uri|args|cookies|headers|files|body
     * @param list<string> $names   optional header/param names the rule is restricted to
     */
    public function __construct(
        public string $id,
        public string $category,
        public string $pattern,
        public int $score,
        public int $paranoia,
        public array $targets,
        public bool $normalize = true,
        public array $names = [],
        public string $message = '',
    ) {
    }

    /** @param array<string,mixed> $a */
    public static function fromArray(array $a): self
    {
        foreach (['id', 'category', 'pattern', 'score', 'targets'] as $req) {
            if (!isset($a[$req])) {
                throw new \InvalidArgumentException("Rule missing '$req'");
            }
        }

        return new self(
            (string) $a['id'],
            (string) $a['category'],
            (string) $a['pattern'],
            (int) $a['score'],
            (int) ($a['paranoia'] ?? 1),
            array_values(array_map('strval', (array) $a['targets'])),
            (bool) ($a['normalize'] ?? true),
            array_values(array_map('strtolower', array_map('strval', (array) ($a['names'] ?? [])))),
            (string) ($a['message'] ?? ''),
        );
    }

    /** True when the pattern compiles. */
    public function compiles(): bool
    {
        return @preg_match($this->pattern, '') !== false;
    }
}
