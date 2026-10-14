<?php

declare(strict_types=1);

namespace AdelWAF;

final class Decision
{
    public const ALLOW = 'allow';
    public const BLOCK = 'block';
    public const MONITOR = 'monitor';

    /**
     * @param list<array<string,mixed>> $matches
     */
    public function __construct(
        public string $action,
        public string $reason = '',
        public string $category = '',
        public int $score = 0,
        public int $status = 403,
        public array $matches = [],
        public string $blockId = '',
        public int $retryAfter = 0,
    ) {
    }

    public static function allow(): self
    {
        return new self(self::ALLOW);
    }

    public function blocks(): bool
    {
        return $this->action === self::BLOCK;
    }
}
