<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Storage\ArrayStorage;
use AdelWAF\Storage\FileStorage;
use AdelWAF\Storage\StorageInterface;

final class StorageTest extends TestCase
{
    /** @return array<string,array{0:callable}> */
    public function backends(): array
    {
        return [
            'array' => [fn (string $dir) => new ArrayStorage()],
            'file' => [fn (string $dir) => new FileStorage($dir . '/store', 0)],
        ];
    }

    /**
     * @dataProvider backends
     */
    public function testContract(callable $make): void
    {
        /** @var StorageInterface $s */
        $s = $make($this->tmp);
        $this->assertNull($s->get('a'));
        $this->assertSame(1, $s->incr('c:x', 60));
        $this->assertSame(2, $s->incr('c:x', 60));
        $s->set('ban:1.1.1.1', 'v1');
        $s->set('ban:2.2.2.2', 'v2', 60);
        $s->set('other', 'v3');
        $this->assertSame('v1', $s->get('ban:1.1.1.1'));
        $this->assertSame(['ban:1.1.1.1' => 'v1', 'ban:2.2.2.2' => 'v2'], $this->sorted($s->scan('ban:')));
        $s->delete('ban:1.1.1.1');
        $this->assertNull($s->get('ban:1.1.1.1'));
    }

    public function testFileStorageExpiry(): void
    {
        $s = new FileStorage($this->tmp . '/store', 0);
        $s->set('k', 'v', 1);
        $this->assertSame('v', $s->get('k'));
        sleep(2);
        $this->assertNull($s->get('k'));
        $s->incr('counter', 1);
        sleep(2);
        $this->assertSame(1, $s->incr('counter', 1), 'counter restarts after ttl');
    }

    public function testArrayStorageTtlWithInjectedClock(): void
    {
        $s = new ArrayStorage();
        $s->now = 1000;
        $s->set('k', 'v', 10);
        $s->now = 1009;
        $this->assertSame('v', $s->get('k'));
        $s->now = 1010;
        $this->assertNull($s->get('k'));
    }

    /**
     * @param array<string,string> $a
     * @return array<string,string>
     */
    private function sorted(array $a): array
    {
        ksort($a);

        return $a;
    }
}
