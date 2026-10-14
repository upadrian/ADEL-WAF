<?php

declare(strict_types=1);

namespace AdelWAF\Notify;

use AdelWAF\Config\Config;
use AdelWAF\Decision;
use AdelWAF\Http\Request;
use AdelWAF\Storage\StorageInterface;

/** Email alerts capped per hour (via the storage counters) so an attack cannot turn into a mail bomb. */
final class Notifier
{
    public function __construct(private Config $config, private StorageInterface $storage)
    {
    }

    public function notify(Request $request, Decision $d): void
    {
        if (!(bool) $this->config->get('notify.enabled', false)) {
            return;
        }
        $to = (string) $this->config->get('notify.email', '');
        if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
            return;
        }
        $max = (int) $this->config->get('notify.max_per_hour', 5);
        if ($this->storage->incr('c:notify:' . gmdate('YmdH'), 3600) > $max) {
            return;
        }
        $clean = static fn (string $s): string => preg_replace('/[\r\n]+/', ' ', $s) ?? '';
        @mail(
            $to,
            'AdelWAF: ' . $clean($d->action . ' ' . $d->category) . ' from ' . $clean($request->ip),
            sprintf(
                "Action: %s\nCategory: %s\nReason: %s\nScore: %d\nIP: %s\nHost: %s\nMethod: %s\nURI: %s\nBlock ID: %s\n",
                $d->action,
                $d->category,
                $d->reason,
                $d->score,
                $request->ip,
                $request->host,
                $request->method,
                substr($request->uri, 0, 500),
                $d->blockId
            )
        );
    }
}
