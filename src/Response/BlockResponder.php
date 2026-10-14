<?php

declare(strict_types=1);

namespace AdelWAF\Response;

use AdelWAF\Decision;
use AdelWAF\Http\Request;

final class BlockResponder
{
    public function __construct(private ?string $template = null, private bool $securityHeaders = false)
    {
    }

    /** Renders the block page. Every interpolated value is HTML-escaped; no request data other than the IP is echoed. */
    public function render(Request $request, Decision $d): string
    {
        $tpl = $this->template !== null && is_file($this->template)
            ? (string) file_get_contents($this->template)
            : (string) file_get_contents(dirname(__DIR__, 2) . '/resources/block.html');
        $limited = $d->status === 429;
        $vars = [
            '{{title}}' => $limited ? 'Too many requests' : 'Access denied',
            '{{message}}' => $limited
                ? 'You have sent too many requests. Please slow down and try again later.'
                : 'Your request was blocked by the web application firewall. If you believe this is a mistake, contact the site owner and quote the reference below.',
            '{{ip}}' => $request->ip,
            '{{block_id}}' => $d->blockId,
        ];
        foreach ($vars as $k => $v) {
            $vars[$k] = htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        return strtr($tpl, $vars);
    }

    /** Sends the response and terminates. */
    public function send(Request $request, Decision $d): void
    {
        $body = $this->render($request, $d);
        if (!headers_sent()) {
            http_response_code($d->status);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Adel-WAF-Block: ' . $d->blockId);
            if ($d->retryAfter > 0) {
                header('Retry-After: ' . $d->retryAfter);
            }
            if ($this->securityHeaders) {
                header('X-Content-Type-Options: nosniff');
                header('X-Frame-Options: SAMEORIGIN');
                header('Referrer-Policy: strict-origin-when-cross-origin');
            }
        }
        echo $body;
        exit;
    }
}
