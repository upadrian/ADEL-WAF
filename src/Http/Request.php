<?php

declare(strict_types=1);

namespace AdelWAF\Http;

/** Immutable, framework-agnostic request snapshot. */
final class Request
{
    /**
     * @param array<string,mixed>  $query
     * @param array<string,mixed>  $body
     * @param array<string,string> $cookies
     * @param array<string,string> $headers lower-case names
     * @param list<array{name:string,filename:string,tmp:string}> $files
     */
    public function __construct(
        public string $method,
        public string $host,
        public string $uri,
        public string $ip,
        public array $query = [],
        public array $body = [],
        public array $cookies = [],
        public array $headers = [],
        public array $files = [],
        public ?string $rawBody = null,
    ) {
    }

    public function path(): string
    {
        $p = parse_url($this->uri, PHP_URL_PATH);

        return is_string($p) && $p !== '' ? $p : '/';
    }

    /** @param list<string> $trustedProxies */
    public static function fromGlobals(array $trustedProxies = [], string $ipHeader = 'X-Forwarded-For', int $maxBody = 1048576): self
    {
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (is_string($v) && str_starts_with($k, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = $v;
            }
        }
        foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $sk => $hk) {
            if (isset($_SERVER[$sk]) && is_string($_SERVER[$sk])) {
                $headers[$hk] = $_SERVER[$sk];
            }
        }

        $fwdKey = 'HTTP_' . strtoupper(str_replace('-', '_', $ipHeader));
        $fwd = isset($_SERVER[$fwdKey]) && is_string($_SERVER[$fwdKey]) ? $_SERVER[$fwdKey] : null;
        $ip = ClientIp::resolve((string) ($_SERVER['REMOTE_ADDR'] ?? ''), $fwd, $trustedProxies);

        $body = is_array($_POST) ? $_POST : [];
        $raw = null;
        $ct = strtolower($headers['content-type'] ?? '');
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($body === [] && $method !== 'GET' && $method !== 'HEAD' && !str_contains($ct, 'multipart/form-data')) {
            $raw = (string) file_get_contents('php://input', false, null, 0, $maxBody);
            if (str_contains($ct, 'json') && $raw !== '') {
                $decoded = json_decode($raw, true, 64);
                if (is_array($decoded)) {
                    $body = $decoded;
                    $raw = null;
                }
            }
        }

        $files = [];
        foreach ($_FILES as $field => $f) {
            if (!is_array($f) || !isset($f['name'])) {
                continue;
            }
            foreach ((array) $f['name'] as $i => $name) {
                $tmp = is_array($f['tmp_name']) ? ($f['tmp_name'][$i] ?? '') : $f['tmp_name'];
                $files[] = ['name' => (string) $field, 'filename' => is_string($name) ? $name : '', 'tmp' => is_string($tmp) ? $tmp : ''];
            }
        }

        return new self(
            $method,
            strtolower(preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '')) ?? ''),
            (string) ($_SERVER['REQUEST_URI'] ?? '/'),
            $ip,
            is_array($_GET) ? $_GET : [],
            $body,
            is_array($_COOKIE) ? array_map('strval', array_filter($_COOKIE, 'is_scalar')) : [],
            $headers,
            $files,
            $raw,
        );
    }

    /**
     * Flatten everything the engine should look at.
     *
     * @return list<array{0:string,1:string,2:string}> [target, name, value]
     */
    public function inspectables(int $maxValueLen = 8192): array
    {
        $out = [];
        $cut = static fn (string $s): string => strlen($s) > $maxValueLen ? substr($s, 0, $maxValueLen) : $s;

        $out[] = ['uri', 'path', $cut(rawurldecode($this->path()))];
        $q = parse_url($this->uri, PHP_URL_QUERY);
        if (is_string($q) && $q !== '') {
            $out[] = ['uri', 'query', $cut($q)];
        }
        self::flatten('args', $this->query, '', $out, $cut);
        self::flatten('args', $this->body, '', $out, $cut);
        self::flatten('cookies', $this->cookies, '', $out, $cut);
        foreach ($this->headers as $name => $value) {
            if ($name === 'cookie' || $name === 'content-length') {
                continue;
            }
            $out[] = ['headers', $name, $cut($value)];
        }
        foreach ($this->files as $f) {
            $out[] = ['files', $f['name'], $cut($f['filename'])];
        }
        if ($this->rawBody !== null && $this->rawBody !== '') {
            $out[] = ['body', 'raw', $cut($this->rawBody)];
        }

        return $out;
    }

    /**
     * @param array<mixed> $data
     * @param list<array{0:string,1:string,2:string}> $out
     */
    private static function flatten(string $target, array $data, string $prefix, array &$out, callable $cut, int $depth = 0): void
    {
        if ($depth > 16) {
            return;
        }
        foreach ($data as $k => $v) {
            $name = $prefix === '' ? (string) $k : $prefix . '[' . $k . ']';
            if (is_string($k) && $k !== '') {
                $out[] = [$target, '(key)' . $name, $cut($k)];
            }
            if (is_array($v)) {
                self::flatten($target, $v, $name, $out, $cut, $depth + 1);
            } elseif (is_scalar($v)) {
                $out[] = [$target, $name, $cut((string) $v)];
            }
        }
    }
}
