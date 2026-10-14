<?php

declare(strict_types=1);

/**
 * Regenerates rules/default/{request.json,scanner.json,manifest.json}.
 * Rules are authored here as PHP arrays (no JSON double-escaping) and emitted as JSON.
 *
 *   php tools/build-default-pack.php [version]
 */

$version = $argv[1] ?? '2.0.0';
$out = dirname(__DIR__) . '/rules/default';
if (!is_dir($out)) {
    mkdir($out, 0777, true);
}

$R = static fn (string $id, string $cat, string $pattern, int $score, array $targets, int $paranoia = 1, array $extra = []): array
    => array_merge(['id' => $id, 'category' => $cat, 'pattern' => $pattern, 'score' => $score, 'paranoia' => $paranoia, 'targets' => $targets], $extra);

$A = ['args', 'cookies', 'body'];
$AU = ['args', 'cookies', 'body', 'uri'];

$rules = [
    // ---- XSS
    $R('xss-001', 'xss', '~<\s*script\b|</\s*script~i', 5, $AU, 1, ['message' => 'script tag']),
    $R('xss-002', 'xss', '~\bjavascript\s*:|\bvbscript\s*:|\bdata\s*:\s*text/html~i', 5, $AU),
    $R('xss-003', 'xss', '~[\s"\'/;]on(?:abort|auxclick|blur|cancel|canplay|change|click|close|contextmenu|dblclick|drag\w*|drop|error|focus|input|invalid|key\w+|load\w*|mouse\w+|pointer\w+|pause|play\w*|reset|resize|scroll|select|submit|toggle|touch\w+|unload|wheel|animation\w+|transition\w+|begin|end|start|hashchange|message|popstate|storage)\s*=~i', 5, $A, 1, ['message' => 'inline event handler']),
    $R('xss-004', 'xss', '~<\s*(?:iframe|object|embed|frame|frameset|applet|meta|base|link|form|svg|math|isindex)\b~i', 4, $A),
    $R('xss-005', 'xss', '~<\s*(?:img|image|video|audio|body|input|details|marquee|style)\b[^>]{0,200}(?:src|href|on\w+|style)\s*=~i', 3, $A, 2),
    $R('xss-006', 'xss', '~\b(?:document\.(?:cookie|write|location|domain)|window\.location|eval\s*\(|\.innerhtml\s*=|fromcharcode\s*\()~i', 4, $A),
    $R('xss-007', 'xss', '~\b(?:alert|prompt|confirm)\s*[(`]~i', 3, $A),
    $R('xss-008', 'xss', '~expression\s*\(|-moz-binding|@import\s+["\']?(?:https?:|//)~i', 4, $A, 2),

    // ---- SQL injection
    $R('sqli-001', 'sqli', '~\bunion\b(?:\s+all)?\s+(?:distinct\s+)?select\b~i', 5, $A),
    $R('sqli-002', 'sqli', '~[\'"`)]\s*(?:or|and|xor|\|\||&&)\s*[\'"`(]?\s*[\w@]+[\'"`)]?\s*(?:=|like|<|>|is)\s*[\'"`(]?\s*[\w@]+~i', 5, $A, 1, ['message' => "tautology after quote"]),
    $R('sqli-003', 'sqli', '~\b(?:or|and)\s+\d+\s*=\s*\d+\b~i', 5, $A),
    $R('sqli-004', 'sqli', '~\binformation_schema\b|\bmysql\.user\b|\bsys\.(?:objects|tables|columns)\b|\bpg_catalog\b|\bsqlite_master\b~i', 5, $A),
    $R('sqli-005', 'sqli', '~\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|\bdbms_pipe\.receive_message\b~i', 5, $A),
    $R('sqli-006', 'sqli', '~\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bload\s+data\s+(?:local\s+)?infile\b~i', 5, $A),
    $R('sqli-007', 'sqli', '~[;\'"`)]\s*(?:drop|truncate|alter|create|insert|update|delete|exec|execute)\s+(?:table|database|from|into|set|xp_|master|user)\b~i', 5, $A),
    $R('sqli-008', 'sqli', '~\b(?:extractvalue|updatexml|json_keys|exp|name_const)\s*\(\s*(?:\d|concat|\(|0x)~i', 5, $A),
    $R('sqli-009', 'sqli', '~\bselect\b.{1,80}\bfrom\b~is', 2, $A, 2),
    $R('sqli-010', 'sqli', '~(?:--|#)\s*$|;\s*--~', 2, $A, 2),
    $R('sqli-011', 'sqli', '~\b(?:unhex|hex|char|concat(?:_ws)?|group_concat|load_file|ascii|substring|substr)\s*\(~i', 2, $A, 3),

    // ---- Path traversal / LFI
    $R('lfi-001', 'lfi', '~(?:\.\.[/\\\\]){2,}~', 5, $AU, 1, ['message' => 'directory traversal']),
    $R('lfi-002', 'lfi', '~\.\.[/\\\\]~', 3, $A, 2),
    $R('lfi-003', 'lfi', '~/etc/(?:passwd|shadow|group|hosts|issue)\b|\b(?:boot|win)\.ini\b|/proc/self/(?:environ|cmdline)|c:[/\\\\]windows~i', 5, $AU),
    $R('lfi-004', 'lfi', '~\b(?:php|phar|zip|expect|glob|data|input)://~i', 5, $A, 1, ['message' => 'dangerous stream wrapper']),

    // ---- Remote inclusion
    $R('rfi-001', 'rfi', '~(?:^|[=\s])(?:https?|ftps?)://[^\s]+\.(?:php\d?|phtml|inc|txt)\b[^\s]*\?*$~i', 3, $A, 2),
    $R('rfi-002', 'rfi', '~\b(?:file|gopher|dict|ldap|tftp|jar|netdoc)://~i', 4, $A),

    // ---- Command / code injection
    $R('rce-001', 'rce', '~\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|assert|create_function)\s*\(~i', 5, $A),
    $R('rce-002', 'rce', '~<\?(?:php|=)|<\?\s~i', 5, $A, 1, ['message' => 'php open tag']),
    $R('rce-003', 'rce', '~(?:[;|`]|\$\(|&&|\|\|)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python\d?|perl|ruby|php|powershell|cmd(?:\.exe)?|chmod|chown|rm|echo|ping|nslookup)\b(?:\s|$|;|\|)~i', 4, $A),
    $R('rce-004', 'rce', '~/bin/(?:ba|z|da|c)?sh\b|/usr/bin/(?:env|python|perl)|cmd\.exe|powershell(?:\.exe)?\s+-~i', 5, $A),
    $R('rce-008', 'rce', '~\b(?:wget|curl|fetch|lwp-download)\s+(?:-\S+\s+)*(?:https?|ftp)://~i', 3, $A),
    $R('rce-005', 'rce', '~\b(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(~i', 3, $A),
    $R('rce-006', 'rce', '~\$\{\s*(?:jndi|env|sys|lower|upper|::-)[^}]*\}~i', 5, $AU, 1, ['message' => 'log4shell-style expression']),
    $R('rce-007', 'rce', '~\b(?:o:\d+:"|a:\d+:\{|c:\d+:")~i', 3, $A, 2, ['message' => 'serialized object']),

    // ---- Scanners / bots
    $R('bot-001', 'bot', '~sqlmap|nikto|nessus|acunetix|havij|masscan|nmap\s*scripting|wpscan|dirbuster|gobuster|ffuf|zgrab|nuclei|openvas|w3af|arachni|netsparker|jaeles~i', 5, ['headers'], 1, ['names' => ['user-agent'], 'normalize' => false]),

    // ---- Sensitive / probing paths
    $R('path-001', 'probe', '~/\.(?:env|git|svn|hg|htpasswd|htaccess|ds_store|aws|ssh|bash_history)(?:/|$|\.)~i', 5, ['uri']),
    $R('path-002', 'probe', '~eval-stdin\.php|/vendor/phpunit/|/phpunit/phpunit|/cgi-bin/.*(?:%2e|\.\.)|/(?:phpmyadmin|pma|myadmin)/scripts/setup\.php~i', 5, ['uri']),
    $R('path-003', 'probe', '~\.(?:bak|old|orig|save|swp|sql|sqlite|dump|tar|tgz|zip|7z|rar|log)$~i', 3, ['uri'], 2),
    $R('path-004', 'probe', '~/(?:shell|c99|r57|wso|b374k|alfa|webshell|cmd|backdoor)\.(?:php\d?|phtml)$~i', 5, ['uri']),
    $R('path-005', 'probe', '~/(?:composer\.(?:json|lock)|package\.json|\.dockerenv|docker-compose\.ya?ml|phpinfo\.php|info\.php)$~i', 3, ['uri'], 2),

    // ---- Uploads (file names)
    $R('upl-001', 'upload', '~\.(?:php\d?|phtml|pht|phar|shtml|cgi|pl|py|sh|exe|jsp|asp|aspx)(?:\.|$)~i', 5, ['files'], 1, ['message' => 'executable upload']),
    $R('upl-002', 'upload', '~\.(?:htaccess|htpasswd|user\.ini)$~i', 5, ['files']),
];

$scanner = [
    'heuristics' => [
        ['id' => 'scan-h-001', 'pattern' => '~eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(~i', 'score' => 5],
        ['id' => 'scan-h-002', 'pattern' => '~(?:assert|eval|system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)~i', 'score' => 5],
        ['id' => 'scan-h-003', 'pattern' => '~\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(~i', 'score' => 5],
        ['id' => 'scan-h-004', 'pattern' => '~preg_replace\s*\(\s*[\'"]([^\w\s]).*\1[a-z]*e[a-z]*[\'"]~is', 'score' => 4],
        ['id' => 'scan-h-005', 'pattern' => '~(?:gzinflate|gzuncompress)\s*\(\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{200,}~i', 'score' => 5],
        ['id' => 'scan-h-006', 'pattern' => '~\b(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}~i', 'score' => 3],
        ['id' => 'scan-h-007', 'pattern' => '~(?:\\\\x[0-9a-f]{2}){12,}~i', 'score' => 3],
        ['id' => 'scan-h-008', 'pattern' => '~(?:move_uploaded_file|file_put_contents|fwrite)\s*\([^;]{0,80}\$_(?:GET|POST|REQUEST|FILES)~i', 'score' => 3],
    ],
    // Case-insensitive plain substrings from known web shells
    'signatures' => [
        'b374k m1n1', 'Shell I</title>', 'SmEvK_PaThAn Shell', 'by C-W-M</title>', '<title>azrail ', '<title>punkholicshell</title>',
        '<title>g00nshell', '<title>PhpSpy Ver', 'Cr@zy_King</title>', '<title>s72 Shell v', '<title>Ru24PostWebShell -',
        '<title>PHP Web Shell</title>', '<title>lostDC - ', "<title>lama's'hell v", '<title>Web Shell</title>', '<title>SimAttacker - ',
        '<small>NGHshell', '<title>GRP WebShell ', '<title>CasuS ', 'by MafiABoY</title>', '<title>Symlink_Sa', 'Developed By LameHacker',
        '<title>Mini Shell</title>', 'B4TM4N SH3LL</title>', '>Ajax/PHP Command Shell<', 'AK-74 Security Team Web-shell', 'ALFA TEaM Shell',
        'Andela Yuwono Priv8 Shell', '<title>Ani-Shell | India</title>', 'AnonymousFox', 'Antichat Shell</title>', 'Ayyildiz Tim  | AYT',
        '<title>BloodSecurity Hackers Shell</title>', 'Bypass Attack Shell', '[c0derz shell]', '<title>Con7ext Shell V.2</title>',
        'Crystal shell v.', '<b>[ Defacing Tool Pro v', '<title>Dive Shell - Emperor Hacking Team</title>', 'FaTaLSheLL v',
        '<title>G-Security Webshell</title>', '<title>h4ntu shell', 'IDBTEAM SHELLS', '<title>IndoXploit</title>', '<KAdot Universal Shell>',
        '>LIFKA SHELL<', "<title>Loader'z WEB shell</title>", 'Locus7Shell v.', '<title>Lolipop.php - Edited By KingDefacer',
        '<title> Matamu Mat </title>', '<h1>.:NCC:. Shell v', 'PHPShell by Macker', 'PHPShell by MAX666', 'Simple PHP backdoor by DK',
        '<title>SimShell - Simorgh Security MGZ</title>', 'Small Shell - Edited By KingDefacer', '<title>small web shell by zaco',
        'SoldiersofAllah Private Shell', 'Sosyete Safe Mode Bypass Shell', 'STNC&nbsp;WebShell', 'StresBypass', '<title>SyRiAn Sh3ll',
        '<title>Yourman.sh Mini Shell</title>', 'Zerion Mini Shell', '<title>0byt3m1n1-V2</title>', '<title>ZEROSHELL | ZEROSTORE</title>',
        '<title>r57 shell</title>', 'webadmin.php</h1>', 'c99shell', 'WSO ', 'FilesMan',
    ],
];

$enc = static fn ($v): string => json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
file_put_contents("$out/request.json", $enc($rules));
file_put_contents("$out/scanner.json", $enc($scanner));

$manifest = [
    'name' => 'default',
    'version' => $version,
    'min_engine' => '2.0.0',
    'released_at' => gmdate('c'),
    'files' => ['request.json' => hash_file('sha256', "$out/request.json")],
    'extra' => ['scanner.json' => hash_file('sha256', "$out/scanner.json")],
];
file_put_contents("$out/manifest.json", $enc($manifest));
echo count($rules) . " rules written to $out\n";
