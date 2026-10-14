# Security policy

Please report vulnerabilities privately through GitHub Security Advisories on this repository
(or email the maintainer). Do not open public issues for bypasses or exploitable bugs.

## Threat model and limits

AdelWAF is an in-process (PHP) filter. It cannot see traffic that never reaches PHP (static files,
other runtimes) and it runs *inside* the process it protects, so it is not a substitute for patching,
least-privilege file permissions, or a network/ModSecurity-level WAF where one is available. Treat it as
defence in depth: start in `monitor` mode, review the log, then switch to `block`.

Ruleset updates are verified with an ed25519 signature (ext-sodium) and are never fetched during a web request.
