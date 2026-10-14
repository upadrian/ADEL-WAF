# Changelog

## 2.0.0 (unreleased)

Complete rewrite as a Composer package (`upadrian/adel-waf`, MIT, PHP >= 8.0).

- Config-file only (PHP/JSON + `config.d/*.json`), JSON Schemas under `schema/`.
- Anomaly-scoring detection engine with input normalisation, JSON/cookie/header/URI inspection and per-param exclusions.
- Versioned, updatable, signed rulesets (`rules:update`, `rules:rollback`).
- Storage: Redis when available (ext-redis or Predis), concurrency-safe file fallback, circuit breaker.
- Trusted-proxy aware client IP, rate limits, bans, allow/deny lists, monitor mode, fail-open bootstrap.
- JSON Lines event log, `bin/adel-waf` management CLI, offline web-shell scanner.
- Removed: WordPress plugin, CodeIgniter copy and the single-file `AdelWAF.php` (kept in tag `v1.0.1`).
- Fixed: reflected XSS in the block page, spoofable IP, phpMyAdmin-cookie bypass, per-request shell scan, fatal static call in PHP 8.
