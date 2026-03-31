# Changelog

All notable changes to `lsec` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **injection.xss-unescaped-output** — detects `{!! !!}` unescaped output in
  Blade templates that can introduce XSS vulnerabilities
- **injection.xxe** — flags XML parsing functions (`simplexml_load_string`,
  `DOMDocument`, etc.) without external entity loading protection
- **injection.insecure-randomness** — warns on `rand()`, `mt_rand()`,
  `array_rand()`, and `shuffle()` which are not cryptographically secure
- **injection.open-redirect** — detects `redirect()` calls where the target
  URL comes from user input
- **http.rate-limiting-missing** — checks whether auth routes (login,
  register, password reset) have `ThrottleRequests` or `RateLimiter` applied
- **http.security-headers-missing** — flags projects with no visible security
  headers middleware (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`, etc.)
- **http.hsts-missing** — warns when no `Strict-Transport-Security` header
  configuration is detected in the application
- **http.sri-missing** — detects externally loaded `<script>` and `<link>`
  tags in Blade templates that lack an `integrity` attribute (Subresource
  Integrity)
- **env.missing-security-txt** — checks for the presence of a `security.txt`
  file at `public/.well-known/security.txt`
- **auth.missing-input-validation** — flags controllers that use request input
  (`$request->input()`, `->all()`, etc.) without visible validation
- CHANGELOG.md for tracking release history

### Changed

- Total rule count increased from 51 to 61
- Confidence threshold test updated to be more targeted

## [0.1.3] - 2026-03-28

### Added

- Initial public release on [crates.io](https://crates.io/crates/lsec)
- `cargo install lsec` support
- Automated release script with crates.io publishing
- 51 rules across 8 categories: env, auth, injection, http, storage, deps,
  secrets, logging
- Pretty terminal, JSON, and SARIF 2.1.0 output formats
- CI mode with severity-based gating and exit codes
- Baseline management for suppressing known findings
- Confidence scoring with per-rule overrides
- Configuration via `lsec.toml`
- GitHub Actions workflow for cross-platform releases
- GitHub Code Scanning integration via SARIF upload

[Unreleased]: https://github.com/AfaanBilal/lsec/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/AfaanBilal/lsec/releases/tag/v0.1.3
