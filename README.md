# `lsec`

`lsec` is a Laravel security audit CLI written in Rust. It scans a Laravel
project for common security issues, insecure coding patterns, risky
configuration, exposed secrets, and dependency concerns, then reports findings
in human-readable, JSON, or SARIF form. It currently ships 51 rules across 8
categories.

## Why `lsec`

Laravel applications often accumulate security-sensitive configuration and
framework conventions across routes, middleware, models, environment files, and
deployment settings. `lsec` helps surface high-signal issues early by performing
fast repository-level static checks against common Laravel security footguns.

`lsec` is designed to be useful for:

- local security reviews before shipping
- CI gates for Laravel repositories
- quick audits of new or inherited codebases
- exporting machine-readable findings for tooling pipelines

## What It Checks

`lsec` currently groups checks into 8 categories:

- `env`
- `auth`
- `injection`
- `http`
- `storage`
- `deps`
- `secrets`
- `logging`

### Environment

- `.env` files that appear commit-eligible because they are not obviously
  ignored
- `APP_DEBUG=true` in production-like environment files
- production environment filename and `APP_ENV` mismatches
- weak, placeholder, or trivially short `APP_KEY` values
- hardcoded database credentials in Laravel config files
- `APP_URL` using HTTP in production-like environments
- `SESSION_SECURE_COOKIE=false` in production-like environments

### Authentication

- sensitive-looking routes without visible auth middleware
- sensitive routes with auth but no obvious policy, gate, role, or permission check
- models present without visible Gate or Policy definitions
- weak password hashing usage such as `md5()` or `sha1()`
- remember-me token usage without obvious expiry controls
- password handling without visible modern hashing usage
- impersonation-style features that need strong gating and auditability
- role or permission assignment driven directly from request input

### Injection

- raw SQL calls with interpolated variables
- models missing visible `$fillable` or `$guarded` declarations
- request input passed directly into query builder clauses
- `eval()` usage
- command execution sinks such as `exec()`, `shell_exec()`, or `proc_open()`
- `unserialize()` usage
- dynamic `include` / `require` paths

### HTTP and Session Security

- CSRF middleware exceptions without visible justification
- insecure or missing session cookie flags
- wildcard CORS origins in config
- hardcoded non-localhost `http://` URLs in config or routes
- wildcard trusted proxy configuration in `TrustProxies`
- outbound HTTP or file fetches built from user-controlled URLs
- cloud metadata endpoint references that deserve SSRF review
- debug tooling routes for Telescope, Horizon, Debugbar, or Ignition that may be exposed

### Storage and Upload Handling

- file access paths influenced by request input
- file upload handling without visible validation
- public storage disk exposure
- files already present under `storage/app/public/`
- user-controlled filenames passed into storage helpers
- archive extraction calls that deserve zip-slip review
- image processing code that lacks visible upload validation

### Dependencies

- severely outdated Laravel core versions in `composer.lock` or `composer.json`
- known vulnerable Packagist packages via OSV lookup
- abandoned Composer packages
- PHP version constraints that may still permit unsupported runtimes
- missing `composer.lock` as a reproducibility and auditability gap
- best-effort notice when the vulnerability database is unreachable

### Secrets

- hardcoded secret-like values in `.php` and `.env` files
- committed private keys or certificate material
- URLs with embedded credentials
- cloud access key-like literals
- custom secret regex patterns from config

### Logging

- debug mode enabled in environment files
- debug or trace log level in production-like environments
- passwords, tokens, secrets, or auth headers being logged
- leftover `dd()`, `dump()`, `var_dump()`, or `print_r()` calls
- missing visible authentication failure logging

## Installation

### Prerequisites

- Rust toolchain with Cargo
- a Laravel project to scan

### Build From Source

```bash
cargo build --release
```

The resulting binary will be available at:

```text
target/release/lsec
```

### Run Without Installing

```bash
cargo run -- scan /path/to/laravel-app
```

## CLI Usage

### Scan a Project

```bash
lsec scan /path/to/laravel-app
```

The supplied path must be the Laravel application root. `lsec` validates this up front and errors out if the directory does not look like a Laravel project root.

### List Supported Rules

```bash
lsec rules
```

### Command Overview

```text
lsec scan <path> [--only <categories>] [--skip <categories>]
                 [--only-rule <ids>] [--skip-rule <ids>]
                 [--format <pretty|json|sarif>] [--output <file>]
                 [--summary] [--quiet] [--ci]
                 [--fail-on <critical|high|medium|low|info>]
                 [--config <path>] [--baseline <path>] [--write-baseline]
                 [--min-confidence <float>]

lsec rules
lsec baseline write <path> [--baseline <file>] [--config <file>]
lsec baseline prune <path> [--baseline <file>] [--config <file>]
```

## Common Examples

### Pretty Terminal Report

```bash
lsec scan . 
```

### JSON Output

```bash
lsec scan . --format json
```

### SARIF Output

```bash
lsec scan . --format sarif --output report.sarif
```

### Show Summary Only

```bash
lsec scan . --summary
```

### Scan Only Selected Categories

```bash
lsec scan . --only env,secrets,deps
```

### Scan Only Specific Rules

```bash
lsec scan . --only-rule http.ssrf-user-url,secrets.private-key
```

### Skip Specific Categories

```bash
lsec scan . --skip logging,http
```

### Skip Specific Rules

```bash
lsec scan . --skip-rule logging.debug-artifact,auth.impersonation-feature
```

### Write a Baseline File During Scan

```bash
lsec scan . --write-baseline
```

### Write a Baseline File Explicitly

```bash
lsec baseline write .
```

Baseline commands use the same Laravel-root validation as `scan`.

### Prune Stale Baseline Entries

```bash
lsec baseline prune .
```

### Ignore Low-Confidence Findings

```bash
lsec scan . --min-confidence 0.8
```

### Use an Existing Baseline File

```bash
lsec scan . --baseline ci/lsec-baseline.json
```

### Use in CI and Fail on Medium or Higher

```bash
lsec scan . --ci --fail-on medium
```

### Use a Custom Config File

```bash
lsec scan . --config ci/lsec.toml
```

## Exit Codes

- `0`: scan completed successfully and did not cross the configured CI failure
  threshold
- `1`: `--ci` was enabled and at least one finding met or exceeded the
  configured failure severity
- `2`: CLI or runtime error

Severity ordering used by CI failure evaluation is:

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

With `--ci`, `--fail-on high` fails the scan if any `CRITICAL` or `HIGH`
finding is present.

## Configuration

By default, `lsec` looks for `lsec.toml` in the scan root. You can also point
to a file explicitly with `--config`.

### Example `lsec.toml`

```toml
[scan]
exclude_paths = ["vendor/", "tests/", "node_modules/", ".git/", "storage/logs/"]
fail_on = "high"
min_confidence = 0.7

[rules]
min_confidence_overrides = { "auth.missing-route-authorization" = 0.8, "logging.auth-failure-missing" = 0.55 }
skip = ["logging"]
skip_ids = ["logging.debug-artifact"]
custom_secrets_patterns = [
  "(?i)internal_token\\s*=\\s*['\\\"][A-Za-z0-9_-]{20,}['\\\"]",
  "(?i)acme_live_[A-Za-z0-9]{24,}"
]
```

### Supported Config Keys

#### `[scan]`

- `exclude_paths`: path prefixes excluded from the project walk
- `fail_on`: default CI failure threshold when `--ci` is used
- `min_confidence`: global confidence floor applied before reporting

Default excluded paths are:

```toml
["vendor/", "tests/", "node_modules/", ".git/"]
```

#### `[rules]`

- `skip`: categories to suppress
- `skip_ids`: exact rule ids to suppress
- `custom_secrets_patterns`: additional regex patterns for secret detection
- `min_confidence_overrides`: per-rule confidence floors keyed by exact rule id

## Output Formats

### Pretty

The default terminal output prints each finding in a structured two-column block with severity badges, confidence, location, explanation, remediation, and snippet context. It starts and ends with tabular severity and category summaries.

### JSON

JSON output includes:

- scan root
- whether summary-only mode was used
- counts by severity
- counts by category
- findings array with remediation and confidence

This format is useful for custom automation and post-processing.

### SARIF

SARIF output is suitable for security tooling integrations that accept SARIF
2.1.0. `lsec` emits:

- tool metadata
- deduplicated rule entries for reported findings
- remediation help text per rule
- result items with severity mapping, confidence, and source locations

Current SARIF level mapping:

- `CRITICAL` and `HIGH` -> `error`
- `MEDIUM` -> `warning`
- `LOW` and `INFO` -> `note`

## Rule Categories

You can scope scans with category and rule filters.

Category filters:

```text
env, auth, injection, http, storage, deps, secrets, logging
```

Rule filters use exact ids, for example:

```text
http.ssrf-user-url, secrets.private-key, deps.known-vuln
```

`lsec rules` also shows the default severity, default confidence, and a short remediation hint for each rule.

## How Scanning Works

`lsec` first validates that the supplied path looks like a Laravel application root, then recursively walks the target repository, reads text files into memory, and skips:

- excluded path prefixes from config
- binary files
- invalid UTF-8 files

Checks are heuristic and static. They do not execute the application.

## CI Integration

`lsec` is intended to be easy to wire into CI jobs.

### Example

```bash
lsec scan . --ci --format sarif --output report.sarif --fail-on high
```

Typical CI flow:

1. run `lsec` on the checked-out Laravel project
2. optionally load or refresh a baseline file for known legacy findings
3. archive or upload `report.sarif`
4. fail the job when findings meet the chosen severity threshold and confidence floor

## Current Limitations

`lsec` is deliberately lightweight, so it currently has a few important
limitations:

- checks are heuristic and may produce false positives or false negatives
- dependency vulnerability lookup is best-effort and depends on network access
- some findings are inferred from framework conventions rather than full code
  flow analysis
- secrets detection is regex-based
- route and auth analysis is intentionally shallow and favors speed over deep
  semantic understanding
- the target path must be the Laravel application root rather than an arbitrary subdirectory
- only Laravel-relevant patterns currently implemented in the source are
  checked

## Roadmap Ideas

Potential future improvements include:

- richer Laravel version support awareness
- more framework-aware route and middleware analysis
- richer baseline lifecycle support
- diff-only scanning for pull requests
- autofix or remediation suggestions
- GitHub Actions examples and packaged releases

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Run Against This Repo

```bash
cargo run -- scan .
```

### List Rules During Development

```bash
cargo run -- rules
```

## Project Structure

```text
src/
  main.rs         CLI entrypoint
  config.rs       configuration loading
  models.rs       shared scan models and enums
  scanner/        repository loading and file discovery
  rules/          security rule implementations
  reporter/       pretty, JSON, and SARIF renderers
```

## Security Review Guidance

`lsec` is a developer aid, not a replacement for a full security review. Treat
findings as prompts for investigation, especially for high- and critical-level
results. A clean scan does not guarantee a secure application.

## Contributing

All contributions are welcome. Please create an issue first for any feature request
or bug.

## License

**lsec** is released under the MIT License.
Check out the full license [here](LICENSE).

Copyright (c) 2026 Afaan Bilal <https://afaan.dev>
