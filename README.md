# `lsec`

`lsec` is a Laravel security audit CLI written in Rust. It scans a Laravel
project for common security issues, insecure coding patterns, risky
configuration, exposed secrets, and dependency concerns, then reports findings
in human-readable, JSON, or SARIF form.

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

### Authentication

- sensitive-looking routes without visible auth middleware
- models present without visible Gate or Policy definitions
- weak password hashing usage such as `md5()` or `sha1()`
- remember-me token usage without obvious expiry controls
- password handling without visible modern hashing usage

### Injection

- raw SQL calls with interpolated variables
- models missing visible `$fillable` or `$guarded` declarations
- request input passed directly into query builder clauses
- `eval()` usage

### HTTP and Session Security

- CSRF middleware exceptions without visible justification
- insecure or missing session cookie flags
- wildcard CORS origins in config
- hardcoded non-localhost `http://` URLs in config or routes

### Storage and Upload Handling

- file access paths influenced by request input
- file upload handling without visible validation
- public storage disk exposure
- files already present under `storage/app/public/`

### Dependencies

- severely outdated Laravel core versions in `composer.lock`
- known vulnerable Packagist packages via OSV lookup
- best-effort notice when the vulnerability database is unreachable

### Secrets

- hardcoded secret-like values in `.php` and `.env` files
- committed private keys or certificate material
- custom secret regex patterns from config

### Logging

- debug mode enabled in environment files
- passwords, tokens, secrets, or auth headers being logged
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

### List Supported Rules

```bash
lsec rules
```

### Command Overview

```text
lsec scan <path> [--only <categories>] [--skip <categories>] [--format <pretty|json|sarif>]
                 [--output <file>] [--summary] [--quiet] [--ci]
                 [--fail-on <critical|high|medium|low|info>] [--config <path>]

lsec rules
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

### Skip Specific Categories

```bash
lsec scan . --skip logging,http
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

[rules]
skip = ["logging"]
custom_secrets_patterns = [
  "(?i)internal_token\\s*=\\s*['\\\"][A-Za-z0-9_-]{20,}['\\\"]",
  "(?i)acme_live_[A-Za-z0-9]{24,}"
]
```

### Supported Config Keys

#### `[scan]`

- `exclude_paths`: path prefixes excluded from the project walk
- `fail_on`: default CI failure threshold when `--ci` is used

Default excluded paths are:

```toml
["vendor/", "tests/", "node_modules/", ".git/"]
```

#### `[rules]`

- `skip`: categories to suppress
- `custom_secrets_patterns`: additional regex patterns for secret detection

## Output Formats

### Pretty

The default terminal output prints each finding with:

- severity
- category
- title
- rule id
- explanatory message
- file and line when available
- code snippet when available

It ends with a summary like:

```text
Summary: critical=1, high=2, medium=3, low=0, info=1, total=7
```

### JSON

JSON output includes:

- scan root
- whether summary-only mode was used
- counts by severity
- findings array

This format is useful for custom automation and post-processing.

### SARIF

SARIF output is suitable for security tooling integrations that accept SARIF
2.1.0. `lsec` emits:

- tool metadata
- deduplicated rule entries for reported findings
- result items with severity mapping and source locations

Current SARIF level mapping:

- `CRITICAL` and `HIGH` -> `error`
- `MEDIUM` -> `warning`
- `LOW` and `INFO` -> `note`

## Rule Categories

You can scope scans with `--only` and `--skip` using these category names:

```text
env, auth, injection, http, storage, deps, secrets, logging
```

## How Scanning Works

`lsec` recursively walks the target repository, reads text files into memory,
and skips:

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
2. archive or upload `report.sarif`
3. fail the job when findings meet the chosen severity threshold

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
- only Laravel-relevant patterns currently implemented in the source are
  checked

## Roadmap Ideas

Potential future improvements include:

- richer Laravel version support awareness
- more framework-aware route and middleware analysis
- baseline and suppression support
- diff-only scanning for pull requests
- autofix or remediation suggestions
- GitHub Actions examples and packaged releases

## Development

### Build

```bash
cargo build
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

## License

Copyright (c) 2026 Afaan Bilal <https://afaan.dev>
