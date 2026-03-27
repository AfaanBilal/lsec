//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
pub mod auth;
pub mod deps;
pub mod env;
pub mod http;
pub mod injection;
pub mod logging;
pub mod secrets;
pub mod storage;

#[cfg(test)]
mod tests;

use crate::models::{Finding, RuleMeta, ScanContext};
use crate::scanner::Project;

pub fn all_rule_metadata() -> Vec<RuleMeta> {
    let mut rules = Vec::new();
    rules.extend(env::metadata());
    rules.extend(auth::metadata());
    rules.extend(injection::metadata());
    rules.extend(http::metadata());
    rules.extend(storage::metadata());
    rules.extend(deps::metadata());
    rules.extend(secrets::metadata());
    rules.extend(logging::metadata());
    rules.sort_by_key(|rule| (rule.category.as_str(), rule.id));
    rules
}

pub fn run_rules(project: &Project, context: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(env::run(project, context));
    findings.extend(auth::run(project, context));
    findings.extend(injection::run(project, context));
    findings.extend(http::run(project, context));
    findings.extend(storage::run(project, context));
    findings.extend(deps::run(project, context));
    findings.extend(secrets::run(project, context));
    findings.extend(logging::run(project, context));
    findings.retain(|finding| context.rule_enabled(finding.rule_id, finding.category));
    findings.sort_by_key(|finding| (finding.severity, finding.file.clone(), finding.line));
    findings
}

fn make_finding(
    meta: RuleMeta,
    file: Option<&str>,
    line: Option<usize>,
    title: impl Into<String>,
    message: impl Into<String>,
    snippet: Option<String>,
) -> Finding {
    Finding {
        rule_id: meta.id,
        title: title.into(),
        message: message.into(),
        remediation: remediation_for_rule(meta.id),
        confidence: confidence_for_rule(meta.id),
        severity: meta.default_severity,
        category: meta.category,
        file: file.map(ToOwned::to_owned),
        line,
        snippet,
    }
}

fn remediation_for_rule(rule_id: &str) -> &'static str {
    match rule_id {
        "env.committed-dotenv" => {
            "Ignore environment files in version control and rotate any secrets that may already have been committed."
        }
        "env.app-debug-production" | "logging.debug-leak" => {
            "Disable debug mode in production-like environments and verify that verbose error pages are not exposed."
        }
        "env.app-env-mismatch" => {
            "Align the environment filename and APP_ENV value so production hardening paths behave as expected."
        }
        "env.weak-app-key" => {
            "Generate a fresh long random APP_KEY and rotate any encrypted or signed data if the old key may have been exposed."
        }
        "env.hardcoded-db-creds" => {
            "Move database credentials into environment-backed configuration instead of committing them in PHP config files."
        }
        "env.app-url-http" => {
            "Use HTTPS for production-facing APP_URL values unless the application is strictly internal and transport is protected elsewhere."
        }
        "env.session-secure-cookie-disabled" | "http.cookie-flags" => {
            "Enable secure cookie flags so session cookies are restricted to HTTPS and hardened browser contexts."
        }
        "auth.missing-route-auth" => {
            "Protect sensitive routes with authentication middleware and verify the route group inherits the expected auth stack."
        }
        "auth.missing-route-authorization" | "auth.missing-policy" => {
            "Add explicit authorization checks such as policies, gates, roles, or permissions for sensitive actions."
        }
        "auth.weak-password-hash" | "auth.password-hash-missing" => {
            "Use Laravel Hash::make with a modern driver such as bcrypt or argon2 for password storage and verification."
        }
        "auth.remember-token-no-expiry" => {
            "Add explicit session revocation, remember-token rotation, or expiry controls for long-lived login state."
        }
        "auth.impersonation-feature" => {
            "Restrict impersonation to audited administrator workflows and log each impersonation start and stop event."
        }
        "auth.user-controlled-role-assignment" => {
            "Do not map request input directly to roles or permissions without strict authorization and allowlisting."
        }
        "injection.raw-sql-interpolation" | "injection.unvalidated-input-query" => {
            "Prefer bound parameters and validated normalized inputs before they reach SQL or query-builder clauses."
        }
        "injection.mass-assignment" => {
            "Define explicit $fillable or safe $guarded rules so user input cannot silently write unintended attributes."
        }
        "injection.eval" | "injection.command-exec" => {
            "Remove dynamic execution sinks where possible and never feed them attacker-controlled data."
        }
        "injection.unserialize" => {
            "Avoid PHP unserialize on untrusted data; prefer JSON or tightly controlled deserialization formats."
        }
        "injection.dynamic-include" => {
            "Replace dynamic include paths with fixed allowlisted code paths or factory mappings."
        }
        "http.csrf-exceptions" => {
            "Document every CSRF exclusion and verify the route is protected by an alternative trust or signature mechanism."
        }
        "http.cors-wildcard" => {
            "Restrict allowed origins to the minimum trusted set, especially for credentialed browser flows."
        }
        "http.insecure-http" => {
            "Replace hardcoded HTTP URLs with HTTPS or configurable environment-backed endpoints."
        }
        "http.trusted-proxies-wildcard" => {
            "Trust only known upstream proxies and document the deployment topology behind forwarded headers."
        }
        "http.ssrf-user-url" | "http.metadata-endpoint" => {
            "Allowlist outbound destinations and block access to internal networks and metadata services from user-driven fetch paths."
        }
        "http.debug-dashboard-exposed" => {
            "Restrict debug dashboards to trusted environments and authenticated operators or disable them entirely in production."
        }
        "storage.user-controlled-path" | "storage.user-controlled-filename" => {
            "Normalize file paths and filenames, regenerate storage names when possible, and confine access to safe directories."
        }
        "storage.upload-validation" | "storage.image-processing-unvalidated" => {
            "Validate uploaded files for MIME, type, and size before storing or processing them."
        }
        "storage.public-disk" => {
            "Review whether public storage exposure is intentional and avoid placing sensitive files on web-accessible disks."
        }
        "storage.zip-extract" => {
            "Validate archive entry paths before extraction to prevent zip-slip and unintended file overwrite behavior."
        }
        "deps.known-vuln" | "deps.outdated-laravel" | "deps.old-php-constraint" => {
            "Update the affected dependency or runtime constraint to a supported, patched version and verify compatibility in CI."
        }
        "deps.vuln-db-unreachable" => {
            "Re-run dependency scanning with network access or use a mirrored advisory source in CI."
        }
        "deps.abandoned-package" => {
            "Replace abandoned packages with actively maintained alternatives and review transitive risk before release."
        }
        "deps.lockfile-missing" => {
            "Commit composer.lock so dependency reviews, deployments, and vulnerability checks operate on a reproducible package set."
        }
        "secrets.inline-secret"
        | "secrets.cloud-access-key"
        | "secrets.embedded-credentials-url" => {
            "Remove hardcoded credentials, rotate any exposed secrets, and move them into environment or secret-manager backed storage."
        }
        "secrets.private-key" => {
            "Remove committed private keys or certificates from the repository and rotate them if exposure is possible."
        }
        "logging.sensitive-log" => {
            "Redact secrets, tokens, and credentials before they reach logs, even in debug-only code paths."
        }
        "logging.auth-failure-missing" => {
            "Add safe authentication failure logging so abuse and brute-force activity can be monitored without storing credentials."
        }
        "logging.debug-log-level" => {
            "Avoid debug or trace logging in production-like environments unless it is time-bound and tightly controlled."
        }
        "logging.debug-artifact" => {
            "Remove leftover debug helpers before release so they cannot leak state or disrupt request handling."
        }
        _ => {
            "Review the flagged code path and harden it using least privilege, strict validation, and environment-specific safeguards."
        }
    }
}

fn confidence_for_rule(rule_id: &str) -> f32 {
    match rule_id {
        "deps.known-vuln" => 0.98,
        "secrets.private-key" | "secrets.cloud-access-key" => 0.97,
        "injection.eval" | "injection.command-exec" | "injection.unserialize" => 0.95,
        "http.metadata-endpoint" | "http.debug-dashboard-exposed" => 0.85,
        "auth.missing-route-authorization"
        | "auth.missing-policy"
        | "logging.auth-failure-missing" => 0.62,
        id if id.starts_with("env.") => 0.88,
        id if id.starts_with("auth.") => 0.76,
        id if id.starts_with("injection.") => 0.87,
        id if id.starts_with("http.") => 0.79,
        id if id.starts_with("storage.") => 0.75,
        id if id.starts_with("deps.") => 0.84,
        id if id.starts_with("secrets.") => 0.9,
        id if id.starts_with("logging.") => 0.72,
        _ => 0.7,
    }
}

fn find_line(content: &str, pattern: &str) -> Option<usize> {
    content
        .lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(pattern).then_some(idx + 1))
}

fn snippet_for_line(content: &str, line_number: usize) -> Option<String> {
    content
        .lines()
        .nth(line_number.saturating_sub(1))
        .map(str::trim)
        .map(str::to_string)
}
