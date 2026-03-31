//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use regex::Regex;

use crate::models::{Category, RuleMeta, ScanContext, Severity};
use crate::scanner::Project;

use super::{find_line, make_finding, snippet_for_line};

const RULES: [RuleMeta; 8] = [
    RuleMeta {
        id: "env.committed-dotenv",
        title: ".env file appears commit-eligible",
        category: Category::Env,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "env.app-debug-production",
        title: "APP_DEBUG enabled in production-like environment",
        category: Category::Env,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "env.app-env-mismatch",
        title: "Environment configuration mismatch",
        category: Category::Env,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "env.weak-app-key",
        title: "Weak or default APP_KEY",
        category: Category::Env,
        default_severity: Severity::Critical,
    },
    RuleMeta {
        id: "env.hardcoded-db-creds",
        title: "Database credentials hardcoded in config",
        category: Category::Env,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "env.app-url-http",
        title: "APP_URL uses insecure HTTP",
        category: Category::Env,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "env.session-secure-cookie-disabled",
        title: "SESSION_SECURE_COOKIE disabled in production-like environment",
        category: Category::Env,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "env.missing-security-txt",
        title: "Missing security.txt file",
        category: Category::Env,
        default_severity: Severity::Low,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Env) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let gitignore = project
        .find_file(".gitignore")
        .map(|file| file.content.as_str())
        .unwrap_or_default();

    for dotenv_name in [".env", ".env.production", ".env.prod"] {
        if let Some(file) = project.find_file(dotenv_name) {
            if !is_ignored_by_gitignore(dotenv_name, gitignore) {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(1),
                    ".env file is present and not obviously ignored",
                    "The scan target contains an environment file that is not obviously excluded by .gitignore. This increases the chance of accidental secret commits.",
                    None,
                ));
            }
        }
    }

    let app_key_re = Regex::new(r"(?m)^APP_KEY=(.+)$").expect("valid regex");
    let app_env_re = Regex::new(r"(?m)^APP_ENV=(.+)$").expect("valid regex");
    let app_debug_re = Regex::new(r"(?m)^APP_DEBUG=(.+)$").expect("valid regex");
    let app_url_re = Regex::new(r"(?m)^APP_URL=(.+)$").expect("valid regex");
    let secure_cookie_re = Regex::new(r"(?m)^SESSION_SECURE_COOKIE=(.+)$").expect("valid regex");

    for file in project.files_under(".env") {
        let app_env = app_env_re
            .captures(&file.content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().trim_matches('"').to_ascii_lowercase());
        let app_debug = app_debug_re
            .captures(&file.content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().trim_matches('"').to_ascii_lowercase());
        let app_url = app_url_re
            .captures(&file.content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().trim_matches('"').to_string());
        let secure_cookie = secure_cookie_re
            .captures(&file.content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().trim_matches('"').to_ascii_lowercase());
        let production_like = file.relative_path.contains("production")
            || file.relative_path.contains("prod")
            || matches!(app_env.as_deref(), Some("production" | "prod"));

        if production_like && matches!(app_debug.as_deref(), Some("true" | "1")) {
            let line = find_line(&file.content, "APP_DEBUG=").unwrap_or(1);
            findings.push(make_finding(
                RULES[1],
                Some(&file.relative_path),
                Some(line),
                "APP_DEBUG is enabled for production",
                "Production-like environment files should not enable Laravel debug mode because it can leak stack traces and secrets.",
                snippet_for_line(&file.content, line),
            ));
        }

        if file.relative_path.contains("production")
            && !matches!(app_env.as_deref(), Some("production" | "prod"))
        {
            let line = find_line(&file.content, "APP_ENV=").unwrap_or(1);
            findings.push(make_finding(
                RULES[2],
                Some(&file.relative_path),
                Some(line),
                "Production environment file has non-production APP_ENV",
                format!(
                    "{} declares a non-production APP_ENV value, which can disable production hardening paths.",
                    file.relative_path
                ),
                snippet_for_line(&file.content, line),
            ));
        }

        if let Some(app_url) = app_url {
            let app_url_lower = app_url.to_ascii_lowercase();
            if production_like
                && app_url_lower.starts_with("http://")
                && !app_url_lower.contains("localhost")
                && !app_url_lower.contains("127.0.0.1")
            {
                let line = find_line(&file.content, "APP_URL=").unwrap_or(1);
                findings.push(make_finding(
                    RULES[5],
                    Some(&file.relative_path),
                    Some(line),
                    "APP_URL uses HTTP in a production-like environment",
                    "Production-facing Laravel URLs should prefer HTTPS to avoid mixed-content and insecure-origin issues.",
                    snippet_for_line(&file.content, line),
                ));
            }
        }

        if production_like && matches!(secure_cookie.as_deref(), Some("false" | "0")) {
            let line = find_line(&file.content, "SESSION_SECURE_COOKIE=").unwrap_or(1);
            findings.push(make_finding(
                RULES[6],
                Some(&file.relative_path),
                Some(line),
                "SESSION_SECURE_COOKIE is disabled for a production-like environment",
                "Laravel session cookies should be marked secure in production-like environments so they are only sent over HTTPS.",
                snippet_for_line(&file.content, line),
            ));
        }

        if let Some(key) = app_key_re
            .captures(&file.content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().trim_matches('"').to_string())
        {
            let weak = key.is_empty()
                || key.len() < 16
                || key.contains("SomeRandomString")
                || key.contains("changeme")
                || key.eq_ignore_ascii_case("base64:");
            if weak {
                let line = find_line(&file.content, "APP_KEY=").unwrap_or(1);
                findings.push(make_finding(
                    RULES[3],
                    Some(&file.relative_path),
                    Some(line),
                    "APP_KEY looks weak or default",
                    "Laravel APP_KEY should be a long, randomly generated secret. Placeholder or trivially short keys weaken encryption and signed payload integrity.",
                    snippet_for_line(&file.content, line),
                ));
            }
        }
    }

    let hardcoded_re =
        Regex::new(r"'(host|database|username|password)'\s*=>\s*'[^']+'").expect("valid regex");
    for file in project.files_under("config/") {
        if !file.relative_path.ends_with(".php") {
            continue;
        }
        for (idx, line) in file.content.lines().enumerate() {
            if hardcoded_re.is_match(line) && !line.contains("env(") {
                findings.push(make_finding(
                    RULES[4],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Database configuration appears hardcoded",
                    "Database credentials in config files should be sourced from environment variables instead of hardcoded strings.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    // Check for security.txt
    let has_security_txt = project.find_file("public/.well-known/security.txt").is_some()
        || project.find_file(".well-known/security.txt").is_some();
    if !has_security_txt {
        findings.push(make_finding(
            RULES[7],
            None,
            None,
            "No security.txt file found",
            "Place a security.txt file at public/.well-known/security.txt with contact details so security researchers can report vulnerabilities. Generate one at https://securitytxt.org/.",
            None,
        ));
    }

    findings
}

fn is_ignored_by_gitignore(path: &str, gitignore: &str) -> bool {
    gitignore.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }

        trimmed == ".env"
            || trimmed == ".env.*"
            || trimmed == "*.env"
            || trimmed == "/.env"
            || trimmed == path
            || trimmed == format!("/{path}")
    })
}
