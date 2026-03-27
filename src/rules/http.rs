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

const RULES: [RuleMeta; 5] = [
    RuleMeta {
        id: "http.csrf-exceptions",
        title: "Routes excluded from CSRF middleware",
        category: Category::Http,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "http.cookie-flags",
        title: "Session cookie security flags missing",
        category: Category::Http,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "http.cors-wildcard",
        title: "CORS wildcard in production config",
        category: Category::Http,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "http.insecure-http",
        title: "Hardcoded HTTP URLs",
        category: Category::Http,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "http.trusted-proxies-wildcard",
        title: "Trusted proxies wildcard",
        category: Category::Http,
        default_severity: Severity::Medium,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Http) {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if let Some(file) = project.find_file("app/Http/Middleware/VerifyCsrfToken.php") {
        findings.extend(check_csrf_exceptions(file));
    }

    if let Some(file) = project.find_file("config/session.php") {
        for key in ["'secure' =>", "'http_only' =>", "'same_site' =>"] {
            let line = find_line(&file.content, key);
            let missing = match key {
                "'secure' =>" => {
                    line.is_none()
                        || file
                            .content
                            .contains("'secure' => env('SESSION_SECURE_COOKIE', false)")
                }
                "'http_only' =>" => line.is_none() || file.content.contains("'http_only' => false"),
                "'same_site' =>" => line.is_none() || file.content.contains("'same_site' => null"),
                _ => false,
            };
            if missing {
                findings.push(make_finding(
                    RULES[1],
                    Some(&file.relative_path),
                    line.or(Some(1)),
                    "Session cookie flag may be insecure",
                    "Secure, HttpOnly, and SameSite cookie settings should be explicitly hardened for production deployments.",
                    line.and_then(|line_no| snippet_for_line(&file.content, line_no)),
                ));
            }
        }
    }

    if let Some(file) = project.find_file("config/cors.php") {
        if file.content.contains("'allowed_origins' => ['*']")
            || file.content.contains("\"allowed_origins\" => ['*']")
        {
            let line = find_line(&file.content, "allowed_origins").unwrap_or(1);
            findings.push(make_finding(
                RULES[2],
                Some(&file.relative_path),
                Some(line),
                "CORS allows all origins",
                "Wildcard CORS origins are risky for production APIs unless the app is intentionally public and all credentialed flows are disabled.",
                snippet_for_line(&file.content, line),
            ));
        }
    }

    let http_re = Regex::new(r#"http://[A-Za-z0-9\.\-/:_]+"#).expect("valid regex");
    if let Some(file) = project.find_file("app/Http/Middleware/TrustProxies.php") {
        if file.content.contains("protected $proxies = '*'")
            || file.content.contains("protected $proxies = \"*\"")
            || file.content.contains("$proxies = '*';")
        {
            let line = find_line(&file.content, "$proxies").unwrap_or(1);
            findings.push(make_finding(
                RULES[4],
                Some(&file.relative_path),
                Some(line),
                "TrustProxies middleware trusts all proxies",
                "Wildcard trusted proxy configuration can make header spoofing easier unless the deployment environment tightly controls upstream proxies.",
                snippet_for_line(&file.content, line),
            ));
        }
    }

    for file in project.files_with_extension("php") {
        if !(file.relative_path.starts_with("config/") || file.relative_path.starts_with("routes/"))
        {
            continue;
        }
        for (idx, line) in file.content.lines().enumerate() {
            if http_re.is_match(line)
                && !line.contains("http://localhost")
                && !line.contains("http://127.0.0.1")
            {
                findings.push(make_finding(
                    RULES[3],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Hardcoded non-HTTPS URL",
                    "Configuration and route code should avoid hardcoded HTTP URLs in production paths.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    findings
}

fn check_csrf_exceptions(file: &crate::scanner::ProjectFile) -> Vec<crate::models::Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = file.content.lines().collect();
    let mut in_except = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("protected $except") {
            in_except = true;
            continue;
        }
        if !in_except {
            continue;
        }
        if trimmed.contains("];") {
            break;
        }
        if !(trimmed.contains('\'') || trimmed.contains('"')) {
            continue;
        }
        let has_inline_comment =
            trimmed.contains("//") || trimmed.contains('#') || trimmed.contains("/*");
        let prev_comment = idx
            .checked_sub(1)
            .and_then(|prev| lines.get(prev))
            .map(|prev| {
                let prev = prev.trim();
                prev.starts_with("//")
                    || prev.starts_with('#')
                    || prev.starts_with("/*")
                    || prev.starts_with('*')
            })
            .unwrap_or(false);
        if !has_inline_comment && !prev_comment {
            findings.push(make_finding(
                RULES[0],
                Some(&file.relative_path),
                Some(idx + 1),
                "CSRF exclusion without visible justification",
                "An entry in VerifyCsrfToken::$except does not have an obvious nearby comment explaining why the route is safe without CSRF protection.",
                Some(trimmed.to_string()),
            ));
        }
    }

    findings
}
