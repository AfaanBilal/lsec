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

use super::make_finding;

const RULES: [RuleMeta; 4] = [
    RuleMeta {
        id: "secrets.inline-secret",
        title: "Hardcoded secret-like value",
        category: Category::Secrets,
        default_severity: Severity::Critical,
    },
    RuleMeta {
        id: "secrets.private-key",
        title: "Private key or certificate committed",
        category: Category::Secrets,
        default_severity: Severity::Critical,
    },
    RuleMeta {
        id: "secrets.embedded-credentials-url",
        title: "URL with embedded credentials",
        category: Category::Secrets,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "secrets.cloud-access-key",
        title: "Cloud access key-like literal",
        category: Category::Secrets,
        default_severity: Severity::Critical,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Secrets) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let builtins = [
        r#"(?i)(api[_-]?key|secret|token|password)\s*['\"]?\s*(=>|=)\s*['\"][A-Za-z0-9_-]{16,}['\"]"#,
        r"(?i)sk_live_[A-Za-z0-9]{16,}",
        r"(?i)ghp_[A-Za-z0-9]{20,}",
    ];
    let private_key_re = Regex::new(r"(?m)^-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----$")
        .expect("valid regex");
    let embedded_creds_url_re =
        Regex::new(r#"https?://[^\s/@:]+:[^\s/@]+@[^\s'"]+"#).expect("valid regex");
    let cloud_key_re = Regex::new(r#"\b(AKIA|ASIA)[A-Z0-9]{16}\b"#).expect("valid regex");
    let mut patterns = builtins
        .iter()
        .map(|pattern| Regex::new(pattern).expect("valid regex"))
        .collect::<Vec<_>>();
    for pattern in &context.config.rules.custom_secrets_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            patterns.push(regex);
        }
    }

    for file in &project.files {
        let is_key_like = file.relative_path.ends_with(".pem")
            || file.relative_path.ends_with(".key")
            || file.relative_path.ends_with(".crt");
        if is_key_like || private_key_re.is_match(&file.content) {
            findings.push(make_finding(
                RULES[1],
                Some(&file.relative_path),
                Some(1),
                "Private key material present in repository",
                "Private keys and certificates should not be committed to application source trees unless explicitly intended and encrypted.",
                None,
            ));
        }

        if !file.relative_path.ends_with(".php") && !file.relative_path.ends_with(".env") {
            continue;
        }

        for (idx, line) in file.content.lines().enumerate() {
            if patterns.iter().any(|regex| regex.is_match(line)) {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Secret-like literal detected",
                    "This line matches a secret/token pattern. Replace hardcoded credentials with environment-backed secrets management.",
                    Some(line.trim().to_string()),
                ));
            }
            if embedded_creds_url_re.is_match(line) {
                findings.push(make_finding(
                    RULES[2],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "URL with embedded credentials detected",
                    "Application URLs should not embed usernames or passwords. Move credentials to environment-backed configuration or a secret manager.",
                    Some(line.trim().to_string()),
                ));
            }
            if cloud_key_re.is_match(line) {
                findings.push(make_finding(
                    RULES[3],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Cloud access key-like literal detected",
                    "This line looks like a cloud access key identifier. Verify that no active credential material has been committed.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    findings
}
