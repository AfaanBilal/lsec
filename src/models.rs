//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use std::path::PathBuf;

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn parse_soft(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Env,
    Auth,
    Injection,
    Http,
    Storage,
    Deps,
    Secrets,
    Logging,
}

impl Category {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "env" => Ok(Self::Env),
            "auth" => Ok(Self::Auth),
            "injection" => Ok(Self::Injection),
            "http" => Ok(Self::Http),
            "storage" => Ok(Self::Storage),
            "deps" => Ok(Self::Deps),
            "secrets" => Ok(Self::Secrets),
            "logging" => Ok(Self::Logging),
            other => Err(format!("unknown rule category: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Env => "env",
            Category::Auth => "auth",
            Category::Injection => "injection",
            Category::Http => "http",
            Category::Storage => "storage",
            Category::Deps => "deps",
            Category::Secrets => "secrets",
            Category::Logging => "logging",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: String,
    pub message: String,
    pub remediation: &'static str,
    pub confidence: f32,
    pub severity: Severity,
    pub category: Category,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

impl Finding {
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.rule_id,
            self.file.as_deref().unwrap_or("-"),
            self.line
                .map(|line| line.to_string())
                .as_deref()
                .unwrap_or("-"),
            self.title
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub default_severity: Severity,
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub root: PathBuf,
    pub config: Config,
    pub only: Vec<Category>,
    pub skip: Vec<Category>,
    pub only_rule_ids: Vec<String>,
    pub skip_rule_ids: Vec<String>,
    pub ci: bool,
}

impl ScanContext {
    pub fn category_enabled(&self, category: Category) -> bool {
        if self.skip.contains(&category) {
            return false;
        }
        self.only.is_empty() || self.only.contains(&category)
    }

    pub fn rule_enabled(&self, rule_id: &str, category: Category) -> bool {
        if !self.category_enabled(category) {
            return false;
        }
        if self.skip_rule_ids.iter().any(|id| id == rule_id) {
            return false;
        }
        self.only_rule_ids.is_empty() || self.only_rule_ids.iter().any(|id| id == rule_id)
    }
}
