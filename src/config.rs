//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::models::{Category, Severity};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_exclude_paths")]
    pub exclude_paths: Vec<String>,
    pub fail_on: Option<String>,
    pub min_confidence: Option<f32>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            exclude_paths: default_exclude_paths(),
            fail_on: None,
            min_confidence: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub skip: Vec<String>,
    #[serde(default)]
    pub skip_ids: Vec<String>,
    #[serde(default)]
    pub custom_secrets_patterns: Vec<String>,
    #[serde(default)]
    pub min_confidence_overrides: HashMap<String, f32>,
}

fn default_exclude_paths() -> Vec<String> {
    vec![
        "vendor/".to_string(),
        "tests/".to_string(),
        "node_modules/".to_string(),
        ".git/".to_string(),
    ]
}

impl Config {
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn fail_on(&self) -> Option<Severity> {
        self.scan.fail_on.as_deref().and_then(Severity::parse_soft)
    }

    pub fn min_confidence(&self) -> Option<f32> {
        self.scan.min_confidence
    }

    pub fn rule_skips(&self) -> Vec<Category> {
        self.rules
            .skip
            .iter()
            .filter_map(|item| Category::parse(item).ok())
            .collect()
    }

    pub fn rule_id_skips(&self) -> Vec<String> {
        self.rules
            .skip_ids
            .iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    }

    pub fn rule_min_confidence(&self, rule_id: &str) -> Option<f32> {
        self.rules.min_confidence_overrides.get(rule_id).copied()
    }
}
