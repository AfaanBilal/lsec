//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use std::collections::BTreeMap;

use serde::Serialize;

use crate::models::{Finding, ScanContext, Severity};

#[derive(Serialize)]
struct SarifReport {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<ResultItem>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: &'static str,
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    short_description: Message,
    help: Message,
    help_uri: &'static str,
    properties: Properties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultItem {
    rule_id: String,
    level: String,
    message: Message,
    locations: Vec<Location>,
    properties: Properties,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Properties {
    confidence: f32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
}

pub fn render(
    findings: &[Finding],
    _context: &ScanContext,
    summary_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let used_findings: &[Finding] = if summary_only { &[] } else { findings };
    let mut rules_by_id = BTreeMap::new();
    for finding in used_findings {
        rules_by_id.entry(finding.rule_id).or_insert_with(|| Rule {
            id: finding.rule_id.to_string(),
            name: finding.title.clone(),
            short_description: Message {
                text: finding.message.clone(),
            },
            help: Message {
                text: finding.remediation.to_string(),
            },
            help_uri: "https://github.com/AfaanBilal/lsec",
            properties: Properties {
                confidence: finding.confidence,
            },
        });
    }

    let report = SarifReport {
        version: "2.1.0",
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "lsec",
                    information_uri: "https://github.com/AfaanBilal/lsec",
                    rules: rules_by_id.into_values().collect(),
                },
            },
            results: used_findings
                .iter()
                .map(|finding| ResultItem {
                    rule_id: finding.rule_id.to_string(),
                    level: sarif_level(finding.severity).to_string(),
                    message: Message {
                        text: format!("{} Fix: {}", finding.message, finding.remediation),
                    },
                    locations: vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: finding.file.clone().unwrap_or_else(|| ".".to_string()),
                                uri_base_id: "%SRCROOT%",
                            },
                            region: Region {
                                start_line: finding.line.unwrap_or(1),
                            },
                        },
                    }],
                    properties: Properties {
                        confidence: finding.confidence,
                    },
                })
                .collect(),
        }],
    };

    Ok(serde_json::to_string_pretty(&report)?)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
