//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::{Value, json};

use crate::models::{Category, RuleMeta, ScanContext, Severity};
use crate::scanner::Project;

use super::make_finding;

const RULES: [RuleMeta; 6] = [
    RuleMeta {
        id: "deps.known-vuln",
        title: "Dependency with known vulnerability",
        category: Category::Deps,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "deps.outdated-laravel",
        title: "Severely outdated Laravel core",
        category: Category::Deps,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "deps.vuln-db-unreachable",
        title: "Vulnerability database unavailable",
        category: Category::Deps,
        default_severity: Severity::Info,
    },
    RuleMeta {
        id: "deps.abandoned-package",
        title: "Abandoned Composer package",
        category: Category::Deps,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "deps.old-php-constraint",
        title: "Outdated PHP version constraint",
        category: Category::Deps,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "deps.lockfile-missing",
        title: "composer.lock missing",
        category: Category::Deps,
        default_severity: Severity::Info,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Deps) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let composer_json = project.find_file("composer.json");
    let lock_file = project.find_file("composer.lock");

    if lock_file.is_none() {
        if let Some(file) = composer_json {
            findings.push(make_finding(
                RULES[5],
                Some(&file.relative_path),
                Some(1),
                "composer.lock not found",
                "Security and reproducibility checks are more reliable when the lockfile is committed alongside composer.json.",
                None,
            ));
        }
    }

    if let Some(file) = composer_json {
        if let Ok(json) = serde_json::from_str::<Value>(&file.content) {
            if let Some(version) = laravel_version_from_constraints(&json) {
                if is_old_laravel(&version) {
                    findings.push(make_finding(
                        RULES[1],
                        Some(&file.relative_path),
                        Some(1),
                        format!("Laravel constraint {} may be severely outdated", version),
                        "Older Laravel release lines can fall out of security support. Review the declared framework constraint against the current supported release policy.",
                        None,
                    ));
                }
            }
            if let Some(constraint) = php_constraint(&json) {
                if is_old_php_constraint(&constraint) {
                    findings.push(make_finding(
                        RULES[4],
                        Some(&file.relative_path),
                        Some(1),
                        format!("PHP constraint {} may allow unsupported runtimes", constraint),
                        "Composer allows an older PHP version range. Review whether the project still permits PHP versions that no longer receive security support.",
                        None,
                    ));
                }
            }
        }
    }

    let Some(lock_file) = lock_file else {
        return findings;
    };

    let Ok(json) = serde_json::from_str::<Value>(&lock_file.content) else {
        return findings;
    };

    let mut packages = collect_packages(&json, "packages");
    packages.extend(collect_packages(&json, "packages-dev"));

    for package in &packages {
        if package.name == "laravel/framework" && is_old_laravel(&package.version) {
            findings.push(make_finding(
                RULES[1],
                Some(&lock_file.relative_path),
                Some(1),
                format!("Laravel core version {} may be severely outdated", package.version),
                "Older Laravel release lines can fall out of security support. Review the framework version against the current supported release policy.",
                None,
            ));
        }
    }

    for abandoned in collect_abandoned_packages(&json) {
        findings.push(make_finding(
            RULES[3],
            Some(&lock_file.relative_path),
            Some(1),
            format!("Abandoned package detected: {}", abandoned),
            "Composer reports this package as abandoned. Review whether it should be replaced with an actively maintained alternative.",
            None,
        ));
    }

    match query_osv(&packages) {
        Ok(vulns) => {
            for vuln in vulns {
                findings.push(make_finding(
                    RULES[0],
                    Some(&lock_file.relative_path),
                    Some(1),
                    vuln.title,
                    vuln.message,
                    None,
                ));
            }
        }
        Err(_) if !context.ci => {
            findings.push(make_finding(
                RULES[2],
                Some(&lock_file.relative_path),
                Some(1),
                "Dependency vulnerability lookup skipped",
                "OSV lookup could not be completed. Dependency CVE detection is best-effort and may require network access.",
                None,
            ));
        }
        Err(_) => {}
    }

    findings
}

#[derive(Clone)]
struct PackageRef {
    name: String,
    version: String,
}

struct VulnMatch {
    title: String,
    message: String,
}

fn collect_packages(root: &Value, field: &str) -> Vec<PackageRef> {
    root.get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pkg| {
            Some(PackageRef {
                name: pkg.get("name")?.as_str()?.to_string(),
                version: pkg.get("version")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn collect_abandoned_packages(root: &Value) -> Vec<String> {
    ["packages", "packages-dev"]
        .into_iter()
        .flat_map(|field| {
            root.get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|pkg| {
                    let abandoned = pkg.get("abandoned")?;
                    match abandoned {
                        Value::Bool(true) => Some(pkg.get("name")?.as_str()?.to_string()),
                        Value::String(replacement) => Some(format!(
                            "{} (suggested replacement: {})",
                            pkg.get("name")?.as_str()?,
                            replacement
                        )),
                        _ => None,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn laravel_version_from_constraints(root: &Value) -> Option<String> {
    root.get("require")
        .and_then(Value::as_object)
        .and_then(|reqs| reqs.get("laravel/framework"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn php_constraint(root: &Value) -> Option<String> {
    root.get("require")
        .and_then(Value::as_object)
        .and_then(|reqs| reqs.get("php"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn is_old_laravel(version: &str) -> bool {
    let digits: String = version
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    let major = digits.parse::<u64>().unwrap_or(0);
    major > 0 && major < 10
}

fn is_old_php_constraint(constraint: &str) -> bool {
    ["5.", "7.0", "7.1", "7.2", "7.3", "7.4", "^7", "~7"]
        .iter()
        .any(|needle| constraint.contains(needle))
}

fn query_osv(packages: &[PackageRef]) -> Result<Vec<VulnMatch>, Box<dyn std::error::Error>> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let mut findings = Vec::new();

    for chunk in packages.chunks(100) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|pkg| {
                json!({
                    "package": { "name": pkg.name, "ecosystem": "Packagist" },
                    "version": pkg.version
                })
            })
            .collect();
        let response: Value = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&json!({ "queries": queries }))
            .send()?
            .error_for_status()?
            .json()?;

        let results = response
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (idx, result) in results.iter().enumerate() {
            let package = &chunk[idx];
            let vulns = result
                .get("vulns")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for vuln in vulns {
                let id = vuln
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown advisory");
                let summary = vuln
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("Known vulnerability found");
                findings.push(VulnMatch {
                    title: format!("Package vulnerability reported: {} ({})", package.name, id),
                    message: format!(
                        "{} {} is affected at version {}. Review composer.lock and upstream advisory details.",
                        summary, package.name, package.version
                    ),
                });
            }
        }
    }

    Ok(findings)
}
