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
        id: "injection.raw-sql-interpolation",
        title: "Raw SQL with interpolation",
        category: Category::Injection,
        default_severity: Severity::Critical,
    },
    RuleMeta {
        id: "injection.mass-assignment",
        title: "Mass assignment guard missing or disabled",
        category: Category::Injection,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "injection.unvalidated-input-query",
        title: "Request input passed directly into query",
        category: Category::Injection,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "injection.eval",
        title: "eval() usage",
        category: Category::Injection,
        default_severity: Severity::Critical,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Injection) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let raw_sql_re =
        Regex::new(r#"DB::(statement|select|unprepared)\s*\([^)]*(\$\w+|\.\s*\$|"\s*\.)"#)
            .expect("valid regex");
    let query_input_re =
        Regex::new(r"(where|orWhere|orderBy|groupBy)\s*\([^)]*(Request::(input|get)|\$request->(input|get|query))")
            .expect("valid regex");
    let eval_re = Regex::new(r"\beval\s*\(").expect("valid regex");

    for file in project.files_with_extension("php") {
        let has_fillable = file.content.contains("$fillable");
        let has_guarded = file.content.contains("$guarded");
        if file.relative_path.starts_with("app/Models/") && !has_fillable && !has_guarded {
            findings.push(make_finding(
                RULES[1],
                Some(&file.relative_path),
                Some(1),
                "Model lacks $fillable/$guarded declarations",
                "Without explicit mass-assignment policy, model attributes may be easier to expose accidentally.",
                None,
            ));
        }

        for (idx, line) in file.content.lines().enumerate() {
            if raw_sql_re.is_match(line) {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Raw SQL call appears to interpolate input",
                    "Raw DB statements should use bound parameters instead of interpolated variables or concatenated strings.",
                    Some(line.trim().to_string()),
                ));
            }
            if line.contains("$guarded = []") {
                findings.push(make_finding(
                    RULES[1],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Model disables mass-assignment protection",
                    "Using $guarded = [] allows all attributes to be mass assigned unless guarded elsewhere.",
                    Some(line.trim().to_string()),
                ));
            }
            if query_input_re.is_match(line) {
                findings.push(make_finding(
                    RULES[2],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Request input used directly in query builder",
                    "Validate and normalize request values before injecting them into query clauses.",
                    Some(line.trim().to_string()),
                ));
            }
            if eval_re.is_match(line) {
                findings.push(make_finding(
                    RULES[3],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "eval() detected",
                    "Dynamic code execution is a high-risk sink and should be removed or heavily constrained.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    findings
}
