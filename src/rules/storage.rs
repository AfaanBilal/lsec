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

const RULES: [RuleMeta; 3] = [
    RuleMeta {
        id: "storage.user-controlled-path",
        title: "User-controlled file path access",
        category: Category::Storage,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "storage.upload-validation",
        title: "Upload handling without visible validation",
        category: Category::Storage,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "storage.public-disk",
        title: "Public storage exposure",
        category: Category::Storage,
        default_severity: Severity::Low,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Storage) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let path_re = Regex::new(r"(Storage::get|file_get_contents)\s*\([^)]*(Request::(input|get)|\$request->(input|get|file)|\$\w+Path)").expect("valid regex");

    for file in project.files_with_extension("php") {
        let has_upload_handling = file.content.contains("->file(")
            || file.content.contains("->store(")
            || file.content.contains("->storeAs(")
            || file.content.contains("move(");
        let has_validation = file.content.contains("validate(")
            || file.content.contains("Validator::make(")
            || file.content.contains("'mimes:")
            || file.content.contains("'max:")
            || file.content.contains("'image'");

        for (idx, line) in file.content.lines().enumerate() {
            if path_re.is_match(line) {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "File access path appears influenced by user input",
                    "Normalize and constrain file paths before using them with Storage::get or file_get_contents to avoid path traversal.",
                    Some(line.trim().to_string()),
                ));
            }
        }

        if has_upload_handling && !has_validation {
            findings.push(make_finding(
                RULES[1],
                Some(&file.relative_path),
                Some(1),
                "Upload handling without visible validation rules",
                "Files appear to be uploaded or moved in this file, but no obvious size/type validation was found nearby.",
                None,
            ));
        }
    }

    if let Some(file) = project.find_file("config/filesystems.php") {
        if file.content.contains("'public' => [")
            && file.content.contains("'visibility' => 'public'")
        {
            findings.push(make_finding(
                RULES[2],
                Some(&file.relative_path),
                Some(1),
                "Public filesystem disk configured",
                "Public disks are normal in Laravel, but review whether uploaded data in storage/app/public is intended to be web-accessible.",
                None,
            ));
        }
    }

    for file in project.files_under("storage/app/public/") {
        findings.push(make_finding(
            RULES[2],
            Some(&file.relative_path),
            Some(1),
            "File present under public storage path",
            "Files under storage/app/public can become web-accessible when the public storage symlink is enabled. Confirm that this exposure is intentional.",
            None,
        ));
    }

    findings
}
