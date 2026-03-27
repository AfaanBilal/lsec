//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
mod config;
mod models;
mod reporter;
mod rules;
mod scanner;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use config::Config;
use models::{Category, Finding, RuleMeta, ScanContext, Severity};
use reporter::{ReportFormat, render_report};
use rules::{all_rule_metadata, confidence_for_rule, remediation_for_rule, run_rules};
use scanner::Project;

#[derive(Parser, Debug)]
#[command(
    name = "lsec",
    version,
    about = "Laravel Security Audit CLI\n© Afaan Bilal <https://afaan.dev>",
    long_about = "Laravel Security Audit CLI\n© Afaan Bilal <https://afaan.dev>\n\nStatic security checks for Laravel repositories, with pretty terminal output, JSON, SARIF, filters, and CI-friendly gating."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Scan a Laravel project for security findings")]
    Scan(ScanCommand),
    #[command(about = "List supported rules with default severity and remediation guidance")]
    Rules,
    #[command(subcommand, about = "Manage baseline suppression files")]
    Baseline(BaselineCommands),
}

#[derive(Args, Debug)]
struct ScanCommand {
    #[arg(help = "Path to the Laravel project root to scan")]
    path: PathBuf,
    #[arg(
        long,
        value_name = "CATEGORIES",
        help = "Comma-separated category allowlist, for example env,secrets,deps"
    )]
    only: Option<String>,
    #[arg(
        long,
        value_name = "CATEGORIES",
        help = "Comma-separated category denylist, for example logging,http"
    )]
    skip: Option<String>,
    #[arg(
        long = "only-rule",
        value_name = "RULE_IDS",
        help = "Comma-separated exact rule ids to run, for example http.ssrf-user-url,secrets.private-key"
    )]
    only_rule: Option<String>,
    #[arg(
        long = "skip-rule",
        value_name = "RULE_IDS",
        help = "Comma-separated exact rule ids to suppress"
    )]
    skip_rule: Option<String>,
    #[arg(long, value_enum, default_value_t = FormatArg::Pretty, help = "Report format to render")]
    format: FormatArg,
    #[arg(
        long,
        value_name = "FILE",
        help = "Write the rendered report to a file instead of stdout"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        help = "Render only the opening summary tables without per-finding details"
    )]
    summary: bool,
    #[arg(long, help = "Suppress report output and rely on the exit code only")]
    quiet: bool,
    #[arg(
        long,
        help = "Enable CI mode so findings can fail the command based on severity"
    )]
    ci: bool,
    #[arg(long, help = "Lowest severity that should fail CI mode")]
    fail_on: Option<SeverityArg>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to an lsec TOML configuration file"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Load suppressions from a baseline JSON file"
    )]
    baseline: Option<PathBuf>,
    #[arg(
        long,
        help = "Write the current findings to the baseline file after scanning"
    )]
    write_baseline: bool,
    #[arg(
        long,
        value_name = "FLOAT",
        help = "Ignore findings below this confidence score (0.0 to 1.0)"
    )]
    min_confidence: Option<f32>,
}

#[derive(Subcommand, Debug)]
enum BaselineCommands {
    #[command(about = "Create or overwrite a baseline file from the current scan")]
    Write(BaselineCommand),
    #[command(about = "Remove stale suppressions that no longer match current findings")]
    Prune(BaselineCommand),
}

#[derive(Args, Debug)]
struct BaselineCommand {
    #[arg(help = "Path to the Laravel project root to scan")]
    path: PathBuf,
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to an lsec TOML configuration file"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to the baseline JSON file (defaults to <path>/lsec-baseline.json)"
    )]
    baseline: Option<PathBuf>,
    #[arg(
        long,
        value_name = "CATEGORIES",
        help = "Comma-separated category allowlist applied before writing or pruning"
    )]
    only: Option<String>,
    #[arg(
        long,
        value_name = "CATEGORIES",
        help = "Comma-separated category denylist applied before writing or pruning"
    )]
    skip: Option<String>,
    #[arg(
        long = "only-rule",
        value_name = "RULE_IDS",
        help = "Comma-separated exact rule ids to include"
    )]
    only_rule: Option<String>,
    #[arg(
        long = "skip-rule",
        value_name = "RULE_IDS",
        help = "Comma-separated exact rule ids to suppress"
    )]
    skip_rule: Option<String>,
    #[arg(
        long,
        value_name = "FLOAT",
        help = "Ignore findings below this confidence score (0.0 to 1.0)"
    )]
    min_confidence: Option<f32>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FormatArg {
    Pretty,
    Json,
    Sarif,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineFile {
    version: u32,
    suppressions: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineEntry {
    fingerprint: String,
    rule_id: String,
    title: String,
    file: Option<String>,
    line: Option<usize>,
}

impl From<FormatArg> for ReportFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Pretty => ReportFormat::Pretty,
            FormatArg::Json => ReportFormat::Json,
            FormatArg::Sarif => ReportFormat::Sarif,
        }
    }
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Laravel Security Audit CLI\n© Afaan Bilal <https://afaan.dev>");
            eprintln!("lsec: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(command) => run_scan(ScanArgs {
            path: command.path,
            only: command.only,
            skip: command.skip,
            only_rule: command.only_rule,
            skip_rule: command.skip_rule,
            format: command.format.into(),
            output: command.output,
            summary: command.summary,
            quiet: command.quiet,
            ci: command.ci,
            fail_on: command.fail_on.map(Into::into),
            config: command.config,
            baseline: command.baseline,
            write_baseline: command.write_baseline,
            min_confidence: command.min_confidence,
        }),
        Commands::Rules => {
            print_rules(&all_rule_metadata());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Baseline(BaselineCommands::Write(command)) => {
            run_baseline(command, BaselineMode::Write)
        }
        Commands::Baseline(BaselineCommands::Prune(command)) => {
            run_baseline(command, BaselineMode::Prune)
        }
    }
}

struct ScanArgs {
    path: PathBuf,
    only: Option<String>,
    skip: Option<String>,
    only_rule: Option<String>,
    skip_rule: Option<String>,
    format: ReportFormat,
    output: Option<PathBuf>,
    summary: bool,
    quiet: bool,
    ci: bool,
    fail_on: Option<Severity>,
    config: Option<PathBuf>,
    baseline: Option<PathBuf>,
    write_baseline: bool,
    min_confidence: Option<f32>,
}

#[derive(Copy, Clone)]
enum BaselineMode {
    Write,
    Prune,
}

fn run_scan(args: ScanArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let root = fs::canonicalize(&args.path)?;
    ensure_laravel_root(&root)?;
    let config = load_config(&root, args.config.as_deref())?;
    let only = parse_categories(args.only.as_deref())?;
    let mut skip = parse_categories(args.skip.as_deref())?;
    skip.extend(config.rule_skips());
    let only_rule_ids = parse_rule_ids(args.only_rule.as_deref());
    let mut skip_rule_ids = parse_rule_ids(args.skip_rule.as_deref());
    skip_rule_ids.extend(config.rule_id_skips());
    let min_confidence = resolve_min_confidence(args.min_confidence, &config)?;
    let fail_on = args.fail_on.or(config.fail_on()).unwrap_or(Severity::High);
    let baseline_path = resolve_baseline_path(&root, args.baseline.as_deref());
    let existing_baseline = load_baseline(baseline_path.as_deref())?;

    let project = Project::load(&root, &config)?;
    let context = ScanContext {
        root: root.clone(),
        config,
        only,
        skip,
        only_rule_ids,
        skip_rule_ids,
        min_confidence,
        ci: args.ci,
    };

    let findings = filtered_findings(&project, &context);

    if args.write_baseline {
        let write_path = baseline_path.unwrap_or_else(|| root.join("lsec-baseline.json"));
        write_baseline_file(&write_path, &findings)?;
    }

    let findings = apply_baseline(findings, existing_baseline.as_ref());
    let report = render_report(args.format, &findings, &context, args.summary)?;

    if let Some(output_path) = args.output {
        fs::write(output_path, report)?;
    } else if !args.quiet {
        println!("{report}");
    }

    let should_fail = args.ci && findings.iter().any(|f| f.severity <= fail_on);
    Ok(if should_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn run_baseline(
    command: BaselineCommand,
    mode: BaselineMode,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let root = fs::canonicalize(&command.path)?;
    ensure_laravel_root(&root)?;
    let config = load_config(&root, command.config.as_deref())?;
    let only = parse_categories(command.only.as_deref())?;
    let mut skip = parse_categories(command.skip.as_deref())?;
    skip.extend(config.rule_skips());
    let only_rule_ids = parse_rule_ids(command.only_rule.as_deref());
    let mut skip_rule_ids = parse_rule_ids(command.skip_rule.as_deref());
    skip_rule_ids.extend(config.rule_id_skips());
    let min_confidence = resolve_min_confidence(command.min_confidence, &config)?;
    let baseline_path = command
        .baseline
        .clone()
        .unwrap_or_else(|| root.join("lsec-baseline.json"));

    let project = Project::load(&root, &config)?;
    let context = ScanContext {
        root: root.clone(),
        config,
        only,
        skip,
        only_rule_ids,
        skip_rule_ids,
        min_confidence,
        ci: false,
    };
    let findings = filtered_findings(&project, &context);

    match mode {
        BaselineMode::Write => {
            write_baseline_file(&baseline_path, &findings)?;
            println!(
                "{} {} ({})",
                "Baseline written:".bold(),
                baseline_path.display(),
                findings.len()
            );
        }
        BaselineMode::Prune => {
            let existing = load_baseline(Some(&baseline_path))?.unwrap_or(BaselineFile {
                version: 1,
                suppressions: Vec::new(),
            });
            let active: HashSet<String> = findings.iter().map(Finding::fingerprint).collect();
            let before = existing.suppressions.len();
            let pruned = BaselineFile {
                version: existing.version,
                suppressions: existing
                    .suppressions
                    .into_iter()
                    .filter(|entry| active.contains(&entry.fingerprint))
                    .collect(),
            };
            fs::write(&baseline_path, serde_json::to_string_pretty(&pruned)?)?;
            println!(
                "{} {} (removed {}, kept {})",
                "Baseline pruned:".bold(),
                baseline_path.display(),
                before.saturating_sub(pruned.suppressions.len()),
                pruned.suppressions.len()
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn filtered_findings(project: &Project, context: &ScanContext) -> Vec<Finding> {
    run_rules(project, context)
        .into_iter()
        .filter(|finding| context.confidence_enabled(finding.rule_id, finding.confidence))
        .collect()
}

fn ensure_laravel_root(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let artisan = root.join("artisan");
    let bootstrap = root.join("bootstrap").join("app.php");
    let config_app = root.join("config").join("app.php");

    if artisan.is_file() && (bootstrap.is_file() || config_app.is_file()) {
        Ok(())
    } else {
        Err(format!(
            "{} does not look like a Laravel application root",
            root.display()
        )
        .into())
    }
}

fn load_config(root: &Path, explicit: Option<&Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let path = explicit
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("lsec.toml"));
    if path.exists() {
        Ok(Config::from_path(&path)?)
    } else {
        Ok(Config::default())
    }
}

fn parse_categories(value: Option<&str>) -> Result<Vec<Category>, Box<dyn std::error::Error>> {
    value
        .map(|raw| {
            raw.split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| Category::parse(item.trim()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.into())
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn parse_rule_ids(value: Option<&str>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_min_confidence(
    cli_value: Option<f32>,
    config: &Config,
) -> Result<Option<f32>, Box<dyn std::error::Error>> {
    let value = cli_value.or(config.min_confidence());
    if let Some(value) = value {
        if !(0.0..=1.0).contains(&value) {
            return Err(
                format!("confidence thresholds must be between 0.0 and 1.0, got {value}").into(),
            );
        }
    }
    Ok(value)
}

fn resolve_baseline_path(root: &Path, explicit: Option<&Path>) -> Option<PathBuf> {
    explicit.map(PathBuf::from).or_else(|| {
        let default = root.join("lsec-baseline.json");
        default.exists().then_some(default)
    })
}

fn load_baseline(path: Option<&Path>) -> Result<Option<BaselineFile>, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&raw)?))
}

fn apply_baseline(findings: Vec<Finding>, baseline: Option<&BaselineFile>) -> Vec<Finding> {
    let Some(baseline) = baseline else {
        return findings;
    };
    let suppressed: HashSet<String> = baseline
        .suppressions
        .iter()
        .map(|entry| entry.fingerprint.clone())
        .collect();
    findings
        .into_iter()
        .filter(|finding| !suppressed.contains(&finding.fingerprint()))
        .collect()
}

fn write_baseline_file(
    path: &Path,
    findings: &[Finding],
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline = BaselineFile {
        version: 1,
        suppressions: findings
            .iter()
            .map(|finding| BaselineEntry {
                fingerprint: finding.fingerprint(),
                rule_id: finding.rule_id.to_string(),
                title: finding.title.clone(),
                file: finding.file.clone(),
                line: finding.line,
            })
            .collect(),
    };
    fs::write(path, serde_json::to_string_pretty(&baseline)?)?;
    Ok(())
}

fn print_rules(rules: &[RuleMeta]) {
    let categories = [
        Category::Env,
        Category::Auth,
        Category::Injection,
        Category::Http,
        Category::Storage,
        Category::Deps,
        Category::Secrets,
        Category::Logging,
    ];
    let id_width = rules.iter().map(|rule| rule.id.len()).max().unwrap_or(0);

    println!(
        "{}
{}",
        "Laravel Security Audit CLI".bold(),
        "© Afaan Bilal <https://afaan.dev>"
    );
    println!(
        "{}",
        "Security rule catalog by category, default severity, confidence, and remediation guidance."
            .dimmed()
    );
    println!("{}", format!("Total rules: {}", rules.len()).dimmed());
    println!();

    for category in categories {
        let category_rules: Vec<&RuleMeta> = rules
            .iter()
            .filter(|rule| rule.category == category)
            .collect();
        if category_rules.is_empty() {
            continue;
        }

        println!(
            "{} {} ({})",
            category_icon(category),
            category_label(category).bold(),
            category_rules.len()
        );
        println!("{}", "-".repeat(88).dimmed());
        for rule in category_rules {
            let severity = paint_severity(rule.default_severity);
            println!(
                "  {:<width$}  {:<8}  {:>3}%  {}",
                rule.id,
                severity,
                (confidence_for_rule(rule.id) * 100.0).round() as u32,
                rule.title,
                width = id_width
            );
            println!(
                "  {} {}",
                "Fix:".bold(),
                remediation_for_rule(rule.id).dimmed()
            );
        }
        println!();
    }
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Env => "Environment",
        Category::Auth => "Authentication",
        Category::Injection => "Injection",
        Category::Http => "HTTP",
        Category::Storage => "Storage",
        Category::Deps => "Dependencies",
        Category::Secrets => "Secrets",
        Category::Logging => "Logging",
    }
}

fn category_icon(category: Category) -> &'static str {
    match category {
        Category::Env => "ENV",
        Category::Auth => "AUTH",
        Category::Injection => "INJ",
        Category::Http => "HTTP",
        Category::Storage => "FS",
        Category::Deps => "DEPS",
        Category::Secrets => "SEC",
        Category::Logging => "LOG",
    }
}

fn paint_severity(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => severity.as_str().red().bold(),
        Severity::High => severity.as_str().red(),
        Severity::Medium => severity.as_str().yellow(),
        Severity::Low => severity.as_str().cyan(),
        Severity::Info => severity.as_str().normal(),
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_laravel_root;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("lsec-{name}-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn accepts_laravel_like_root() {
        let root = temp_dir("laravel-root");
        fs::write(root.join("artisan"), "#!/usr/bin/env php").unwrap();
        fs::create_dir_all(root.join("bootstrap")).unwrap();
        fs::write(root.join("bootstrap").join("app.php"), "<?php").unwrap();

        let result = ensure_laravel_root(&root);

        fs::remove_dir_all(&root).unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_non_laravel_root() {
        let root = temp_dir("not-laravel");
        fs::write(root.join("README.md"), "hello").unwrap();

        let err = ensure_laravel_root(&root).unwrap_err().to_string();

        fs::remove_dir_all(&root).unwrap();
        assert!(err.contains("does not look like a Laravel application root"));
    }
}
