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

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use config::Config;
use models::{Category, Finding, RuleMeta, ScanContext, Severity};
use reporter::{ReportFormat, render_report};
use rules::{all_rule_metadata, run_rules};
use scanner::Project;

#[derive(Parser, Debug)]
#[command(name = "lsec", version, about = "Laravel Security Audit CLI\n© Afaan Bilal <https://afaan.dev>")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Scan {
        path: PathBuf,
        #[arg(long)]
        only: Option<String>,
        #[arg(long)]
        skip: Option<String>,
        #[arg(long = "only-rule")]
        only_rule: Option<String>,
        #[arg(long = "skip-rule")]
        skip_rule: Option<String>,
        #[arg(long, value_enum, default_value_t = FormatArg::Pretty)]
        format: FormatArg,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        summary: bool,
        #[arg(long)]
        quiet: bool,
        #[arg(long)]
        ci: bool,
        #[arg(long)]
        fail_on: Option<SeverityArg>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        write_baseline: bool,
    },
    Rules,
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
            eprintln!("lsec: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            path,
            only,
            skip,
            only_rule,
            skip_rule,
            format,
            output,
            summary,
            quiet,
            ci,
            fail_on,
            config,
            baseline,
            write_baseline,
        } => run_scan(ScanArgs {
            path,
            only,
            skip,
            only_rule,
            skip_rule,
            format: format.into(),
            output,
            summary,
            quiet,
            ci,
            fail_on: fail_on.map(Into::into),
            config,
            baseline,
            write_baseline,
        }),
        Commands::Rules => {
            print_rules(&all_rule_metadata());
            Ok(ExitCode::SUCCESS)
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
}

fn run_scan(args: ScanArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let root = fs::canonicalize(&args.path)?;
    let config = load_config(&root, args.config.as_deref())?;
    let only = parse_categories(args.only.as_deref())?;
    let mut skip = parse_categories(args.skip.as_deref())?;
    skip.extend(config.rule_skips());
    let only_rule_ids = parse_rule_ids(args.only_rule.as_deref());
    let mut skip_rule_ids = parse_rule_ids(args.skip_rule.as_deref());
    skip_rule_ids.extend(config.rule_id_skips());
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
        ci: args.ci,
    };

    let findings = run_rules(&project, &context);

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

fn resolve_baseline_path(root: &Path, explicit: Option<&Path>) -> Option<PathBuf> {
    explicit
        .map(PathBuf::from)
        .or_else(|| {
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

fn write_baseline_file(path: &Path, findings: &[Finding]) -> Result<(), Box<dyn std::error::Error>> {
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

    println!("{} {}", "Laravel Security Audit CLI".bold(), "\n© Afaan Bilal <https://afaan.dev>\n");
    println!("{}", "Laravel security checks grouped by category and default severity.".dimmed());
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
            "{} {}",
            category_icon(category),
            category_label(category).bold()
        );
        for rule in category_rules {
            let severity = paint_severity(rule.default_severity);
            println!(
                "  {:<width$}  {:<8}  {}",
                rule.id,
                severity,
                rule.title,
                width = id_width
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
