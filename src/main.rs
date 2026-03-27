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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;

use config::Config;
use models::{Category, RuleMeta, ScanContext, Severity};
use reporter::{ReportFormat, render_report};
use rules::{all_rule_metadata, run_rules};
use scanner::Project;

#[derive(Parser, Debug)]
#[command(name = "lsec", version, about = "Laravel Security Audit CLI \n© Afaan Bilal <https://afaan.dev>")]
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
            format,
            output,
            summary,
            quiet,
            ci,
            fail_on,
            config,
        } => run_scan(ScanArgs {
            path,
            only,
            skip,
            format: format.into(),
            output,
            summary,
            quiet,
            ci,
            fail_on: fail_on.map(Into::into),
            config,
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
    format: ReportFormat,
    output: Option<PathBuf>,
    summary: bool,
    quiet: bool,
    ci: bool,
    fail_on: Option<Severity>,
    config: Option<PathBuf>,
}

fn run_scan(args: ScanArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let root = fs::canonicalize(&args.path)?;
    let config = load_config(&root, args.config.as_deref())?;
    let only = parse_categories(args.only.as_deref())?;
    let mut skip = parse_categories(args.skip.as_deref())?;
    skip.extend(config.rule_skips());
    let fail_on = args.fail_on.or(config.fail_on()).unwrap_or(Severity::High);

    let project = Project::load(&root, &config)?;
    let context = ScanContext {
        root,
        config,
        only,
        skip,
        ci: args.ci,
    };

    let findings = run_rules(&project, &context);
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
