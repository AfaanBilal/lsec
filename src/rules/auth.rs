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

use super::{find_line, make_finding, snippet_for_line};

const RULES: [RuleMeta; 8] = [
    RuleMeta {
        id: "auth.missing-route-auth",
        title: "Sensitive routes may be missing auth middleware",
        category: Category::Auth,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "auth.missing-route-authorization",
        title: "Sensitive routes may be missing authorization checks",
        category: Category::Auth,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "auth.missing-policy",
        title: "Models present without visible Gate/Policy definitions",
        category: Category::Auth,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "auth.weak-password-hash",
        title: "Weak password hashing usage",
        category: Category::Auth,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "auth.remember-token-no-expiry",
        title: "Remember-me token usage with no visible expiry control",
        category: Category::Auth,
        default_severity: Severity::Low,
    },
    RuleMeta {
        id: "auth.password-hash-missing",
        title: "No modern password hashing usage detected",
        category: Category::Auth,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "auth.impersonation-feature",
        title: "User impersonation feature detected",
        category: Category::Auth,
        default_severity: Severity::Medium,
    },
    RuleMeta {
        id: "auth.user-controlled-role-assignment",
        title: "User-controlled role or permission assignment",
        category: Category::Auth,
        default_severity: Severity::High,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Auth) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let sensitive_route_re =
        Regex::new(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(")
            .expect("valid regex");
    let sensitive_hint_re = Regex::new(
        r"(admin|account|billing|profile|settings|users|orders|roles|permissions|telescope|horizon)",
    )
    .expect("valid regex");
    let weak_hash_re = Regex::new(r"\b(md5|sha1)\s*\(").expect("valid regex");
    let impersonation_re =
        Regex::new(r"(?i)(impersonat(e|ion)|loginAs\s*\(|becomeUser\s*\()").expect("valid regex");
    let role_assignment_re = Regex::new(
        r"(assignRole|syncRoles|givePermissionTo|syncPermissions)\s*\([^)]*(Request::(input|get)|\$request->(input|get|all|validated|query))",
    )
    .expect("valid regex");

    for file in project.files_under("routes/") {
        if !file.relative_path.ends_with(".php") {
            continue;
        }

        let mut active_groups: Vec<GroupContext> = Vec::new();
        let mut brace_depth = 0usize;
        for (idx, line) in file.content.lines().enumerate() {
            while matches!(active_groups.last(), Some(group) if brace_depth < group.start_depth) {
                active_groups.pop();
            }

            let normalized = line.to_ascii_lowercase();
            if is_group_start(&normalized) {
                active_groups.push(GroupContext {
                    start_depth: brace_depth + count_open_braces(line),
                    has_auth_middleware: has_auth_middleware(&normalized),
                    has_authorization: has_authorization_hint(&normalized),
                });
            }

            let inherited_auth = active_groups.iter().any(|group| group.has_auth_middleware);
            let inherited_authorization = active_groups.iter().any(|group| group.has_authorization);
            let sensitive_route =
                sensitive_route_re.is_match(line) && sensitive_hint_re.is_match(&normalized);
            let route_has_auth = has_auth_middleware(&normalized) || inherited_auth;
            let route_has_authorization =
                has_authorization_hint(&normalized) || inherited_authorization;

            if sensitive_route && !route_has_auth {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Sensitive-looking route without explicit auth middleware",
                    "This route looks sensitive based on its URI/name, but no auth middleware was found on the route line or any active enclosing route group.",
                    Some(line.trim().to_string()),
                ));
            } else if sensitive_route && route_has_auth && !route_has_authorization {
                findings.push(make_finding(
                    RULES[1],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Sensitive-looking route lacks an obvious authorization gate",
                    "Authentication was found, but no nearby policy, gate, permission, or role-based authorization hint was detected for this sensitive route.",
                    Some(line.trim().to_string()),
                ));
            }

            brace_depth += count_open_braces(line);
            brace_depth = brace_depth.saturating_sub(count_close_braces(line));
            while matches!(active_groups.last(), Some(group) if brace_depth < group.start_depth) {
                active_groups.pop();
            }
        }
    }

    let model_files = project.files_under("app/Models/");
    let has_policy_dir = !project.files_under("app/Policies/").is_empty();
    let has_gate_defs = project.files.iter().any(|file| {
        file.relative_path.ends_with(".php")
            && (file.content.contains("Gate::define(") || file.content.contains("Gate::policy("))
    });
    if !model_files.is_empty() && !has_policy_dir && !has_gate_defs {
        findings.push(make_finding(
            RULES[2],
            None,
            None,
            "Models found without visible authorization rules",
            "Eloquent models exist but no Gate::define, Gate::policy, or app/Policies directory was found. Authorization may be missing or implemented outside standard Laravel locations.",
            None,
        ));
    }

    for file in project.files_with_extension("php") {
        for (idx, line) in file.content.lines().enumerate() {
            if weak_hash_re.is_match(line) {
                findings.push(make_finding(
                    RULES[3],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Weak password hashing primitive detected",
                    "md5/sha1 are not appropriate for password hashing. Use Laravel Hash::make with bcrypt or argon2.",
                    Some(line.trim().to_string()),
                ));
            }
            if role_assignment_re.is_match(line) {
                findings.push(make_finding(
                    RULES[7],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Role or permission assignment appears request-controlled",
                    "Assigning roles or permissions directly from request input can allow privilege escalation unless the input is tightly authorized and validated.",
                    Some(line.trim().to_string()),
                ));
            }
            if impersonation_re.is_match(line) {
                findings.push(make_finding(
                    RULES[6],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Impersonation capability detected",
                    "User impersonation features should be tightly gated, audited, and disabled outside trusted administrator workflows.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    let password_handling_present = project.files.iter().any(|file| {
        file.relative_path.ends_with(".php")
            && (file.content.contains("password") || file.content.contains("Auth::attempt("))
    });
    let modern_hash_present = project.files.iter().any(|file| {
        file.relative_path.ends_with(".php")
            && (file.content.contains("Hash::make(")
                || file.content.contains("bcrypt(")
                || file.content.contains("PASSWORD_BCRYPT")
                || file.content.contains("PASSWORD_ARGON2")
                || file.content.contains("PASSWORD_ARGON2ID"))
    }) || project.files.iter().any(|file| {
        file.relative_path == "config/hashing.php"
            && (file.content.contains("'driver' => 'bcrypt'")
                || file.content.contains("'driver' => 'argon'")
                || file.content.contains("'driver' => 'argon2id'"))
    });
    if password_handling_present && !modern_hash_present {
        findings.push(make_finding(
            RULES[5],
            None,
            None,
            "Password handling detected without modern hashing call sites",
            "The codebase references password handling, but no bcrypt/argon2/Hash::make usage was found. Verify that stored passwords are hashed with Laravel's supported drivers.",
            None,
        ));
    }

    let has_remember_token = project
        .files
        .iter()
        .any(|file| file.content.contains("remember_token"));
    if has_remember_token {
        let has_expiry = project
            .files
            .iter()
            .any(|file| file.content.contains("remember") && file.content.contains("expire"));
        if !has_expiry {
            let file = model_files
                .first()
                .copied()
                .or_else(|| project.files_with_extension("php").first().copied());
            if let Some(file) = file {
                let line = find_line(&file.content, "remember_token").or(Some(1));
                findings.push(make_finding(
                    RULES[4],
                    Some(&file.relative_path),
                    line,
                    "Remember-me tokens found without obvious expiry policy",
                    "Laravel remember-me tokens can persist for long periods. Consider explicit expiry or device/session revocation controls.",
                    line.and_then(|line_number| snippet_for_line(&file.content, line_number)),
                ));
            }
        }
    }

    findings
}

#[derive(Clone, Copy)]
struct GroupContext {
    start_depth: usize,
    has_auth_middleware: bool,
    has_authorization: bool,
}

fn is_group_start(line: &str) -> bool {
    line.contains("route::") && line.contains("->group(")
}

fn has_auth_middleware(line: &str) -> bool {
    line.contains("middleware(")
        && (line.contains("auth")
            || line.contains("verified")
            || line.contains("sanctum")
            || line.contains("auth:"))
}

fn has_authorization_hint(line: &str) -> bool {
    (line.contains("middleware(")
        && (line.contains("can:") || line.contains("permission:") || line.contains("role:")))
        || line.contains("->can(")
        || line.contains("authorize(")
        || line.contains("Gate::allows(")
        || line.contains("Gate::authorize(")
}

fn count_open_braces(line: &str) -> usize {
    line.matches('{').count()
}

fn count_close_braces(line: &str) -> usize {
    line.matches('}').count()
}
