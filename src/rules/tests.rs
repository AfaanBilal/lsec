use std::path::PathBuf;

use crate::config::Config;
use crate::models::ScanContext;
use crate::rules::run_rules;
use crate::scanner::Project;

fn context() -> ScanContext {
    ScanContext {
        root: PathBuf::from("."),
        config: Config::default(),
        only: Vec::new(),
        skip: Vec::new(),
        only_rule_ids: Vec::new(),
        skip_rule_ids: Vec::new(),
        min_confidence: None,
        ci: false,
    }
}

#[test]
fn detects_missing_authorization_on_sensitive_route() {
    let project = Project::from_test_files(&[(
        "routes/web.php",
        "Route::get('/admin/users', fn () => 'ok')->middleware('auth');",
    )]);
    let findings = run_rules(&project, &context());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "auth.missing-route-authorization")
    );
}

#[test]
fn detects_unserialize_usage() {
    let project = Project::from_test_files(&[(
        "app/Http/Controllers/FooController.php",
        "<?php\n$payload = unserialize($request->input('payload'));",
    )]);
    let findings = run_rules(&project, &context());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "injection.unserialize")
    );
}

#[test]
fn detects_user_controlled_outbound_url() {
    let project = Project::from_test_files(&[(
        "app/Services/Webhook.php",
        "<?php\nHttp::get($request->input('url'));",
    )]);
    let findings = run_rules(&project, &context());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "http.ssrf-user-url")
    );
}

#[test]
fn detects_user_controlled_storage_filename() {
    let project = Project::from_test_files(&[(
        "app/Http/Controllers/UploadController.php",
        "<?php\n$request->file('avatar')->storeAs('avatars', $request->input('name'));",
    )]);
    let findings = run_rules(&project, &context());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "storage.user-controlled-filename")
    );
}

#[test]
fn detects_missing_lockfile_and_old_php_constraint() {
    let project = Project::from_test_files(&[(
        "composer.json",
        r#"{
  "require": {
    "php": "^7.4",
    "laravel/framework": "^8.0"
  }
}"#,
    )]);
    let findings = run_rules(&project, &context());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "deps.lockfile-missing")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "deps.old-php-constraint")
    );
}

#[test]
fn respects_rule_id_filtering() {
    let project = Project::from_test_files(&[(
        "app/Services/Webhook.php",
        "<?php\nHttp::get($request->input('url'));\n$payload = unserialize($request->input('payload'));",
    )]);
    let mut context = context();
    context.only_rule_ids = vec!["http.ssrf-user-url".to_string()];
    let findings = run_rules(&project, &context);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "http.ssrf-user-url");
}

#[test]
fn respects_confidence_threshold_overrides() {
    let project = Project::from_test_files(&[(
        "routes/web.php",
        "Route::get('/admin/users', fn () => 'ok')->middleware('auth');",
    )]);
    let mut context = context();
    context.min_confidence = Some(0.7);
    let findings = run_rules(&project, &context)
        .into_iter()
        .filter(|finding| context.confidence_enabled(finding.rule_id, finding.confidence))
        .collect::<Vec<_>>();
    assert!(findings.is_empty());
}
