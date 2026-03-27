//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct ProjectFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct Project {
    pub files: Vec<ProjectFile>,
}

impl Project {
    pub fn load(root: &Path, config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let mut files = Vec::new();
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if !entry.file_type().is_file() || is_excluded(root, path, &config.scan.exclude_paths) {
                continue;
            }

            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            if bytes.contains(&0) {
                continue;
            }
            let Ok(content) = String::from_utf8(bytes) else {
                continue;
            };

            files.push(ProjectFile {
                path: path.to_path_buf(),
                relative_path: relative(root, path),
                content,
            });
        }

        Ok(Self { files })
    }

    pub fn find_file(&self, relative_path: &str) -> Option<&ProjectFile> {
        self.files
            .iter()
            .find(|file| file.relative_path == relative_path)
    }

    pub fn files_with_extension(&self, extension: &str) -> Vec<&ProjectFile> {
        self.files
            .iter()
            .filter(|file| file.path.extension().and_then(|ext| ext.to_str()) == Some(extension))
            .collect()
    }

    pub fn files_under(&self, prefix: &str) -> Vec<&ProjectFile> {
        self.files
            .iter()
            .filter(|file| file.relative_path.starts_with(prefix))
            .collect()
    }
}

fn is_excluded(root: &Path, path: &Path, excludes: &[String]) -> bool {
    let rel = relative(root, path);
    excludes.iter().any(|prefix| rel.starts_with(prefix.trim()))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
