use std::collections::HashMap;
use std::path::Path;
use anyhow::{Context, Result};
use cargo_lock::Lockfile;
use rustsec::{
    advisory::Advisory,
    database::Database,
    repository::git::Repository,
};
use semver::Version;
use serde::Serialize;

// 用于测试
#[cfg(test)]
use {
    std::collections::BTreeMap,
    std::str::FromStr,
};

#[derive(Debug, Serialize)]
pub struct VulnReport {
    pub total_packages: usize,
    pub packages: Vec<PackageReport>,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct PackageReport {
    pub package_name: String,
    pub package_version: String,
    pub advisories: Vec<AdvisoryFinding>,
}

#[derive(Debug, Serialize)]
pub struct AdvisoryFinding {
    pub id: String,
    pub description: String,
    pub severity: Option<String>,
    pub unaffected_versions: String,
    pub patched_versions: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub total_vulnerabilities: usize,
    pub by_severity: SeverityCounts,
}

#[derive(Debug, Default, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

pub struct Scanner {
    db: Database,
}

impl Scanner {
    /// 从本地 git 仓库加载 advisory DB
    /// path 应指向一个 RustSec/advisory-db 的克隆
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let path = db_path.as_ref();
        if !path.exists() {
            anyhow::bail!("Advisory DB path does not exist: {}", path.display());
        }

        let repo = Repository::open(path)
            .context("failed to open advisory DB git repository")?;
        
        let db = Database::load_from_repo(&repo)
            .context("failed to load advisory database")?;

        Ok(Scanner { db })
    }

    /// 扫描指定的 Cargo.lock 文件
    pub fn scan_lockfile(&self, lockfile: &Lockfile) -> Result<VulnReport> {
        // Aggregate findings per package
        let mut package_reports = Vec::new();
        let mut summary = Summary::default();

        // Pre-index advisories by package to avoid O(N*M)
        let mut by_package: HashMap<String, Vec<&Advisory>> = HashMap::new();
        for adv in self.db.iter() {
            // Skip withdrawn and informational advisories; keep only actionable
            if adv.metadata.withdrawn.is_some() || adv.metadata.informational.is_some() {
                continue;
            }
            by_package
                .entry(adv.metadata.package.to_string())
                .or_default()
                .push(adv);
        }

        // Scan each package against its advisories
        for pkg in &lockfile.packages {
            let mut advisories_for_pkg = Vec::new();
            if let Some(advs) = by_package.get(pkg.name.as_str()) {
                for advisory in advs {
                    if self.is_version_affected(&pkg.version, advisory) {
                        let advisory_find = self.create_advisory_finding(advisory);

                        // Update severity summary
                        if let Some(sev) = &advisory_find.severity {
                            match sev.to_uppercase().as_str() {
                                "CRITICAL" => summary.by_severity.critical += 1,
                                "HIGH" => summary.by_severity.high += 1,
                                "MEDIUM" => summary.by_severity.medium += 1,
                                "LOW" => summary.by_severity.low += 1,
                                _ => summary.by_severity.unknown += 1,
                            }
                        } else {
                            summary.by_severity.unknown += 1;
                        }

                        advisories_for_pkg.push(advisory_find);
                    }
                }
            }

            if !advisories_for_pkg.is_empty() {
                package_reports.push(PackageReport {
                    package_name: pkg.name.to_string(),
                    package_version: pkg.version.to_string(),
                    advisories: advisories_for_pkg,
                });
            }
        }

        // Count total advisories discovered across all packages
        summary.total_vulnerabilities = package_reports
            .iter()
            .map(|p| p.advisories.len())
            .sum();

        Ok(VulnReport { total_packages: lockfile.packages.len(), packages: package_reports, summary })
    }

    /// 检查给定版本是否受某个 advisory 影响
    fn is_version_affected(&self, version: &Version, advisory: &Advisory) -> bool {
        // Not affected if version is explicitly in patched ranges
        if advisory.versions.patched().iter().any(|req| req.matches(version)) {
            return false;
        }

        // Not affected if version matches any unaffected requirement
        if advisory
            .versions
            .unaffected()
            .iter()
            .any(|req| req.matches(version))
        {
            return false;
        }

        // Otherwise, assume affected
        true
    }

    /// 从 advisory 创建漏洞发现记录
    fn create_advisory_finding(&self, advisory: &Advisory) -> AdvisoryFinding {
        let unaffected_versions = advisory
            .versions
            .unaffected()
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let patched = advisory.versions.patched();
        let patched_versions = if !patched.is_empty() {
            Some(
                patched
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        } else {
            None
        };

        AdvisoryFinding {
            id: advisory.metadata.id.to_string(),
            description: advisory.metadata.description.clone(),
            severity: advisory
                .metadata
                .cvss
                .as_ref()
                .map(|c| c.severity().to_string()),
            unaffected_versions,
            patched_versions,
            references: advisory
                .metadata
                .references
                .iter()
                .map(|r| r.to_string())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// 创建一个小型测试用 advisory DB
    fn setup_test_db() -> (TempDir, String) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("advisory-db");
        fs::create_dir(&db_path).unwrap();
        
        // 初始化 git 仓库
        git2::Repository::init(&db_path).unwrap();
        
        (temp_dir, db_path.to_string_lossy().to_string())
    }

    // This test requires a valid RustSec advisory-db layout; ignored by default.
    #[ignore]
    #[test]
    fn test_load_empty_db() {
        let (_temp_dir, db_path) = setup_test_db();
        let scanner = Scanner::new(&db_path).unwrap();

        // 创建一个最小的 lockfile 进行测试
        let mut lockfile = Lockfile {
            version: cargo_lock::ResolveVersion::V2,
            packages: vec![],
            root: None,
            metadata: BTreeMap::new(),
            patch: cargo_lock::Patch::default(),
        };
        let name = cargo_lock::package::Name::from_str("test-package").unwrap();
        let version = semver::Version::new(1, 0, 0);
        lockfile.packages.push(cargo_lock::Package {
            name,
            version,
            source: None,
            checksum: None,
            dependencies: vec![],
            replace: None,
        });

        let report = scanner.scan_lockfile(&lockfile).unwrap();
        assert_eq!(report.packages.len(), 0);
        assert_eq!(report.total_packages, 1);
    }

    #[test]
    fn test_nonexistent_db() {
        let result = Scanner::new("/nonexistent/path");
        assert!(result.is_err());
    }
}