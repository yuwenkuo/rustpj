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
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub package_name: String,
    pub package_version: String,
    pub advisory: AdvisoryInfo,
    pub patched_versions: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdvisoryInfo {
    pub id: String,
    pub description: String,
    pub severity: Option<String>,
    pub affected_versions: String,
    pub references: Vec<String>,
    pub cvss: Option<f32>,
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
        let mut findings = Vec::new();
        let mut summary = Summary::default();

        // 扫描每个包的每个 advisory
        for pkg in &lockfile.packages {
            let pkg_name = &pkg.name;
            let pkg_version = pkg.version.to_string();
            
            // 尝试解析版本（用于 semver 比较）
            if let Ok(version) = Version::parse(&pkg_version) {
                // 查找与该包相关的所有 advisories
                for advisory in self.db.iter() {
                    let rustsec_name = advisory.metadata.package.to_string();
                    let pkg_name_str = pkg_name.to_string();
                    if rustsec_name == pkg_name_str {
                        // 检查版本是否受影响
                        if self.is_version_affected(&version, advisory) {
                            let finding = self.create_finding(pkg, advisory);
                            
                            // 更新统计
                            if let Some(severity) = &finding.advisory.severity {
                                match severity.to_uppercase().as_str() {
                                    "CRITICAL" => summary.by_severity.critical += 1,
                                    "HIGH" => summary.by_severity.high += 1,
                                    "MEDIUM" => summary.by_severity.medium += 1,
                                    "LOW" => summary.by_severity.low += 1,
                                    _ => summary.by_severity.unknown += 1,
                                }
                            } else {
                                summary.by_severity.unknown += 1;
                            }
                            
                            findings.push(finding);
                        }
                    }
                }
            }
        }

        summary.total_vulnerabilities = findings.len();

        Ok(VulnReport {
            total_packages: lockfile.packages.len(),
            findings,
            summary,
        })
    }

    /// 检查给定版本是否受某个 advisory 影响
    fn is_version_affected(&self, version: &Version, advisory: &Advisory) -> bool {
        // 如果有明确的已修复版本列表，检查当前版本是否在补丁版本之前
        let patched_ranges = advisory.versions.patched();
        for req in patched_ranges {
            if req.matches(version) {
                return false;
            }
        }

        // 检查版本是否在受影响范围内
        advisory.versions.unaffected()
            .iter()
            .any(|req| !req.matches(version))
    }

    /// 从 advisory 创建漏洞发现记录
    fn create_finding(&self, pkg: &cargo_lock::Package, advisory: &Advisory) -> Finding {
        let affected_versions = advisory.versions.unaffected()
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let patched = advisory.versions.patched();
        let patched_versions = if !patched.is_empty() {
            Some(patched.iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", "))
        } else {
            None
        };

        // CVSS 分数
        let cvss = advisory.metadata.cvss.as_ref()
            .map(|c| match c.severity() {
                rustsec::advisory::Severity::Critical => 10.0,
                rustsec::advisory::Severity::High => 8.0,
                rustsec::advisory::Severity::Medium => 5.0,
                rustsec::advisory::Severity::Low => 2.0,
                _ => 0.0,
            });

        Finding {
            package_name: pkg.name.to_string(),
            package_version: pkg.version.to_string(),
            advisory: AdvisoryInfo {
                id: advisory.metadata.id.to_string(),
                description: advisory.metadata.description.clone(),
                severity: advisory.metadata.cvss.as_ref().map(|c| c.severity().to_string()),
                affected_versions,
                references: advisory.metadata.references.iter().map(|r| r.to_string()).collect(),
                cvss,
            },
            patched_versions,
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
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.total_packages, 1);
    }

    #[test]
    fn test_nonexistent_db() {
        let result = Scanner::new("/nonexistent/path");
        assert!(result.is_err());
    }
}