use cargo_lock::Lockfile;
use crate::extract_zip::TomlLockExtractor;
use std::fs;
use std::process::Command;
use walkdir::WalkDir;
use std::path::PathBuf;

// Return both the parsed lockfile and the detected project root directory
pub struct LockDiscovery {
    pub lockfile: Lockfile,
    pub project_root: PathBuf,
}

pub fn get_lockfile(zip_path: &str) -> Result<LockDiscovery, anyhow::Error> {
    let output_dir = "./tmp";
    
    // 确保有一个干净的临时目录
    if fs::metadata(output_dir).is_ok() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;

    TomlLockExtractor::extract_toml_and_lock_files(zip_path, output_dir)?;
    
    // 在解压目录中递归查找 Cargo.lock 文件
    for entry in WalkDir::new(output_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name() == "Cargo.lock" {
            let lock_path = entry.path();
            if let Ok(lockfile) = Lockfile::load(lock_path) {
                let project_root = lock_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .ok_or_else(|| anyhow::anyhow!("Failed to determine project root from Cargo.lock"))?;
                return Ok(LockDiscovery { lockfile, project_root });
            }
        }
    }

    // 如果没有找到 Cargo.lock，尝试查找项目根目录的 Cargo.toml
    let mut project_root = None;
    for entry in WalkDir::new(output_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name() == "Cargo.toml" {
            let cargo_dir = entry.path().parent()
                .ok_or_else(|| anyhow::anyhow!("无法获取 Cargo.toml 所在目录"))?;
                
            // 检查这个目录是否像是项目根目录（例如，检查是否有 src 目录）
            if cargo_dir.join("src").exists() {
                project_root = Some(PathBuf::from(cargo_dir));
                break;
            }
        }
    }

    // 如果找到项目根目录，尝试生成 lock 文件
    if let Some(root) = project_root {
        println!("\nNote: No Cargo.lock found, attempting to generate offline...");
        
        // 运行 cargo generate-lockfile
        let status = Command::new("cargo")
            .current_dir(&root)
            .arg("generate-lockfile")
            .status()
            .map_err(|e| anyhow::anyhow!("无法执行 cargo generate-lockfile: {}", e))?;

        if !status.success() {
            return Err(anyhow::anyhow!("生成 Cargo.lock 失败，请检查项目依赖配置是否正确"));
        }

        println!("OK generated Cargo.lock");

        // 尝试加载生成的 lock 文件
        let lock_path = root.join("Cargo.lock");
        return Lockfile::load(&lock_path)
            .map(|lockfile| LockDiscovery { lockfile, project_root: root })
            .map_err(|e| anyhow::anyhow!("无法加载生成的 Cargo.lock: {}", e));
    }
    
    Err(anyhow::anyhow!("在 ZIP 文件中找不到有效的 Rust 项目结构（需要 Cargo.toml 和 src 目录）。请确保 ZIP 文件包含完整的 Rust 项目"))
}
