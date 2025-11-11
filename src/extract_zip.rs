use std::fs::{self, File};
use std::io;
use std::path::Path;
use zip::read::ZipArchive;
use anyhow::{Result, Context};

pub struct TomlLockExtractor;

impl TomlLockExtractor {
    // Extract the entire ZIP payload. We previously extracted only .toml/.lock, which
    // prevented `cargo generate-lockfile` from working because Cargo requires a real
    // target (src/main.rs, src/lib.rs, or explicit [[bin]]) to parse the manifest.
    // Using `mangled_name()` ensures any path traversal inside the ZIP is neutralized.
    pub fn extract_toml_and_lock_files(zip_path: &str, output_dir: &str) -> Result<()> {
        fs::create_dir_all(output_dir).context("无法创建输出目录")?;

        let file = File::open(zip_path).context("无法打开 ZIP 文件")?;
        let mut archive = ZipArchive::new(file).context("无效的 ZIP 文件")?;

        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .context(format!("无法读取 ZIP 中的文件索引 {}", i))?;

            let rel = entry.mangled_name();
            let out_path = Path::new(output_dir).join(&rel);

            if entry.is_dir() {
                fs::create_dir_all(&out_path)
                    .with_context(|| format!("无法创建目录: {}", out_path.display()))?;
                continue;
            }

            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("无法创建目录: {}", parent.display()))?;
            }

            let mut out_file = File::create(&out_path)
                .with_context(|| format!("无法创建文件: {}", out_path.display()))?;
            io::copy(&mut entry, &mut out_file)
                .with_context(|| format!("无法写入文件: {}", out_path.display()))?;

            // Only print a line for interesting files to keep logs tidy
            if let Some(name) = rel.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".toml") || name.ends_with(".lock") || name == "main.rs" {
                    println!("EXTRACTED: {} -> {}", name, out_path.display());
                }
            }
        }

        Ok(())
    }
}
