use std::fs::{self, File};
use std::io;
use std::path::Path;
use zip::read::ZipArchive;
use anyhow::{Result, Context};

pub struct TomlLockExtractor;

impl TomlLockExtractor {
    /// 从 ZIP 文件中提取所有 .toml 和 .lock 文件
    pub fn extract_toml_and_lock_files(
        zip_path: &str,
        output_dir: &str,
    ) -> Result<()> {
        // 创建输出目录
        fs::create_dir_all(output_dir)
            .context("无法创建输出目录")?;

        // 打开 ZIP 文件
        let file = File::open(zip_path)
            .context("无法打开 ZIP 文件")?;
        
        let mut archive = ZipArchive::new(file)
            .context("无效的 ZIP 文件")?;

        // 遍历 ZIP 中的所有文件
        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)
                .context(format!("无法读取 ZIP 中的文件索引 {}", i))?;

            let file_path = zip_file.mangled_name();
            let file_name = file_path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");

            // 检查文件扩展名
            if Self::is_toml_or_lock_file(file_name) {
                let relative_path = file_path.to_string_lossy().to_string();
                
                // 创建输出路径
                let output_path = Path::new(output_dir).join(&relative_path);
                
                // 确保父目录存在
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)
                        .context(format!("无法创建目录: {}", parent.display()))?;
                }

                // 写入文件
                let mut output_file = File::create(&output_path)
                    .context(format!("无法创建文件: {}", output_path.display()))?;
                
                io::copy(&mut zip_file, &mut output_file)
                    .context(format!("无法写入文件: {}", output_path.display()))?;

                println!("✓ 提取: {} -> {}", file_name, output_path.display());
            }
        }

        Ok(())
    }

    /// 检查文件名是否为 .toml 或 .lock 文件
    fn is_toml_or_lock_file(filename: &str) -> bool {
        let path = Path::new(filename);
        
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            extension == "toml" || extension == "lock"
        } else {
            false
        }
    }
}
