use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zip::read::ZipArchive;
use anyhow::{Result, Context};

pub struct TomlLockExtractor;

impl TomlLockExtractor {
    /// 从 ZIP 文件中提取所有 .toml 和 .lock 文件
    pub fn extract_toml_and_lock_files(
        zip_path: &str,
        output_dir: &str,
    ) -> Result<Vec<ExtractedFile>> {
        // 创建输出目录
        fs::create_dir_all(output_dir)
            .context("无法创建输出目录")?;

        let mut extracted_files = Vec::new();

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

                // 记录提取的文件信息
                extracted_files.push(ExtractedFile {
                    original_path: relative_path,
                    output_path: output_path.to_string_lossy().to_string(),
                    file_size: zip_file.size(),
                });

                println!("✓ 提取: {} -> {}", file_name, output_path.display());
            }
        }

        Ok(extracted_files)
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

    /// 从 ZIP 文件中提取特定的 TOML/Lock 文件（如 Cargo.toml, package-lock.json 等）
    pub fn extract_specific_files(
        zip_path: &str,
        output_dir: &str,
        specific_files: &[&str],
    ) -> Result<Vec<ExtractedFile>> {
        fs::create_dir_all(output_dir)
            .context("无法创建输出目录")?;

        let mut extracted_files = Vec::new();

        let file = File::open(zip_path)
            .context("无法打开 ZIP 文件")?;
        
        let mut archive = ZipArchive::new(file)
            .context("无效的 ZIP 文件")?;

        for target_file in specific_files {
            if let Ok(mut zip_file) = archive.by_name(target_file) {
                let output_path = Path::new(output_dir).join(target_file);
                
                // 确保父目录存在
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)
                        .context(format!("无法创建目录: {}", parent.display()))?;
                }

                let mut output_file = File::create(&output_path)
                    .context(format!("无法创建文件: {}", output_path.display()))?;
                
                io::copy(&mut zip_file, &mut output_file)
                    .context(format!("无法写入文件: {}", output_path.display()))?;

                extracted_files.push(ExtractedFile {
                    original_path: target_file.to_string(),
                    output_path: output_path.to_string_lossy().to_string(),
                    file_size: zip_file.size(),
                });

                println!("✓ 提取特定文件: {} -> {}", target_file, output_path.display());
            } else {
                println!("⚠ 未找到文件: {}", target_file);
            }
        }

        Ok(extracted_files)
    }

    /// 从 ZIP 文件中读取 .toml 和 .lock 文件的内容到内存
    pub fn read_toml_and_lock_contents(zip_path: &str) -> Result<Vec<FileContent>> {
        let mut file_contents = Vec::new();

        let file = File::open(zip_path)
            .context("无法打开 ZIP 文件")?;
        
        let mut archive = ZipArchive::new(file)
            .context("无效的 ZIP 文件")?;

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)
                .context(format!("无法读取 ZIP 中的文件索引 {}", i))?;

            let file_path = zip_file.mangled_name();
            let file_name = file_path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");

            if Self::is_toml_or_lock_file(file_name) {
                let mut content = String::new();
                zip_file.read_to_string(&mut content)
                    .context(format!("无法读取文件内容: {}", file_name))?;

                file_contents.push(FileContent {
                    path: file_path.to_string_lossy().to_string(),
                    content,
                    size: zip_file.size(),
                });

                println!("✓ 读取到内存: {} ({} 字节)", file_name, zip_file.size());
            }
        }

        Ok(file_contents)
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedFile {
    pub original_path: String,
    pub output_path: String,
    pub file_size: u64,
}

#[derive(Debug, Clone)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub size: u64,
}
