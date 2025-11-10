mod extract_zip;
mod get_lockfile;
mod scanner;
mod get_sbom;

use std::path::Path;
use anyhow::{Context, Result};
use get_lockfile::get_lockfile;
use scanner::Scanner;
use std::env;
use get_sbom::generate_sbom_from_lockfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-zip-file>", args[0]);
        eprintln!("Example: {} ./test/project.zip", args[0]);
        std::process::exit(1);
    }

    let zip_path = &args[1];
    println!("扫描文件: {}", zip_path);
    let discovery = get_lockfile(zip_path)?;
    let lockfile = &discovery.lockfile;

    // 创建输出目录
    std::fs::create_dir_all("./output")
        .context("failed to create output directory")?;

    // 获取 sbom 并写入 sbom 文件
    let sbom_path = "./output/sbom.json";
    generate_sbom_from_lockfile(lockfile, &discovery.project_root, sbom_path)?;

    // 初始化扫描器（使用本地 advisory DB）
    let scanner = Scanner::new("./data/advisory-db")
        .context("failed to initialize vulnerability scanner")?;

    // 扫描依赖并生成报告
    let report = scanner.scan_lockfile(lockfile)
        .context("failed to scan dependencies")?;

    // 将报告写入 JSON 文件
    let report_path = Path::new("./output/vuln_report.json");
    std::fs::write(
        report_path,
        serde_json::to_string_pretty(&report)?,
    ).context("failed to write vulnerability report")?;

    
    

    // 打印扫描统计
    println!("\nScan completed!");
    println!("Total packages scanned: {}", report.total_packages);
    println!("Vulnerabilities found: {}", report.summary.total_vulnerabilities);
    println!("By severity:");
    println!("  Critical: {}", report.summary.by_severity.critical);
    println!("  High:     {}", report.summary.by_severity.high);
    println!("  Medium:   {}", report.summary.by_severity.medium);
    println!("  Low:      {}", report.summary.by_severity.low);
    println!("  Unknown:  {}", report.summary.by_severity.unknown);
    println!("\nDetailed report written to: {}", report_path.display());

    // 清理临时文件和目录
    println!("\nCleaning temporary files...");
    if let Err(e) = std::fs::remove_dir_all("./tmp") {
        eprintln!("Warning: failed to clean temporary files: {}", e);
    } else {
        println!("OK temporary files cleaned");
    }

    Ok(())
}
