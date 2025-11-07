use cargo_lock::Lockfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Dependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dependsOn")]
    depends_on: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    timestamp: String,
    tools: Vec<Tool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Component {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "bom-ref")]
    bom_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<License>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct License {
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<LicenseChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expression: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LicenseChoice {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

pub fn generate_sbom_from_lockfile(lockfile: &Lockfile, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 读取并解析 Cargo.lock
    // let lockfile = Lockfile::load(lockfile_path)?;
    
    println!("Fetching license information...");
    
    // 一次性获取所有许可证信息
    let license_cache = fetch_all_licenses()?;
    
    println!("Building SBOM...");
    
    // 创建组件列表和依赖关系映射
    let mut components = Vec::new();
    let mut dependencies = Vec::new();
    
    for package in &lockfile.packages {
        let version = package.version.to_string();
        let name = package.name.as_str();
        
        // 生成 PURL (Package URL)
        let purl = format!("pkg:cargo/{}@{}", name, version);
        let bom_ref = format!("{}@{}", name, version);
        
        // 从缓存中获取许可证信息
        let licenses = license_cache
            .get(&(name.to_string(), version.clone()))
            .and_then(|license_str| Some(parse_license_expression(license_str)));
        
        components.push(Component {
            component_type: "library".to_string(),
            name: name.to_string(),
            version: version.clone(),
            purl: Some(purl),
            bom_ref: Some(bom_ref.clone()),
            licenses,
        });
        
        // 构建依赖关系
        let mut depends_on = Vec::new();
        for dep in &package.dependencies {
            // 在 lockfile 中查找依赖的具体版本
            if let Some(dep_pkg) = lockfile.packages.iter().find(|p| p.name.as_str() == dep.name.as_str()) {
                let dep_ref = format!("{}@{}", dep.name.as_str(), dep_pkg.version);
                depends_on.push(dep_ref);
            }
        }
        
        dependencies.push(Dependency {
            reference: bom_ref,
            depends_on: if depends_on.is_empty() { None } else { Some(depends_on) },
        });
    }
    
    // 创建 SBOM
    let bom = CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.4".to_string(),
        version: 1,
        metadata: Metadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tools: vec![Tool {
                vendor: "Custom".to_string(),
                name: "cargo-sbom-generator".to_string(),
                version: "1.0.0".to_string(),
            }],
        },
        components,
        dependencies,
    };
    
    // 序列化为 JSON
    let json = serde_json::to_string_pretty(&bom)?;
    
    // 写入文件
    fs::write(output_path, json)?;
    
    println!("SBOM generated successfully at: {}", output_path);
    println!("Total components: {}", bom.components.len());
    println!("Total dependencies: {}", bom.dependencies.len());
    
    Ok(())
}

fn fetch_all_licenses() -> Result<HashMap<(String, String), String>, Box<dyn std::error::Error>> {
    let mut license_map = HashMap::new();
    // println!("Fetching license information...");
    // 执行 cargo metadata 一次
    let output = Command::new("cargo")
        .args(&["metadata", "--format-version=1", "--offline", "--locked"])
        .output()?;
    // println!("Fetching license information...");
    if !output.status.success() {
        eprintln!("Warning: cargo metadata failed, licenses will not be included");
        return Ok(license_map);
    }
    // println!("Fetching license information...");
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    
    // 遍历所有包并提取许可证
    if let Some(packages) = metadata["packages"].as_array() {
        for pkg in packages {
            if let (Some(name), Some(version), Some(license)) = (
                pkg["name"].as_str(),
                pkg["version"].as_str(),
                pkg["license"].as_str(),
            ) {
                license_map.insert((name.to_string(), version.to_string()), license.to_string());
            }
        }
    }
    
    Ok(license_map)
}

fn parse_license_expression(license_str: &str) -> Vec<License> {
    // 处理 SPDX 许可证表达式
    if license_str.contains(" OR ") || license_str.contains(" AND ") || license_str.contains('/') {
        // 复杂表达式，使用 expression 字段
        vec![License {
            license: None,
            expression: Some(license_str.to_string()),
        }]
    } else {
        // 简单许可证，使用 id 字段
        vec![License {
            license: Some(LicenseChoice {
                id: Some(license_str.to_string()),
                name: None,
            }),
            expression: None,
        }]
    }
}