use cargo_lock::Lockfile;
use crate::extract_zip::{TomlLockExtractor};

pub fn get_lockfile(zip_path: &str) -> Lockfile {
    let output_dir = "./tmp";
    TomlLockExtractor::extract_toml_and_lock_files(zip_path, output_dir);
    let lockfile = Lockfile::load(format!("{}/Cargo.lock", output_dir)).unwrap();
    return lockfile;
}