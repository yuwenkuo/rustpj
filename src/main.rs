mod extract_zip;
mod get_lockfile;

use cargo_lock::Lockfile;
use extract_zip::{TomlLockExtractor};
use get_lockfile::get_lockfile;
fn main() {
	let zip_path = "./test/test1.zip";
	let output_dir = "./test";
    let lockfile = get_lockfile(zip_path);
    println!("{}", lockfile.to_string());
	// TomlLockExtractor::extract_toml_and_lock_files(zip_path, output_dir);
}
