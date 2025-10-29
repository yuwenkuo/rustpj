mod extract_zip;

use extract_zip::{TomlLockExtractor};


fn main() {
	let zip_path = "./test/test1.zip";
	let output_dir = "./test";
	TomlLockExtractor::extract_toml_and_lock_files(zip_path, output_dir);
}
