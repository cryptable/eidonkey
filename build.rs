extern crate cmake;

use cmake::Config;

fn main() {
	// Builds the project in the directory located in `pincode`, installing it
	// into $OUT_DIR
//	let dst = Config::new("pincode").cflag("").build();
	let dst = cmake::build("pincode");

	println!("cargo:rustc-link-search=native={}", dst.display());
	// println!("cargo:rustc-link-lib=static=pincode");
}