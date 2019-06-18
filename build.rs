extern crate cmake;

use std::process::Command;

// -L/usr/local/lib   -framework IOKit -framework Carbon -framework Cocoa -framework AudioToolbox -framework System -framework OpenGL -lwx_osx_cocoau_wxBase-3.0 -lwx_baseu-3.0 

fn get_wx_libraries() {
	let output = Command::new("wx-config")
		.arg("--libs")
		.output()
		.unwrap_or_else( |e| { panic!("failed to execute process 'wx-config': {}", e) } );
	let hello = String::from_utf8(output.stdout).unwrap_or_else( |e| { panic!("failed to execute process 'wx-config': {}", e) } ) ;
	
	let mut framework: bool = false;

	for part in hello.split_whitespace() {
		if part.starts_with("-L") {
	    	println!("cargo:rustc-link-search=native={}", part.trim_left_matches("-L"));
		}
		else if part.starts_with("-l") {
	    	println!("cargo:rustc-link-lib=dylib={}", part.trim_left_matches("-l"));
		}
		else if part == "-framework" {
			framework = true;
		}
		else {
			if framework {
		        println!("cargo:rustc-link-lib=framework={}", part);				
			}
		}
	}
} 

fn main() {
	// Builds the project in the directory located in `pincode`, installing it
	// into $OUT_DIR
	let dst = cmake::build("pincode");

	get_wx_libraries();

	println!("cargo:rustc-link-lib=dylib=c++");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=pincode");
}