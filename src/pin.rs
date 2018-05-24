extern crate serde_json;

use self::serde_json::Value;

use std::process::Command;

pub const PINCODE_OK: u32				= 0;
pub const PINCODE_CALL_FAILED:u32		= 101;
pub const PINCODE_DECODE_ERROR:u32		= 102;
pub const PINCODE_DECODE_UTF8_ERROR:u32	= 103;

pub fn init_pincode() {

}

pub fn close_pincode() {

}

fn parseJsonResult(jsonData: &str) -> Result<String, u32> {
	let result : Value = serde_json::from_str(jsonData).unwrap();

	trace!("Decoding result: {:?}", result);

	let result_code = result.find("result_code").unwrap().as_u64().unwrap();
	trace!("Decoding result_code: {:?}", result_code);
	let result_data = result.find("result_data").unwrap().as_str().unwrap();
	trace!("Decoding result_data: {:?}", result_data);

	if result_code == 0 {
		Ok(result_data.to_string())
	}
	else {
		Err(result_code as u32)
	}
}

pub fn get_pincode_auth(nbr_retries: i32) -> Result<String, u32> {
	trace!("Retries [{:?}]", nbr_retries);
	let mut command = Command::new("./pincode");

	if nbr_retries >= 0 {
		command.args(&["-t", "authentication"]).arg("-r").arg(nbr_retries.to_string());
	}
	else {
		command.args(&["-t", "authentication"]);
	}
	let output = command.output();

	trace!("get_pincode_auth: {:?}", output);
	match output {
		Ok(outp) => {
			let out = String::from_utf8(outp.stdout);

			match out {
				Ok(data) => { 
					trace!("get_pincode_auth: output {:?}", data);
					parseJsonResult(&data)
				},
				Err(_) => Err(PINCODE_DECODE_UTF8_ERROR)
			}
		},
		Err(_) => Err(PINCODE_CALL_FAILED)
	}
}

pub fn get_pincode_sign(nbr_retries: i32, hash: String) -> Result<String, u32> {
	trace!("Retries [{:?}]", nbr_retries);
	trace!("Hash [{:?}]", hash);
	let mut command = Command::new("./pincode");

	if nbr_retries >= 0 {
		command.args(&["-t", "signature"]).arg("-h").arg(hash).arg("-r").arg(nbr_retries.to_string());
	}
	else {
		command.args(&["-t", "signature"]).arg("-h").arg(hash);
	}
	let output = command.output();

	trace!("get_pincode_sign: {:?}", output);
	match output {
		Ok(outp) => {
			let out = String::from_utf8(outp.stdout);

			match out {
				Ok(data) => {
					trace!("get_pincode_sign: output {:?}", data);
					parseJsonResult(&data)
				},
				Err(_) => Err(PINCODE_DECODE_UTF8_ERROR)
			}
		},
		Err(_) => Err(PINCODE_CALL_FAILED)
	}
}

#[cfg(test)]
mod tests {

	#[test]
	fn test_pincode() {
		let res = get_pincode_auth(0, "Test");

		match res {
			Ok(pin) => assert_eq!("1234", pin),
			Err(e) => {
				println!("Error {:?}", e);
				assert!(false);
			}
		}
	}
}