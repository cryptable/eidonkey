extern crate serde_json;

use self::serde_json::Value;

pub const PINCODE_OK: u32				= 0;
pub const PINCODE_CALL_FAILED:u32		= 101;
pub const PINCODE_DECODE_ERROR:u32		= 102;
pub const PINCODE_DECODE_UTF8_ERROR:u32	= 103;

#[link(name = "pincode")]
extern {
	fn initPINCode();
	fn getAuthenticationPINCode(nbrRetries: i32, pincode: *mut u8, len: *mut u64) -> u64;
	fn getSignaturePINCode(nbrRetries: i32, hash: *const u8, pincode: *mut u8, len: *mut u64) -> u64;
	fn closePINCode();
}

pub fn init_pincode() {
    unsafe {
    	initPINCode(); 
    }
}

pub fn close_pincode() {
    unsafe {
    	closePINCode(); 
    }
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

	unsafe {
		let mut size : u64 = 32;
		let mut ret : u64 = 0;
		let mut pincode: Vec<u8> = vec![0; size as usize];

		trace!("Calling getAuthenticationPINCode()");
		ret = getAuthenticationPINCode(nbr_retries, pincode.as_mut_ptr(), &mut size);

		if ret != PINCODE_OK as u64 {
			trace!("Calling failed");
			return Err(PINCODE_CALL_FAILED);
		}
		match String::from_utf8(pincode) {
			Ok(pin) => {
				trace!("PIN received");
				return Ok(pin.trim_right_matches(char::from(0)).to_string());
			},
			Err(_) => { 
				trace!("PIN failed");
				return Err(PINCODE_CALL_FAILED);
			},
		}
	}
}

pub fn get_pincode_sign(nbr_retries: i32, hash: String) -> Result<String, u32> {
	trace!("Retries [{:?}]", nbr_retries);
	trace!("Hash [{:?}]", hash);


	unsafe {
		let mut size : u64 = 32;
		let mut ret : u64 = 0;
		let mut pincode: Vec<u8> = vec![0; size as usize];

		ret = getSignaturePINCode(nbr_retries, hash.as_ptr(), pincode.as_mut_ptr(), &mut size);

		if ret != PINCODE_OK as u64 {
			return Err(PINCODE_CALL_FAILED);
		}
		match String::from_utf8(pincode) {
			Ok(pin) => {
				return Ok(pin.trim_right_matches(char::from(0)).to_string());
			},
			Err(_) => { 
				return Err(PINCODE_CALL_FAILED);
			},
		}
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