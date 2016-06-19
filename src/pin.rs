use std::ptr;

pub const PINCODE_OK: u32				= 0;
pub const PINCODE_NOT_ENTERED: u32		= 1;
pub const PINCODE_BUFFER_TOO_SMALL:u32	= 2;
pub const PINCODE_BUFFER_UNDEFINED:u32	= 3;

pub const PINCODE_UTF8_DECODE_ERROR:u32	= 101;	

#[cfg(not(feature = "mock_pincode"))]
#[link(name = "pincode", kind="static")]
extern {
	fn getPINCode(nbrRetries: u32, pincode: *mut u8, len: *mut usize) -> u32;
	fn initPINCode();
	fn closePINCode();
}

#[cfg(feature = "mock_pincode")]
fn initPINCode() {
}

#[cfg(feature = "mock_pincode")]
fn closePINCode() {
}

#[cfg(feature = "mock_pincode")]
fn getPINCode(nbrRetries: u32, pincode: *mut u8, len: *mut usize) -> u32 {

	unsafe {
		*len = 4; 
		ptr::write(pincode.offset(0), 0x31);
		ptr::write(pincode.offset(1), 0x32);
		ptr::write(pincode.offset(2), 0x33);
		ptr::write(pincode.offset(3), 0x34);
    }

	return PINCODE_OK;
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

pub fn get_pincode(nbr_retries: u32) -> Result<String, u32> {
	unsafe {

		let mut pincode: Vec<u8> = vec![0; 16];
		let mut pincode_lg: usize = 16;
		println!("pin: request PIN code");
		let ret = getPINCode( nbr_retries, pincode.as_mut_ptr(), &mut pincode_lg);

		println!("pin: PIN code return {}", ret);
		if ret == PINCODE_OK {
			pincode.truncate(pincode_lg);
			match String::from_utf8(pincode) {
				Ok(p) => Ok(p),
				Err(_) => Err(PINCODE_UTF8_DECODE_ERROR)
			}
		}
		else {
			Err(ret)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::get_pincode;

	#[test]
	fn test_pincode() {
		let res = get_pincode(0);

		match res {
			Ok(pin) => assert_eq!("1234", pin),
			Err(e) => {
				println!("Error {:?}", e);
				assert!(false);
			}
		}
	}
}