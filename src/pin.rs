use std::ptr;

pub const PINCODE_OK: u32				= 0;
pub const PINCODE_NOT_ENTERED: u32		= 1;
pub const PINCODE_BUFFER_TOO_SMALL:u32	= 2;
pub const PINCODE_BUFFER_UNDEFINED:u32	= 3;

pub const PINCODE_UTF8_DECODE_ERROR:u32	= 101;

#[cfg(not(feature = "mock_pincode"))]
#[link(name = "pincode")]	
extern {
	fn getPINCode(pincode: *mut u8, len: *mut usize) -> u32;
}

#[cfg(feature = "mock_pincode")]
fn getPINCode(pincode: *mut u8, len: *mut usize) -> u32 {

	unsafe {
		*len = 4; 
		ptr::write(pincode.offset(0), 0x31);
		ptr::write(pincode.offset(1), 0x32);
		ptr::write(pincode.offset(2), 0x33);
		ptr::write(pincode.offset(3), 0x34);
    }

	return PINCODE_OK;
}


pub fn get_pincode() -> Result<String, u32> {
	unsafe {
		let mut pincode: Vec<u8> = vec![0; 16];
		let mut pincode_lg: usize = 16;
		let ret = getPINCode( pincode.as_mut_ptr(), &mut pincode_lg);

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
