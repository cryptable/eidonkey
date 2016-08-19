extern crate serde_json;
extern crate nanomsg;
extern crate rand;

use self::serde_json::Value;

use std::env;
use std::ptr;
use std::fs;
use std::process::Command;
use std::io::Read;
use self::nanomsg::{Socket, Protocol, Error};
use self::rand::{thread_rng, Rng};

pub const PINCODE_OK: u32				= 0;
pub const PINCODE_CALL_FAILED:u32		= 101;
pub const PINCODE_DECODE_ERROR:u32		= 102;
pub const PINCODE_DECODE_UTF8_ERROR:u32	= 103;


#[cfg(any(target_os="macos", target_os="linux"))]
fn get_temp_filepath()-> String {
	let mut dir = env::temp_dir();
	let rnd_part: String = thread_rng().gen_ascii_chars().take(10).collect();
	dir.push("nano".to_string() + &rnd_part);
	dir.set_extension("ipc");
	let tmpFN = dir.to_str();

	match tmpFN {
		Some(filename) => filename.to_string(),
		None => "/tmpNanomsg.ipc".to_string()
	}
}

#[cfg(target_os="windows")]
fn get_temp_filepath()-> String {
	let nano: String = "nano".to_string();
	let rnd_part: String = thread_rng().gen_ascii_chars().take(10).collect();
	"/" + nano + &rnd_part + ".ipc"
}

fn parse_json_result(jsonData: &str) -> Result<String, u32> {
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

	let mut socket = Socket::new(Protocol::Pull).unwrap();
	let tmp_fn = get_temp_filepath();
	let ipc_fn = format!("ipc://{}",tmp_fn);
	trace!("nanomsg:socket.bind {:?}", tmp_fn);
    let mut endpoint = socket.bind(ipc_fn.as_str()).unwrap();

	trace!("execute command [pincode ]");
	let mut command = Command::new("./pincode");
	if nbr_retries >= 0 {
		trace!("execute command [pincode -a -r {:?} -p {:?}]",nbr_retries.to_string(), ipc_fn);
		command.arg("-a").arg("-r").arg(nbr_retries.to_string()).arg("-p").arg(ipc_fn);
	}
	else {
		trace!("execute command [pincode -a -p {:?}]", ipc_fn);
		command.arg("-a").arg("-p").arg(ipc_fn);
	}
	let output = command.output();

	let mut msg = String::new();
    let res = socket.read_to_string(&mut msg);
	match res {
		Ok(_) => {
			trace!("get_pincode_auth: output {:?}", msg);
			fs::remove_file(tmp_fn);
			parse_json_result(&msg)
		},
		Err(e) => {
			trace!("get_pincode_auth: failed {:?}", e);
			fs::remove_file(tmp_fn);
			Err(PINCODE_CALL_FAILED)
		}
	}
}

pub fn get_pincode_sign(nbr_retries: i32, hash: String) -> Result<String, u32> {
	trace!("Retries [{:?}]", nbr_retries);
	trace!("Hash [{:?}]", hash);
	let mut socket = Socket::new(Protocol::Pull).unwrap();
	let tmp_fn = get_temp_filepath();
	let ipc_fn = format!("ipc://{}",tmp_fn);
	trace!("nanomsg:socket.bind {:?}", tmp_fn);
    let mut endpoint = socket.bind(ipc_fn.as_str()).unwrap();

	trace!("execute command [pincode ]");
	let mut command = Command::new("./pincode");
	if nbr_retries >= 0 {
		trace!("execute command [pincode -d <hash> -r {:?} -p {:?}]",nbr_retries.to_string(), ipc_fn);
		command.arg("-d").arg(hash).arg("-r").arg(nbr_retries.to_string()).arg("-p").arg(ipc_fn);
	}
	else {
		trace!("execute command [pincode -d <hash> -p {:?}]", ipc_fn);
		command.arg("-d").arg(hash).arg("-p").arg(ipc_fn);
	}
	let output = command.output();

	let mut msg = String::new();
    let res = socket.read_to_string(&mut msg);
	match res {
		Ok(_) => {
			trace!("get_pincode_sign: output {:?}", msg);
			fs::remove_file(tmp_fn);
			parse_json_result(&msg)
		},
		Err(e) => {
			trace!("get_pincode_sign: failed {:?}", e);
			fs::remove_file(tmp_fn);
			Err(PINCODE_CALL_FAILED)
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