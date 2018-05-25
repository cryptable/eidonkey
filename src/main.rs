#[macro_use]
extern crate log;
extern crate env_logger;
extern crate openssl;
extern crate getopts;
extern crate data_encoding;
extern crate eidonkey;

use std::io::Write;
use std::env;
use std::io::{self, Read};

use getopts::Options;

use data_encoding::{base64, hex};

use eidonkey::{ EIdDonkeyCard, EIDONKEY_WRONG_PIN_RETRIES_X };

mod pin;
use pin::*;

pub const PARSING_REQUEST_ERROR: u32 	= 0x90020001;
pub const MISSING_PARAMETERS: u32 		= 0x90020002;
pub const INCORRECT_PARAMETERS: u32 	= 0x90020003; 
pub const PINCODE_FAILED: u32 			= 0x90020004; 
pub const PINCODE_CANCELLED: u32		= 0x90020005; 

fn version() -> String {
	"{\"result\":\"ok\",\"version\":\"0.1.0\"}".to_string()
}

fn error_card_response(error_code: u32) -> String {
	error_response_with_msg(error_code, EIdDonkeyCard::get_error_message(error_code))
}

fn error_response_with_msg(error_code: u32, error_msg: String) -> String {
	format!("{{\"result\":\"nok\",\
			   \"error_code\":{},\
			   \"error_msg\":\"{}\"\
			 }}", error_code, error_msg)
}

fn identity(eid_card: EIdDonkeyCard) -> String {

	trace!("Read Identity file");
	let identity_res = eid_card.read_identity();
	match identity_res {
		Ok(identity) => format!("{{\"result\":\"ok\",\
									\"identity\":{{\"card_number\":\"{}\",\
								 		\"chip_number\":\"{}\",\
							 			\"validity_begin\":\"{}\",\
								 		\"validity_end\":\"{}\",\
								 		\"delivery_municipality\":\"{}\",\
							 			\"national_number\":\"{}\",\
							 			\"name\":\"{}\",\
								 		\"second_first_name\":\"{}\",\
								 		\"third_first_name\":\"{}\",\
							 			\"nationality\":\"{}\",\
							 			\"birth_location\":\"{}\",\
								 		\"birth_date\":\"{}\",\
								 		\"sex\":\"{}\",\
							 			\"noble_condition\":\"{}\",\
							 			\"document_type\":\"{}\",\
								 		\"special_status\":\"{}\",\
								 		\"hash_photo\":\"{}\"\
								 	}},\
									\"identity_raw\":\"{}\",\
									\"signature\":\"{}\"\
							 	}}", 
		 							identity.card_number,
		 							base64::encode(&identity.chip_number), 
		 							identity.validity_begin, 
		 							identity.validity_end, 
		 							identity.delivery_municipality, 
		 							identity.national_number, 
		 							identity.name,
		 							identity.second_first_name.unwrap_or("null".to_string()),
		 							identity.third_first_name, 
		 							identity.nationality, 
		 							identity.birth_location, 
		 							identity.birth_date, 
		 							identity.sex, 
		 							identity.noble_condition.unwrap_or("null".to_string()),
		 							identity.document_type,
		 							identity.special_status.unwrap_or("null".to_string()),
		 							base64::encode(&identity.hash_photo),
		 							base64::encode(&identity.identity),
		 							base64::encode(&identity.signature)
		 							),
		Err(e) => error_card_response(e)
	}
}

fn address(eid_card: EIdDonkeyCard) -> String {
	let address_res = eid_card.read_address();

	match address_res {
		Ok(address) => format!("{{\"result\":\"ok\",\
				\"address\":{{\
					\"street\":\"{}\",\
					\"zip_code\":\"{}\",\
					\"city\":\"{}\"\
				}},\
				\"address_raw\":\"{}\",\
				\"signature\":\"{}\"\
			}}", 
			address.street,
			address.zip_code,
			address.city,
			base64::encode(&address.address),
			base64::encode(&address.signature)),
		Err(e) => error_card_response(e)
	}	
}

fn photo(eid_card: EIdDonkeyCard) -> String {
	let photo_res = eid_card.read_photo();

	match photo_res {
		Ok(photo) => format!("{{\"result\":\"ok\",\"photo\":\"{}\"}}", 
	 							base64::encode(&photo)),
		Err(e) => error_card_response(e)
	}	
}

fn status(eid_card: EIdDonkeyCard) -> String {
	let status_res = eid_card.get_status();

	match status_res {
		Ok(status) => format!("{{\"result\":\"ok\",\"status\":\
									{{\"reader_name\":\"{}\",\
										\"protocol\":\"{}\",\
										\"atr\":\"{}\"\
									}}\
								}}", 
	 							status.reader_name,
	 							status.protocol,
	 							base64::encode(&status.atr)),
		Err(e) => error_card_response(e)
	}	
}

fn certificates_authentication(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_authentication_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => error_card_response(e)
	}	
}

fn certificates_signing(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_signing_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => error_card_response(e)
	}	
}

fn certificates_rootca(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_rootca_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => error_card_response(e)
	}	
}

fn certificates_ca(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_ca_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => error_card_response(e)
	}	
}

fn certificates_rrn(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_rrn_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => error_card_response(e)
	}	
}

fn connect_card() -> Result<EIdDonkeyCard, u32> {
	EIdDonkeyCard::new()
}

struct RequestPinCode {
	auth: bool,
	nbr_retries: i32,
	data: String
}

struct ResponsePinCode {
	code: u32,
	data: String
}


fn signature_auth(eid_card: EIdDonkeyCard, params: &str) -> String {
	let split_params = params.split("=");
	let vec_params : Vec<&str> = split_params.collect();
	let mut retries: i32 = -1;

	if vec_params.len() <= 1 {
		return error_response_with_msg(MISSING_PARAMETERS, "Missing Parameters".to_string())
	}

	loop {

		let pincode = get_pincode_sign(5, "Test".to_string()).unwrap();

		if pincode.len() == 0 {
			trace!("signature_auth: Authentication of [{:?}]", vec_params[1]);
			let data_res = hex::decode(vec_params[1].to_uppercase().as_bytes());
			match data_res {
				Ok(data) => {
					trace!("signature_auth: Start signing");
					let signature_res = eid_card.sign_with_auth_cert(pincode, &data);

					match signature_res {
						Ok(signature) => return format!("{{\"result\":\"ok\",\"signature\": \"{}\"}}", 
					 								base64::encode(&signature)),
						Err(e) => {
							if (e ^ EIDONKEY_WRONG_PIN_RETRIES_X) > 0 {
								retries = (e ^ EIDONKEY_WRONG_PIN_RETRIES_X) as i32;
							}	
							else {
								return error_card_response(e)
							}
						}
					}
				},
				Err(_) => return error_response_with_msg(INCORRECT_PARAMETERS, "Incorrect Parameters".to_string())
			}
		}
		else {
			return error_response_with_msg(PINCODE_FAILED, pincode)
		}
	}
}

fn signature_sign(eid_card: EIdDonkeyCard, params: &str) -> String {
	let split_params = params.split("=");
	let vec_params : Vec<&str> = split_params.collect();
	let mut retries: i32 = -1;

	if vec_params.len() <= 1 {
		return error_response_with_msg(MISSING_PARAMETERS, "Missing Parameters".to_string())
	}

	loop {

		let pincode = get_pincode_sign(5, "Test".to_string()).unwrap();

		if pincode.len() == 0 {
			trace!("signature_sign: Signing of [{:?}]", vec_params[1]);
			let data_res = hex::decode(vec_params[1].to_uppercase().as_bytes());
			match data_res {
				Ok(data) => {
					trace!("signature_auth: Start signing");
					let signature_res = eid_card.sign_with_sign_cert(pincode, &data);

					match signature_res {
						Ok(signature) => return format!("{{\"result\":\"ok\",\"signature\": \"{}\"}}", 
					 							     base64::encode(&signature)),
						Err(e) => {
							if (e ^ EIDONKEY_WRONG_PIN_RETRIES_X) > 0 {
								retries = (e ^ EIDONKEY_WRONG_PIN_RETRIES_X) as i32;
							}	
							else {
								return error_card_response(e)
							}
						}
					}				
				},
				Err(_) => return error_response_with_msg(INCORRECT_PARAMETERS, "Incorrect Parameters".to_string())
			}
		}
		else {
			return error_response_with_msg(PINCODE_FAILED, pincode)
		}
	}
}

fn call_route_get_handler(uri: &str, params: &str) -> Option<Vec<u8>> {

  trace!("Handling /{} request", uri);
	match uri {
	    "/version" => Some(version().into_bytes()),
	    "/identity" => { 
	    	match connect_card() {
		    	Ok(card) => Some(identity(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/address" => {
	    	match connect_card() {
	    		Ok(card) => Some(address(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/photo" => {
	    	match connect_card() {
	    		Ok(card) => Some(photo(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	} 	
	    },
	    "/status" => {
	    	match connect_card() {
	    		Ok(card) => Some(status(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}	    	
	    },
	    "/signature/authentication" => {
	    	match connect_card() {
	    		Ok(card) => Some(signature_auth(card, params).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/signature/signing" => {
	    	match connect_card() {
	    		Ok(card) => Some(signature_sign(card, params).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/certificates/authentication" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_authentication(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/certificates/signing" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_signing(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/certificates/rootca" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_rootca(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/certificates/ca" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_ca(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    "/certificates/rrn" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_rrn(card).into_bytes()),
		    	Err(e) => Some(error_card_response(e).into_bytes())
	    	}
	    },
	    _ => None,
	}
}

/// Print help function
fn print_usage(program: &str, opts: Options) {
	let brief = format!("Usage: {} [options]", program);
	print!("{}", opts.usage(&brief));
}

fn main() {
	env_logger::init().unwrap();

	let args: Vec<String> = env::args().collect();
	let program = args[0].clone();

	let mut opts = Options::new();
	opts.optflag("h", "help", "print this help menu");
	opts.optopt("p", "path", "the path of the URI", "/status");
	let matches = opts.parse(&args[1..]).unwrap();

	if matches.opt_present("h") {
		print_usage(&program, opts);
		return;
	}

	let path = matches.opt_str("p").unwrap();

	init_pincode();

	// Call route handler
//	let mut uri = String::new();
//	io::stdin().read_to_string(&mut uri);

	trace!("Incoming URI [{}]", path);
	let split_uri = path.split("?");
	let parts_uri: Vec<&str> = split_uri.collect();
	let params = if parts_uri.len() > 1 { parts_uri[1] } else { "" };

	let stdout = io::stdout();
	let mut handle = stdout.lock();

	let body = call_route_get_handler(parts_uri[0], params);
	match body {
	 	Some(ref data) => {

			handle.write(data);
		},
		None => {
			handle.write(b"{ error: 'error'}");			
		}
	}

	
	close_pincode();
}
