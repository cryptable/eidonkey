#[macro_use]
extern crate log;
extern crate env_logger;
extern crate hyper;
extern crate openssl;
extern crate getopts;
extern crate data_encoding;
extern crate eidonkey;

use std::io::Write;
use std::env;
use std::fs::File;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::{SyncSender, Receiver};
use std::thread;

use hyper::server::{Handler,Server,Request,Response};
use hyper::header::{AccessControlAllowOrigin, ContentLength, ContentType};
use hyper::uri::RequestUri;
use hyper::status::StatusCode;

use openssl::asn1::Asn1Time;
use openssl::nid;
use openssl::bn::{BigNum, MSB_MAYBE_ZERO};
use openssl::ssl::{Ssl, SslMethod, SslContext};
use openssl::x509::{X509Builder, X509Name, X509FileType, X509, X509Ref};
use openssl::x509::extension::{Extension, BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use getopts::Options;

use data_encoding::{base64, hex};

use eidonkey::{ EIdDonkeyCard, EIDONKEY_WRONG_PIN_RETRIES_X };

mod pin;
use pin::*;

mod https;
use https::*;

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

// Library of core handler 
const SERVER_CA_CERTIFICATE_FILE: &'static str = "tmpcacert.crt";
const SERVER_CERTIFICATE_FILE: &'static str = "tmpcert.crt";

struct RequestPinCode {
	auth: bool,
	nbr_retries: i32,
	data: String
}

struct ResponsePinCode {
	code: u32,
	data: String
}

struct SenderHandler {
    sender: Mutex<SyncSender<RequestPinCode>>,
    receiver: Mutex<Receiver<ResponsePinCode>>
}

impl SenderHandler {

	fn signature_auth(&self, eid_card: EIdDonkeyCard, params: &str) -> String {
		let split_params = params.split("=");
		let vec_params : Vec<&str> = split_params.collect();
		let mut retries: i32 = -1;

		if vec_params.len() <= 1 {
			return error_response_with_msg(MISSING_PARAMETERS, "Missing Parameters".to_string())
		}

		loop {
			self.sender.lock().unwrap().send(RequestPinCode {auth: true, nbr_retries: retries as i32, data: vec_params[1].to_uppercase()}).unwrap();
			let pincode = self.receiver.lock().unwrap().recv().unwrap();

			if pincode.code == 0 {
				trace!("signature_auth: Authentication of [{:?}]", vec_params[1]);
				let data_res = hex::decode(vec_params[1].to_uppercase().as_bytes());
				match data_res {
					Ok(data) => {
						trace!("signature_auth: Start signing");
						let signature_res = eid_card.sign_with_auth_cert(pincode.data, &data);

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
				return error_response_with_msg(PINCODE_FAILED, pincode.data.to_string())
			}
		}
	}

	fn signature_sign(&self, eid_card: EIdDonkeyCard, params: &str) -> String {
		let split_params = params.split("=");
		let vec_params : Vec<&str> = split_params.collect();
		let mut retries: i32 = -1;

		if vec_params.len() <= 1 {
			return error_response_with_msg(MISSING_PARAMETERS, "Missing Parameters".to_string())
		}

		loop {
			self.sender.lock().unwrap().send(RequestPinCode {auth: false, nbr_retries: retries, data: vec_params[1].to_uppercase()}).unwrap();
			let pincode = self.receiver.lock().unwrap().recv().unwrap();

			if pincode.code == 0 {
				trace!("signature_sign: Signing of [{:?}]", vec_params[1]);
				let data_res = hex::decode(vec_params[1].to_uppercase().as_bytes());
				match data_res {
					Ok(data) => {
						trace!("signature_auth: Start signing");
						let signature_res = eid_card.sign_with_sign_cert(pincode.data, &data);

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
				return error_response_with_msg(PINCODE_FAILED, pincode.data.to_string())
			}
		}
	}

	fn call_route_get_handler(&self, uri: &str, params: &str) -> Option<Vec<u8>> {

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
		    		Ok(card) => Some(self.signature_auth(card, params).into_bytes()),
			    	Err(e) => Some(error_card_response(e).into_bytes())
		    	}
		    },
		    "/signature/signing" => {
		    	match connect_card() {
		    		Ok(card) => Some(self.signature_sign(card, params).into_bytes()),
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

	fn get_handler(&self, req: Request, mut res: Response) {

	 	match req.uri {
	 		RequestUri::AbsolutePath(ref uri) => {

		 		trace!("Incoming URI [{}]", uri);
				let split_uri = uri.split("?");
				let parts_uri: Vec<&str> = split_uri.collect();
				let params = if parts_uri.len() > 1 { parts_uri[1] } else { "" };

	 			let body = self.call_route_get_handler(parts_uri[0], params);
	 			match body {
	 				Some(ref data) => {
	 					// Headers when call succeeded
					 	res.headers_mut().set(ContentType::json());
					 	res.headers_mut().set(ContentLength(data.len() as u64));
						let mut res = res.start().unwrap();
					    res.write_all(data).unwrap();
					},
	 				None => *res.status_mut() = StatusCode::NotFound
	 			}
	 		},
			_ => *res.status_mut() = StatusCode::InternalServerError
	 	}
	}
}

impl Handler for SenderHandler {

	fn handle(&self, req: Request, mut res: Response) {
		// Headers for all requests
		res.headers_mut().set(
	    	AccessControlAllowOrigin::Any
		);

		match req.method {
		    hyper::Get => {
		    	self.get_handler( req, res);
	        },
	        _ => *res.status_mut() = StatusCode::MethodNotAllowed
		}
	}

}

fn start_server(http_req: Mutex<SyncSender<RequestPinCode>>, http_resp: Mutex<Receiver<ResponsePinCode>>) {
	let (cert, pkey, ca) = generate_signed_certificate();

    let ssl = HttpsServer::from_memory(&pkey, &cert, &ca).unwrap();
	Server::https("127.0.0.1:10443", ssl).unwrap().handle(SenderHandler {
		sender: http_req,
		receiver: http_resp
	}).unwrap();
}

/// Print help function
fn print_usage(program: &str, opts: Options) {
	let brief = format!("Usage: {} [options]", program);
	print!("{}", opts.usage(&brief));
}

fn register_eidonkey() {
	let output = Command::new("bash")
	                     .arg("./post-startup-eidonkey")
	                     .output()
	                     .unwrap_or_else(|e| { panic!("failed to execute process: {}", e) });
}

fn pkey() -> PKey {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

/// Generate self-signed certificate command
/// It creates 2 files in the current directory:
fn generate_signed_certificate() -> (X509, PKey, X509) {
	
	// Create CA certificate
	let ca_pkey = pkey();

	let mut ca_gen = X509::builder().unwrap();
	ca_gen.set_version(2).unwrap();

    let mut ca_name = X509Name::builder().unwrap();
    ca_name.append_entry_by_nid(nid::COMMONNAME, "My eidonkey CA").unwrap();
    let ca_name = ca_name.build();
    ca_gen.set_subject_name(&ca_name).unwrap();
    ca_gen.set_issuer_name(&ca_name).unwrap();

	ca_gen.set_not_before(&Asn1Time::days_from_now(0).unwrap());
    ca_gen.set_not_after(&Asn1Time::days_from_now(365*10).unwrap());

	let mut serial = BigNum::new().unwrap();
    serial.rand(128, MSB_MAYBE_ZERO, false).unwrap();
    ca_gen.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();

    ca_gen.set_pubkey(&ca_pkey).unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    ca_gen.append_extension(basic_constraints).unwrap();

    let ca_key_usage = KeyUsage::new().key_cert_sign().crl_sign().build().unwrap();
    ca_gen.append_extension(ca_key_usage).unwrap();
    
    let ca_subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&ca_gen.x509v3_context(None, None))
        .unwrap();
    ca_gen.append_extension(ca_subject_key_identifier).unwrap();

    let ca_authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&ca_gen.x509v3_context(None, None))
        .unwrap();
    let cert_authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&ca_gen.x509v3_context(None, None))
        .unwrap();    ca_gen.append_extension(ca_authority_key_identifier).unwrap();

    ca_gen.sign(&ca_pkey, MessageDigest::sha256()).unwrap();

    let ca = ca_gen.build();

	let ca_path = SERVER_CA_CERTIFICATE_FILE;
	let mut file = File::create(ca_path).unwrap();
	assert!(file.write_all(&ca.to_pem().unwrap()).is_ok());

	// local host generator
	let cert_pkey = pkey();
	let mut cert_gen = X509::builder().unwrap();
	cert_gen.set_version(2).unwrap();

    let mut cert_name = X509Name::builder().unwrap();
    cert_name.append_entry_by_nid(nid::COMMONNAME, "localhost").unwrap();
    let cert_name = cert_name.build();
    cert_gen.set_subject_name(&cert_name).unwrap();
    cert_gen.set_issuer_name(&ca_name).unwrap();

	cert_gen.set_not_before(&Asn1Time::days_from_now(0).unwrap());
    cert_gen.set_not_after(&Asn1Time::days_from_now(365*10).unwrap());

    serial.rand(128, MSB_MAYBE_ZERO, false).unwrap();
    cert_gen.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    
    cert_gen.set_pubkey(&cert_pkey).unwrap();

    let cert_key_usage = KeyUsage::new().digital_signature().key_encipherment().data_encipherment().build().unwrap();
    cert_gen.append_extension(cert_key_usage).unwrap();
    
    let cert_subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_gen.x509v3_context(None, None))
        .unwrap();
    cert_gen.append_extension(cert_subject_key_identifier).unwrap();

    cert_gen.append_extension(cert_authority_key_identifier).unwrap();

    let ext_key_usage = ExtendedKeyUsage::new().server_auth().build().unwrap();
    cert_gen.append_extension(ext_key_usage).unwrap();

    cert_gen.sign(&ca_pkey, MessageDigest::sha256()).unwrap();

    let cert = cert_gen.build();

	let cert_path = SERVER_CERTIFICATE_FILE;
	let mut file = File::create(cert_path).unwrap();
	assert!(file.write_all(&cert.to_pem().unwrap()).is_ok());

	register_eidonkey();

	(cert, cert_pkey, ca)
}

fn main() {
	env_logger::init().unwrap();

	let args: Vec<String> = env::args().collect();
	let program = args[0].clone();

	let mut opts = Options::new();
	opts.optflag("h", "help", "print this help menu");
	let matches = opts.parse(&args[1..]).unwrap();

	if matches.opt_present("h") {
		print_usage(&program, opts);
		return;
	}

	// Start service
	let (req_tx, req_rx) = sync_channel::<RequestPinCode>(0);
	let (resp_tx, resp_rx) = sync_channel::<ResponsePinCode>(0);

	let http_child = thread::spawn(move || {
		start_server(Mutex::new(req_tx), Mutex::new(resp_rx));
	});

	init_pincode();
	
	loop {
		let pin_code: ResponsePinCode;
		let pin_code_res: Result<String, u32>;
		trace!("Waiting for PINcode");
		let req  = req_rx.recv().unwrap();
		trace!("Request PIN code nbr retries: {}", req.nbr_retries);
		trace!("Request PIN code data: {}", req.data);
		if req.auth == true {
			trace!("Request PIN for authentication: {}", req.nbr_retries);
			pin_code_res = get_pincode_auth(req.nbr_retries);
		}
		else {
			trace!("Request PIN for signature: {}", req.nbr_retries);
			pin_code_res = get_pincode_sign(req.nbr_retries, req.data);
		}
		match pin_code_res {
			Ok(pin) => {
				pin_code = ResponsePinCode { code:0, data:pin }
			},
			Err(code) => {
				trace!("Request PIN failed code: {}", code);
				if code == 101 {
					pin_code = ResponsePinCode { code:PINCODE_FAILED, data:"Getting the pincode failed (Invalid parameters).".to_string() }
				}
				else {
					pin_code = ResponsePinCode { code:PINCODE_CANCELLED, data:"PIN code was not entered.".to_string() }
				}
			}
		}
		trace!("Sending PIN code {:?}:{:?}", pin_code.code, pin_code.data);
		resp_tx.send(pin_code).unwrap();
	}

	close_pincode();

	let res = http_child.join();
}
