extern crate hyper;
extern crate openssl;
extern crate getopts;
extern crate data_encoding;
extern crate eidonkey;

use std::io::Write;
use std::env;
use std::fs::File;
use std::sync::Arc;

use hyper::server::{Server,Request,Response};
use hyper::header::{AccessControlAllowOrigin, ContentLength, ContentType};
use hyper::uri::RequestUri;
use hyper::status::StatusCode;
use hyper::net::Openssl;

use openssl::ssl::{SslMethod, SslContext};
use openssl::x509::{X509Generator, X509FileType};
use openssl::x509::extension::{Extension, KeyUsageOption, ExtKeyUsageOption};
use openssl::crypto::hash::Type;

use getopts::Options;

use data_encoding::{base64, hex};

use eidonkey::EIdDonkeyCard;

fn sign() -> String {
    "{\"result\":\"nok\",\"reason\":\"not_implemented\"}".to_string()
}

fn version() -> String {
    "{\"result\":\"ok\",\"version\":\"0.1.0\"}".to_string()
}

fn identity(eid_card: EIdDonkeyCard) -> String {

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
								 		\"special_status\":\"{}\",
								 		\"hash_photo\":\"{}\"\
								 	}},
									\"identity_raw\":\"{}\",
									\"signature\":\"{}\"		 	
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
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e))
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
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e))
	}	
}

fn photo(eid_card: EIdDonkeyCard) -> String {
	let photo_res = eid_card.read_photo();

	match photo_res {
		Ok(photo) => format!("{{\"result\":\"ok\",\"photo\":\"{}\"}}", 
	 							base64::encode(&photo)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn status(eid_card: EIdDonkeyCard) -> String {
	let status_res = eid_card.get_status();

	match status_res {
		Ok(status) => format!("{{\"result\":\"ok\",\"status\":
									{{\"reader_name\":\"{}\",\
										\"protocol\":\"{}\",\
										\"atr\":\"{}\"\
									}}\
								}}", 
	 							status.reader_name,
	 							status.protocol,
	 							base64::encode(&status.atr)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn signature_auth(eid_card: EIdDonkeyCard, params: &str) -> String {
	let split_params = params.split("=");
	let vec_params : Vec<&str> = split_params.collect();

	if vec_params.len() <= 1 {
		return format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", 501,  "Bad data format")
	}

	println!("{:?}", vec_params[1]);
	// TODO: fix unwrap
	let data = hex::decode(vec_params[1].to_uppercase().as_bytes()).unwrap();
	println!("Start signing");
	let signature_res = eid_card.sign_with_auth_cert(&data);

	match signature_res {
		Ok(signature) => format!("{{\"result\":\"ok\",\"signature\": \"{}\"}}", 
	 							base64::encode(&signature)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn signature_sign(eid_card: EIdDonkeyCard, params: &str) -> String {
	let split_params = params.split("=");
	let vec_params : Vec<&str> = split_params.collect();

	if vec_params.len() <= 1 {
		return format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", 501,  "Bad data format")
	}

	println!("{:?}", vec_params[1]);
	// TODO: fix unwrap
	let data = hex::decode(vec_params[1].to_uppercase().as_bytes()).unwrap();
	println!("Start signing");
	let signature_res = eid_card.sign_with_sign_cert(&data);

	match signature_res {
		Ok(signature) => format!("{{\"result\":\"ok\",\"signature\": \"{}\"}}", 
	 							base64::encode(&signature)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn certificates_authentication(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_authentication_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn certificates_signing(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_signing_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn certificates_rootca(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_rootca_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn certificates_ca(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_ca_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

fn certificates_rrn(eid_card: EIdDonkeyCard) -> String {
	let cert_res = eid_card.read_rrn_cert();

	match cert_res {
		Ok(cert) => format!("{{\"result\":\"ok\",\"certificate\":\"{}\"}}", 
	 							base64::encode(&cert)),
		Err(e) => format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e))
	}	
}

// Library of core handler 
const SERVER_CERTIFICATE_FILE: &'static str = "cert.crt";
const SERVER_PRIVATE_KEY_FILE: &'static str = "cert.key";

fn call_route_post_handler(uri: &str) -> Option<Vec<u8>> {
	match uri {
	    "/sign" => Some(sign().into_bytes()),
	    _ => None,
	}
}

fn post_handler(req: Request, mut res: Response) {

 	match req.uri {
 		RequestUri::AbsolutePath(ref path) => {

 			let body = call_route_post_handler(path);
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

fn connect_card() -> Result<EIdDonkeyCard, u32> {
	let reader = EIdDonkeyCard::list_readers();
	match reader {
		Ok(readers) => Ok(EIdDonkeyCard::new(&readers[0])),
		Err(e) => Err(e)
	}
}

fn call_route_get_handler(uri: &str, params: &str) -> Option<Vec<u8>> {

	match uri {
	    "/version" => Some(version().into_bytes()),
	    "/identity" => { 
	    	match connect_card() {
		    	Ok(card) => Some(identity(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e,  EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/address" => {
	    	match connect_card() {
	    		Ok(card) => Some(address(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/photo" => {
	    	match connect_card() {
	    		Ok(card) => Some(photo(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	} 	
	    },
	    "/status" => {
	    	match connect_card() {
	    		Ok(card) => Some(status(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}	    	
	    },
	    "/signature/authentication" => {
	    	match connect_card() {
	    		Ok(card) => Some(signature_auth(card, params).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/signature/signing" => {
	    	match connect_card() {
	    		Ok(card) => Some(signature_sign(card, params).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/certificates/authentication" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_authentication(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/certificates/signing" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_signing(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/certificates/rootca" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_rootca(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/certificates/ca" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_ca(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    "/certificates/rrn" => {
	    	match connect_card() {
	    		Ok(card) => Some(certificates_rrn(card).into_bytes()),
		    	Err(e) => Some(format!("{{\"result\":\"nok\",\
			     			\"error_code\":\"{}\",\
			     			\"error_msg\":\"{}\"\
			     			}}", e, EIdDonkeyCard::get_error_message(e)).into_bytes())
	    	}
	    },
	    _ => None,
	}
}

fn get_handler(req: Request, mut res: Response) {

 	match req.uri {
 		RequestUri::AbsolutePath(ref uri) => {

	 		println!("Incoming URI [{}]", uri);
			let split_uri = uri.split("?");
			let parts_uri: Vec<&str> = split_uri.collect();
			let params = if parts_uri.len() > 1 { parts_uri[1] } else { "" };

 			let body = call_route_get_handler(parts_uri[0], params);
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

fn main_handler(req: Request, mut res: Response) {
	// Headers for all requests
	res.headers_mut().set(
    	AccessControlAllowOrigin::Any
	);

	match req.method {
	    hyper::Post => {
	    	post_handler(req, res);
        },
	    hyper::Get => {
	    	get_handler(req, res);
        },
        _ => *res.status_mut() = StatusCode::MethodNotAllowed
	}
}

// Thighten the SSL server protocols: TLS1.2 only
fn start_server() {
	let mut ssl_ctx = SslContext::new(SslMethod::Tlsv1_2).unwrap();
	ssl_ctx.set_cipher_list("AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256");
    ssl_ctx.set_certificate_file(SERVER_CERTIFICATE_FILE, X509FileType::PEM).unwrap();
    ssl_ctx.set_private_key_file(SERVER_PRIVATE_KEY_FILE, X509FileType::PEM).unwrap();
    let ssl = Openssl { context: Arc::new(ssl_ctx) };
	Server::https("127.0.0.1:8443", ssl).unwrap().handle(main_handler).unwrap();
}

/// Print help function
fn print_usage(program: &str, opts: Options) {
	let brief = format!("Usage: {} [options]", program);
	print!("{}", opts.usage(&brief));
}

/// Generate self-signed certificate command
/// It creates 2 files in the current directory:
/// - cert.pem : self-signed certificate
/// - cert.key : unprotected private key
fn generate_self_signed_certificate() {
	let gen = X509Generator::new()
		.set_bitlength(2048)
		.set_valid_period(365*10)
		.add_name("CN".to_owned(), "localhost".to_owned())
		.set_sign_hash(Type::SHA256)
		.add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature,KeyUsageOption::KeyEncipherment,KeyUsageOption::DataEncipherment]))
		.add_extension(Extension::ExtKeyUsage(vec![ExtKeyUsageOption::ServerAuth]));

	let (cert, pkey) = gen.generate().unwrap();

	let cert_path = SERVER_CERTIFICATE_FILE;
	let mut file = File::create(cert_path).unwrap();
	assert!(cert.write_pem(&mut file).is_ok());

	let pkey_path = SERVER_PRIVATE_KEY_FILE;
	let mut file = File::create(pkey_path).unwrap();
	assert!(pkey.write_pem(&mut file).is_ok());
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let program = args[0].clone();

	let mut opts = Options::new();
	opts.optflag("g", "gencert", "Generate self-signed certificate");
	opts.optflag("h", "help", "print this help menu");
	let matches = opts.parse(&args[1..]).unwrap();

	if matches.opt_present("h") {
		print_usage(&program, opts);
		return;
	}

	if matches.opt_present("g") {
		generate_self_signed_certificate();
		return;
	}

	// Start service
	start_server();
}
