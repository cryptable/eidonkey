extern crate hyper;
extern crate openssl;
extern crate getopts;
extern crate donkeycard;

use std::io::Write;
use std::env;
use std::fs::File;

use hyper::server::{Server,Request,Response};
use hyper::header::{AccessControlAllowOrigin, ContentLength, ContentType};
use hyper::net::Openssl;
use hyper::uri::RequestUri;
use hyper::status::StatusCode;

use openssl::crypto::hash::Type;
use openssl::x509::X509Generator;
use openssl::x509::extension::{Extension, KeyUsageOption, ExtKeyUsageOption};

use getopts::Options;

use donkeycard::EIdDonkeyCard;

fn sign() -> String {
    "{\"result\":\"nok\",\"reason\":\"not_implemented\"}".to_string()
}

fn version() -> String {
    "{\"result\":\"ok\",\"version\":\"0.1.0\"}".to_string()
}

fn identity() -> String {
	let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
	let eid_card = EIdDonkeyCard::new(reader).unwrap();
	let identity = eid_card.read_identity().unwrap();

	format!("{{\"result\":\"ok\",\"identity\":{{\"card_number\":\"{}\",\
	 		\"validity_begin\":\"{}\",\
	 		\"validity_end\":\"{}\",\
	 		\"delivery_municipality\":\"{}\",\
	 		\"national_number\":\"{}\",\
	 		\"name\":\"{}\",\
	 		\"third_first_name\":\"{}\",\
	 		\"nationality\":\"{}\",\
	 		\"birth_location\":\"{}\",\
	 		\"birth_date\":\"{}\",\
	 		\"sex\":\"{}\",\
	 		\"document_type\":\"{}\"}}}}", 
	 							identity.card_number, 
	 							identity.validity_begin, 
	 							identity.validity_end, 
	 							identity.delivery_municipality, 
	 							identity.national_number, 
	 							identity.name, 
	 							identity.third_first_name, 
	 							identity.nationality, 
	 							identity.birth_location, 
	 							identity.birth_date, 
	 							identity.sex, 
	 							identity.document_type)
}

fn address() -> String {
	let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
	let eid_card = EIdDonkeyCard::new(reader).unwrap();
	let address = eid_card.read_address().unwrap();

	format!("{{\"result\":\"ok\",\"identity\":{{\"address\":\"{}\"}}}}", 
	 							address.address)
}

// Library of core handler 
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

fn call_route_get_handler(uri: &str) -> Option<Vec<u8>> {
	match uri {
	    "/version" => Some(version().into_bytes()),
	    "/identity" => Some(identity().into_bytes()),
	    "/address" => Some(address().into_bytes()),
	    _ => None,
	}
}

fn get_handler(req: Request, mut res: Response) {

 	match req.uri {
 		RequestUri::AbsolutePath(ref path) => {

 			let body = call_route_get_handler(path);
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

fn start_server() {
	let ssl = Openssl::with_cert_and_key("./cert.crt", "./cert.key").unwrap();
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

	let cert_path = "cert.crt";
	let mut file = File::create(cert_path).unwrap();
	assert!(cert.write_pem(&mut file).is_ok());

	let pkey_path = "cert.key";
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
