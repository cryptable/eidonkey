#[macro_use]
extern crate log;
extern crate libc;
#[macro_use]
extern crate lazy_static;
mod card;
use std::io::prelude::*;
use std::fs::File;
use std::sync::{Mutex, Arc};
use std::sync::MutexGuard;
use std::{mem};

use card::*;
use card::pcsc::*;

const AUTH_KEYID: u8 = 0x82;
const SIGN_KEYID: u8 = 0x83;

const SHA1_PSS: u8 = 0x10;
const SHA256_PSS: u8 = 0x20;
const PKCS1: u8 = 0x01; 

static IDENTITY_FILE_ID: &'static[u8]		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31];
static IDENTITY_SIGN_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x32];
static ADDRESS_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33];
static ADDRESS_SIGN_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x34];
static PHOTO_FILE_ID: &'static[u8] 			= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x35];
static AUTHN_CERT_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x00, 0x50, 0x38];
static SIGN_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x00, 0x50, 0x39];
static CA_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x00, 0x50, 0x3A];
static ROOT_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x00, 0x50, 0x3B];
static RRN_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x00, 0x50, 0x3C];
const TAG_TWO_FIRST_FIRST_NAMES: u8         = 8;
const TAG_NOBLE_CONDITION: u8               = 14;
const TAG_SPECIAL_STATUS: u8                = 16;

pub const EIDONKEY_BASE_ERROR: u32 				= 0x80120000;
pub const EIDONKEY_READ_ERROR: u32 				= 0x80120001;
pub const EIDONKEY_SIGN_ERROR: u32 				= 0x80120002;
pub const EIDONKEY_VERIFY_ERROR: u32			= 0x80120003;
pub const EIDONKEY_WRONG_PIN_RETRIES_X: u32		= 0x801200C0;
pub const EIDONKEY_WRONG_PIN_RETRIES_1: u32		= 0x801200C1;
pub const EIDONKEY_WRONG_PIN_RETRIES_2: u32		= 0x801200C2;
pub const EIDONKEY_WRONG_PIN_RETRIES_3: u32		= 0x801200C3;
pub const EIDONKEY_WRONG_PIN_RETRIES_4: u32		= 0x801200C4;
pub const EIDONKEY_WRONG_PIN_RETRIES_5: u32		= 0x801200C5;
pub const EIDONKEY_WRONG_PIN_RETRIES_6: u32		= 0x801200C6;
pub const EIDONKEY_WRONG_PIN_RETRIES_7: u32		= 0x801200C7;
pub const EIDONKEY_WRONG_PIN_RETRIES_8: u32		= 0x801200C8;
pub const EIDONKEY_WRONG_PIN_RETRIES_9: u32		= 0x801200C9;
pub const EIDONKEY_WRONG_PIN_RETRIES_10: u32	= 0x801200CA;
pub const EIDONKEY_WRONG_PIN_RETRIES_11: u32	= 0x801200CB;
pub const EIDONKEY_WRONG_PIN_RETRIES_12: u32	= 0x801200CC;
pub const EIDONKEY_WRONG_PIN_RETRIES_13: u32	= 0x801200CD;
pub const EIDONKEY_WRONG_PIN_RETRIES_14: u32	= 0x801200CE;
pub const EIDONKEY_WRONG_PIN_RETRIES_15: u32	= 0x801200CF;
pub const EIDONKEY_CARD_BLOCKED: u32			= 0x801200C0;

#[derive(Clone)]
pub struct EIdDonkeyCard {
	card_handle: Arc<Mutex<DonkeyCardConnect>>,
}

pub struct EIdIdentity {
	pub card_number: String,
	pub chip_number: Vec<u8>,
	pub validity_begin: String,
	pub validity_end: String,
	pub delivery_municipality: String,
	pub national_number: String,
	pub name: String,
	pub second_first_name: Option<String>,
	pub third_first_name: String,
	pub nationality: String,
	pub birth_location: String,
	pub birth_date: String,
	pub sex: String,
	pub noble_condition: Option<String>,
	pub document_type: String,
	pub special_status: Option<String>,
	pub hash_photo: Vec<u8>,
	pub identity: Vec<u8>,
	pub signature: Vec<u8>,
}

pub struct EIdAddress {
	pub street: String,
	pub zip_code: String,
	pub city: String,
	pub address: Vec<u8>,
	pub signature: Vec<u8>,
}

pub struct EIdStatus {
	pub reader_name: String,
	pub protocol: String,
	pub atr: Vec<u8>,
}


fn convert_validity_date(date: &String) -> String {
	let v: Vec<&str> = date.split(".").collect();
	format!("{}-{}-{}", v[2], v[1], v[0])
}

fn convert_birth_date(date: &String) -> String {
	let v: Vec<&str> = date.split(|c| c == ' ' || c == '.').collect();
	let month = v[1];
	let mut MM: &str;
	if month == "JAN" {
		MM = "01";
	}
	else if month == "FEB" || month == "FEV" {
		MM = "02";
	}
	else if month == "MARS" || month == "MÄR" || month == "MAAR" {
		MM = "03";
	}
	else if month == "AVR" || month == "APR" {
		MM = "04";
	}
	else if month == "MAI" || month == "MEI" {
		MM = "05";
	}
	else if month == "JUN" || month == "JUIN" {
		MM = "06";
	}
	else if month == "JUL" || month == "JUIL" {
		MM = "07";
	}
	else if month == "AOUT" || month == "AUG" {
		MM = "08";
	}
	else if month == "SEP" || month == "SEPT" {
		MM = "09";
	}
	else if month == "OCT" || month == "OKT" {
		MM = "10";
	}
	else if month == "NOV" {
		MM = "11";
	}
	else {
		MM = "12";
	}

	format!("{}-{}-{}", v[2], MM, v[0])
}

fn get_data_len(data: & Vec<u8>, offset: usize) -> (u32, u32) {
	let mut result: u32 = 0;
	let mut i = offset;
	while data[i] == 0xFF {
		result = result * data[i] as u32 + 255;
		i = i + 1;
	}
	result = result + data[i] as u32;
	(result, (i as u32 - offset as u32 + 1))
}

fn copy_vector(data: & Vec<u8>, offset: usize, len: u32) -> Vec<u8> {
	let mut result: Vec<u8> = Vec::new();
	let mut i = 0;
	while i<len {
		result.push(data[offset + i as usize]);
		i = i + 1;
	}
	
	result
}

fn copy_vector_to_gender(data: & Vec<u8>, offset: usize, len: u32) -> String {
	match data[0] as char {
		'M' => "M".to_string(),
		'F' => "F".to_string(),
		'V' => "F".to_string(),
		'W' => "F".to_string(),
		_ => "U".to_string()
	}
}

fn copy_vector_to_string(data: & Vec<u8>, offset: usize, len: u32) -> String {
	String::from_utf8(copy_vector(data, offset, len)).unwrap()
}

fn get_protocol_string(prot: u32) -> String {
	match prot {
		SCARD_PROTOCOL_T0 => "Active protocol T=0".to_string(),
		SCARD_PROTOCOL_T1 => "Active protocol T=1".to_string(),
		SCARD_PROTOCOL_T15 => "Active protocol T=15".to_string(),
		SCARD_PROTOCOL_RAW => "Active protocol RAW".to_string(),
		SCARD_PROTOCOL_ANY => "Active protocol ANY(T=0 and T=1)".to_string(),
		_ => "Unknown active protocol".to_string()
	}
}

fn get_response(card_handle: MutexGuard<DonkeyCardConnect>,len: u8, response: &mut Vec<u8>) -> Result< Vec<u8>, u32> {
	let mut get_cmd: Vec<u8> = vec![0x00, 0xC0, 0x00, 0x00, len];
	trace!("get_response: get response len [{:02X}]", len);

	let result = card_handle.transmit(&get_cmd);
	match result {
		Ok(resp) => {
			trace!("select: Get response finished {:X}:{:X}", resp.sw[0], resp.sw[1]);
			let mut copy_data = resp.data.clone();
			response.append(&mut copy_data);
			if (resp.sw[0] == 0x90) && (resp.sw[1] == 0x00) {
				let copy_response = response.clone();
				Ok(copy_response)
			}
			else {
				if resp.sw[0] == 0x61 {
					if resp.sw[1] == 0x00 {
						get_response(card_handle, 0xFF, response)
					}
					else {
						get_response(card_handle, resp.sw[1], response)
					}
				}
				else {
					Err(EIDONKEY_READ_ERROR)
				}
			}
		},
		Err(e) => Err(e),
	}
}

lazy_static! {
	pub static ref EIDDONKEYCARD_LOCK: Mutex<()> = Mutex::new(());
}

impl EIdDonkeyCard {

	pub fn list_readers() -> Result< Vec<String> , u32> {
		DonkeyCard::new().and_then(|con| con.list_readers())
	}

	pub fn get_error_message(e: u32) -> String {
		match e {
			SCARD_W_REMOVED_CARD => "eId card was removed, please re-insert your eId card".to_string(),
			SCARD_W_UNSUPPORTED_CARD => "Unsupported card, insert your eId card".to_string(),
			SCARD_E_NO_READERS_AVAILABLE => "No readers unavailable, attach your reader".to_string(),
			SCARD_E_SERVICE_STOPPED => "PCSC service stopped, restart your service or computer".to_string(),
			SCARD_E_NO_SERVICE => "No PCSC service detected, install the pcsc driver of the reader".to_string(),
			SCARD_E_CARD_UNSUPPORTED => "Smart card unsupported, insert your eId card".to_string(),
			SCARD_E_READER_UNSUPPORTED => "Reader unsupported, attach a valid reader".to_string(),
			SCARD_E_READER_UNAVAILABLE => "Reader unavailable, (re)attach your reader".to_string(),
			SCARD_E_UNKNOWN_CARD => "Unknown eId, insert the correct eId card".to_string(),
			SCARD_E_NO_SMARTCARD => "No eId, insert your eId card".to_string(),
			SCARD_E_UNKNOWN_READER => "Unkown PCSC reader, attached a valid reader".to_string(),
			SCARD_F_INTERNAL_ERROR => "Internal Error".to_string(),
			EIDONKEY_READ_ERROR => "Read error from smartcard".to_string(),
			_ => "Unknown error".to_string()
		}
	}

	pub fn new(reader : & String) -> Result<EIdDonkeyCard, u32> {
		unsafe {
			static mut EIDONKEYCARD_SINGLETON : *const EIdDonkeyCard = 0 as *const EIdDonkeyCard;
			let _g = EIDDONKEYCARD_LOCK.lock().unwrap();

			let handle_res = DonkeyCardConnect::new(reader);
			match handle_res {
				Ok(handle) => {
					if EIDONKEYCARD_SINGLETON == 0 as *const EIdDonkeyCard {
						let eidonkeycard = EIdDonkeyCard {
									card_handle: Arc::new(Mutex::new(handle)),
								};
						EIDONKEYCARD_SINGLETON = mem::transmute(Box::new(eidonkeycard));
					}
					Ok((*EIDONKEYCARD_SINGLETON).clone())
				},
				Err(e) => {
					if EIDONKEYCARD_SINGLETON != 0 as *const EIdDonkeyCard {
						drop(EIDONKEYCARD_SINGLETON);
						EIDONKEYCARD_SINGLETON = 0 as *const EIdDonkeyCard;
					}
					Err(e)
				}
			}
		}
	}

	fn read_file(&self, file_loc: &[u8]) -> Result< Vec<u8>, u32> {

		let card_handle = self.card_handle.lock().unwrap();
		let result = card_handle.transmit(&file_loc.to_vec());
		match result {
			Ok(resp) => {
				let read_length: usize = 0xFD;
				let mut data: Vec<u8> = Vec::new();
				let mut read_command: Vec<u8> = vec![0x00, 0xB0, 0x00, 0x00, 0xFD ];
				loop {
					let mut result = card_handle.transmit(&read_command);

					match result {
						Ok(resp) => {
							if resp.sw[0] == 0x6C {
								// ZETES reader wants exact length
								// Invalid length, set new length and try again
								read_command[4] = resp.sw[1];
								continue
							}
							if (resp.sw[0] != 0x90) && (resp.sw[1] != 0x00) {
								print!("Error code: {:.*X}{:.*X}\n", 2, resp.sw[0], 2, resp.sw[1]);
								return Err(EIDONKEY_READ_ERROR)
							}
							if resp.data.len() == 0 {
								return Ok(data);
							}
							else if resp.data.len() < read_length {
								data.extend_from_slice(&(resp.data));
								return Ok(data);
							}
							else {
								data.extend_from_slice(&(resp.data));
							}
							// Update offset
							read_command[2] = ((data.len() >> 8) & 0xFF) as u8;
							read_command[3] = data.len() as u8;
						},
						Err(e) => return Err(e)
					}
				}
			},
			Err(e) => Err(e)
		}
	}

	pub fn read_identity(&self) -> Result< EIdIdentity, u32> {
		let id_res = self.read_file(IDENTITY_FILE_ID);
		match id_res {
			Ok(id) => {
				let id_sig_res = self.read_file(IDENTITY_SIGN_FILE_ID);
				match id_sig_res {
					Ok(id_sig) => {
						let mut pos: usize = 0;
						trace!("card_number tag : {}", id[pos]);
						pos = pos + 1;
						let mut len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_card_number = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("chip_number tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let v_chip_number = copy_vector(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("validity_begin tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_validity_begin = convert_validity_date(&copy_vector_to_string(&id, pos, len.0));
						pos = pos + len.0 as usize;
						trace!("validity_end tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_validity_end = convert_validity_date(&copy_vector_to_string(&id, pos, len.0));
						pos = pos + len.0 as usize;
						trace!("delivery_municipality tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_delivery_municipality = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("national_number tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_national_number = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("name tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_name = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let mut s_second_first_name : Option<String>;
						if id[pos] == TAG_TWO_FIRST_FIRST_NAMES {
							trace!("second_first_name tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							trace!("pos : {}", pos);
							s_second_first_name = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_second_first_name = None;							
						}
						trace!("third_first_name tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_third_first_name = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("nationality tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_nationality = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("birth_location tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_birth_location = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("birth_date tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_birth_date = convert_birth_date(&copy_vector_to_string(&id, pos, len.0));
						pos = pos + len.0 as usize;
						trace!("sex tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_sex = copy_vector_to_gender(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let mut s_noble_condition : Option<String>;
						if id[pos] == TAG_NOBLE_CONDITION {
							trace!("noble_condition tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							trace!("pos : {}", pos);
							s_noble_condition = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_noble_condition = None;
						}
						trace!("document_type tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_document_type = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let s_special_status: Option<String>;
						if id[pos] == TAG_SPECIAL_STATUS {
							trace!("special_status tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							trace!("pos : {}", pos);
							s_special_status = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_special_status = None;
						}
						trace!("hash_photo tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let v_hash_photo = copy_vector(&id, pos, len.0);

						Ok(EIdIdentity {
							card_number: s_card_number,
							chip_number: v_chip_number,
							validity_begin: s_validity_begin,
							validity_end: s_validity_end,
							delivery_municipality: s_delivery_municipality,
							national_number: s_national_number,
							name: s_name,
							second_first_name: s_second_first_name,
							third_first_name: s_third_first_name,
							nationality: s_nationality,
							birth_location: s_birth_location,
							birth_date: s_birth_date,
							sex: s_sex,
							noble_condition: s_noble_condition,
							document_type: s_document_type,
							special_status: s_special_status,
							hash_photo: v_hash_photo,
							identity: id,
							signature: id_sig
						})
					},
					Err(e) => Err(e),
				}
			},
			Err(e) => Err(e),
		}
	}

	pub fn read_address(&self) -> Result< EIdAddress, u32> {
		let address_res = self.read_file(ADDRESS_FILE_ID);
		match address_res {
			Ok(addr) => {
				let address_sig_res = self.read_file(ADDRESS_SIGN_FILE_ID);
				match address_sig_res {
					Ok(address_sig) => {
						let mut pos: usize = 0;
						trace!("street tag : {}", addr[pos]);
						pos = pos + 1;
						let mut len = get_data_len(&addr, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_street = copy_vector_to_string(&addr, pos, len.0);
						trace!("street : {}", s_street);
						pos = pos + len.0 as usize;
						trace!("postal code tag : {}", addr[pos]);
						pos = pos + 1;
						len = get_data_len(&addr, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_zip_code = copy_vector_to_string(&addr, pos, len.0);
						pos = pos + len.0 as usize;
						trace!("city tag : {}", addr[pos]);
						pos = pos + 1;
						len = get_data_len(&addr, pos);
						pos = pos + len.1 as usize;
						trace!("pos : {}", pos);
						let s_city = copy_vector_to_string(&addr, pos, len.0);
						Ok(EIdAddress{
							street: s_street,
							zip_code: s_zip_code,
							city: s_city,
							address: addr,
							signature: address_sig			
						})
					},
					Err(e) => Err(e),
				}
			},
			Err(e) => Err(e),
		}
	}

	pub fn read_photo(&self) -> Result< Vec<u8>, u32> {
		let photo_res = self.read_file(PHOTO_FILE_ID);
		match photo_res {
			Ok(img) => {
				Ok(img)
			},
			Err(e) => Err(e),
		}
	}

	pub fn get_status(&self) -> Result< EIdStatus, u32> {
		let card_handle = self.card_handle.lock().unwrap();
		let status_res = card_handle.status();

		match status_res {
			Ok(status) => Ok(EIdStatus {
				reader_name: status.reader_name.clone(),
				protocol: get_protocol_string(status.protocol as u32),
				atr: status.atr.clone()
			}),
			Err(e) => Err(e),
		}
	}

	pub fn read_authentication_cert(&self) -> Result< Vec<u8>, u32> {
		let cert_auth_res = self.read_file(AUTHN_CERT_FILE_ID);
		match cert_auth_res {
			Ok(certificate) => Ok(certificate),
			Err(e) => Err(e),
		}
	}

	pub fn read_signing_cert(&self) -> Result< Vec<u8>, u32> {
		let cert_sign_res = self.read_file(SIGN_CERT_FILE_ID);
		match cert_sign_res {
			Ok(certificate) => Ok(certificate),
			Err(e) => Err(e),
		}
	}

	pub fn read_ca_cert(&self) -> Result< Vec<u8>, u32> {
		let ca_cert_res = self.read_file(CA_CERT_FILE_ID);
		match ca_cert_res {
			Ok(certificate) => Ok(certificate),
			Err(e) => Err(e),
		}
	}

	pub fn read_rootca_cert(&self) -> Result< Vec<u8>, u32> {
		let root_cert_res = self.read_file(ROOT_CERT_FILE_ID);
		match root_cert_res {
			Ok(certificate) => Ok(certificate),
			Err(e) => Err(e),
		}
	}

	pub fn read_rrn_cert(&self) -> Result< Vec<u8>, u32> {
		let root_cert_res = self.read_file(RRN_CERT_FILE_ID);
		match root_cert_res {
			Ok(certificate) => Ok(certificate),
			Err(e) => Err(e),
		}
	}

	fn verify(&self, pin_ref: u8, pin: String) -> Result< (), u32> {
		let card_handle = self.card_handle.lock().unwrap();
		let mut command: Vec<u8> = vec![0x00, 0x20, 0x00, pin_ref, 0x08, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
		let pin_len : u8 = 0x20 | (0x0F & (pin.len() as u8));
		let mut i = 0;
		let mut j = 0;

		command[5] = pin_len;
		for b in pin.into_bytes() {
			if (i % 2) == 0 {
				command[6+j] = 0xF0 & ((0x0F & b) << 4);
			}
			else {
				command[6+j] = command[6+j] | (0x0F & b);
				j = j + 1;
			}
			i = i+1;
		}

		let result = card_handle.transmit(&command);
		match result {
			Ok(resp) => {
				if (resp.sw[0] == 0x90) && (resp.sw[1] == 0x00) {
					Ok(())
				}
				else {
					trace!("sw0:{:X}, sw1:{:X}", resp.sw[0], resp.sw[1]);
					if resp.sw[0] == 0x63 {
						// WRONG PIN CODE resp.sw[1]=0Cx where x is number of retries  
						Err(EIDONKEY_BASE_ERROR + resp.sw[1] as u32)
					}
					else if (resp.sw[0] == 0x69) && (resp.sw[1] == 0x83) {
						Err(EIDONKEY_CARD_BLOCKED)
					}
					else {
						Err(EIDONKEY_VERIFY_ERROR)
					}
				}
			},
			Err(e) => Err(e),
		}
	}

	fn select(&self, signAlgo:u8, signKey: u8) -> Result< (), u32> {
		let card_handle = self.card_handle.lock().unwrap();
		let set_cmd: Vec<u8> = vec![0x00, 0x22, 0x41, 0xB6, 0x05, 0x04, 0x80, signAlgo, 0x84, signKey];
		trace!("select: select Authentication Key");

		let result = card_handle.transmit(&set_cmd);
		match result {
			Ok(resp) => {
				trace!("select: Select finished {:X}:{:X}", resp.sw[0], resp.sw[1]);
				if (resp.sw[0] == 0x90) && (resp.sw[1] == 0x00) {
					Ok(())
				}
				else {
					trace!("sw0:{:X}, sw1:{:X}", resp.sw[0], resp.sw[1]);
					Err(EIDONKEY_READ_ERROR)
				}
			},
			Err(e) => Err(e),
		}
	}

	fn sign(&self, data: & Vec<u8>) -> Result< Vec<u8>, u32> {
		let card_handle = self.card_handle.lock().unwrap();
		let mut sign_cmd: Vec<u8> = vec![0x00, 0x2A, 0x9E, 0x9A];
		let mut copy_data = data.clone();
		sign_cmd.push(data.len() as u8);
		sign_cmd.append(&mut copy_data);
		sign_cmd.push(0x80);

		print!("sign: data [");
		for c in sign_cmd.clone() {
			print!("{:02X}", c);
		}		
		trace!("]");

		let result = card_handle.transmit(&sign_cmd);
		trace!("sign: start signature {}", sign_cmd.len());
		match result {
			Ok(resp) => {
				trace!("sign: Signature finished {:X}:{:X}", resp.sw[0], resp.sw[1]);
				if (resp.sw[0] == 0x90) && (resp.sw[1] == 0x00) {
					Ok(resp.data)
				}
				else {
					trace!("sw0:{:X}, sw1:{:X}", resp.sw[0], resp.sw[1]);
					if resp.sw[0] == 0x61 {
						let mut response: Vec<u8> = Vec::new();
						get_response(card_handle, resp.sw[1], &mut response)
					}
					else {
						Err(EIDONKEY_READ_ERROR)
					}
				}
			},
			Err(e) => Err(e),
		}
	}

	pub fn sign_with_auth_cert(&self, pincode: String, data: & Vec<u8>) -> Result< (Vec<u8>), u32> {

		trace!("sign_with_auth_cert: enter PIN {}", pincode);
		let mut res = self.select(PKCS1, AUTH_KEYID);
		match res {
			Ok(_) => {
				trace!("sign_with_auth_cert: select Authentication Key succeeded");
				res = self.verify(0x01, pincode);
				match res {
					Ok(_) => {
						trace!("sign_with_auth_cert: PIN verified");
						self.sign( &data)
					},
					Err(e) => Err(e),
				}
			},
			Err(e) => Err(e)
		}
	}

	pub fn sign_with_sign_cert(&self, pincode: String, data: & Vec<u8>) -> Result< (Vec<u8>), u32> {

		trace!("sign_with_sign_cert: enter PIN {}", pincode);
		let mut res = self.select(PKCS1, SIGN_KEYID);

		match res {
			Ok(_) => {
				trace!("sign_with_sign_cert: select Signature Key succeeded");
				res = self.verify(0x01, pincode);
				match res {
					Ok(_) => {
						trace!("sign_with_sign_cert: PIN verified");
						self.sign( &data)
					},
					Err(e) => Err(e),
				}
			},
			Err(e) => Err(e)
		}
	}

}

#[cfg(test)]
mod tests {
	extern crate openssl;
	use self::openssl::x509::X509;
	use self::openssl::crypto::hash::{hash, Type};
	use std::fs::File;
	use super::EIdDonkeyCard;
	use super::convert_birth_date;
	use super::copy_vector_to_gender;

	#[test]
	fn test_read_identity() {
		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let eid_card = EIdDonkeyCard::new(reader);
		let identity_res = eid_card.read_identity();

		match identity_res {
			Ok(id) => {
				println!("card number: {}", id.card_number);
				print!("chip_number: ");
				for c in id.chip_number {
					print!("{:.2X}", c);
				}			
				print!("\n");
				println!("validity begin: {}", id.validity_begin);
				println!("validity end: {}", id.validity_end);
				println!("delivery municipality: {}", id.delivery_municipality);
				println!("national number: {}", id.national_number);
				println!("name: {}", id.name);
				match id.second_first_name {
					Some(n) => println!("second first_name: {}", n),
					None => println!("second first_name is non-existent"),
				}
				println!("third first_name: {}", id.third_first_name);
				println!("nationality: {}", id.nationality);
				println!("birth location: {}", id.birth_location);
				println!("birth date: {}", id.birth_date);
				println!("sex: {}", id.sex);
				match id.noble_condition {
					Some(n) => println!("noble condition: {}", n),
					None => println!("noble condition is non-existent"),
				}
				println!("document type: {}", id.document_type);
				match id.special_status {
					Some(n) => println!("special status: {}", n),
					None => println!("special status is non-existent"),
				}
				print!("hash photo: ");
				for c in id.hash_photo {
					print!("{:.2X}", c);
				}			
				print!("\n");
				print!("identity: ");
				for c in id.identity {
					print!("{:.2X}", c);
				}			
				print!("\n");
				print!("signature: ");
				for c in id.signature {
					print!("{:.2X}", c);
				}			
				print!("\n");
				assert!(true);
			},
			Err(e) => {
				println!("Error {:X}", e);
				assert!(false);
			},
		}
	}

	#[test]
	fn test_read_address() {
		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let eid_card = EIdDonkeyCard::new(reader);
		let address_res = eid_card.read_address();

		match address_res {
			Ok(addr) => {
				println!("street: {}", addr.street);
				println!("ZIP code: {}", addr.zip_code);
				println!("city: {}", addr.city);
				print!("binary address: ");
				for c in addr.address {
					print!("{:.2X}", c);
				}			
				print!("\n");
				print!("signature: ");
				for c in addr.signature {
					print!("{:.2X}", c);
				}			
				print!("\n");
				assert!(true);
			},
			Err(e) => {
				println!("Error {:X}", e);
				assert!(false);
			},
		}
	}

	#[test]
	fn test_read_address_unsyncronised_access() {
		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let mut eid_card = EIdDonkeyCard::new(reader);
		let eid_card2 = EIdDonkeyCard::new(reader);

		let address_res = eid_card.read_address();

		match address_res {
			Ok(addr) => {
				println!("street: {}", addr.street);
				println!("ZIP code: {}", addr.zip_code);
				println!("city: {}", addr.city);
				print!("binary address: ");
				for c in addr.address {
					print!("{:.2X}", c);
				}			
				print!("\n");
				print!("signature: ");
				for c in addr.signature {
					print!("{:.2X}", c);
				}			
				print!("\n");
				assert!(true);
			},
			Err(e) => {
				println!("Error {:X}", e);
				assert!(false);
			},
		}

		let address_res2 = eid_card2.read_address();
		match address_res2 {
			Ok(addr) => {
				println!("street2: {}", addr.street);
				println!("ZIP code2: {}", addr.zip_code);
				println!("city2: {}", addr.city);
				print!("binary address2: ");
				for c in addr.address {
					print!("{:.2X}", c);
				}			
				print!("\n");
				print!("signature2: ");
				for c in addr.signature {
					print!("{:.2X}", c);
				}			
				print!("\n");
				assert!(true);
			},
			Err(e) => {
				println!("Error {:X}", e);
				assert!(false);
			},
		}

	}

	#[test]
	#[ignore]
	fn test_verify_command() {
		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let mut eid_card = EIdDonkeyCard::new(reader);
		
		match eid_card.verify(0x01, "1234".to_string())	{
			Ok(_) => {
				println!("Verify successful!");
				assert!(true);
			},
			Err(e) =>{ 
				println!("Verify failed!");
				assert!(false);
			}
		}
	}

	#[test]
	fn test_convert_birth_date() {
		let mut birt_date = convert_birth_date(&"01 JAN 2014".to_string());
		assert_eq!(birt_date, "2014-01-01".to_string());
		birt_date = convert_birth_date(&"01 FEV 2014".to_string());
		assert_eq!(birt_date, "2014-02-01".to_string());
		birt_date = convert_birth_date(&"01 MARS 2014".to_string());
		assert_eq!(birt_date, "2014-03-01".to_string());
		birt_date = convert_birth_date(&"01 AVR 2014".to_string());
		assert_eq!(birt_date, "2014-04-01".to_string());
		birt_date = convert_birth_date(&"01 MAI 2014".to_string());
		assert_eq!(birt_date, "2014-05-01".to_string());
		birt_date = convert_birth_date(&"01 JUIN 2014".to_string());
		assert_eq!(birt_date, "2014-06-01".to_string());
		birt_date = convert_birth_date(&"01 JUIL 2014".to_string());
		assert_eq!(birt_date, "2014-07-01".to_string());
		birt_date = convert_birth_date(&"01 AOUT 2014".to_string());
		assert_eq!(birt_date, "2014-08-01".to_string());
		birt_date = convert_birth_date(&"01 SEPT 2014".to_string());
		assert_eq!(birt_date, "2014-09-01".to_string());
		birt_date = convert_birth_date(&"01 OCT 2014".to_string());
		assert_eq!(birt_date, "2014-10-01".to_string());
		birt_date = convert_birth_date(&"01 NOV 2014".to_string());
		assert_eq!(birt_date, "2014-11-01".to_string());
		birt_date = convert_birth_date(&"01 DEC 2014".to_string());
		assert_eq!(birt_date, "2014-12-01".to_string());
		birt_date = convert_birth_date(&"01 FEB 2014".to_string());
		assert_eq!(birt_date, "2014-02-01".to_string());
		birt_date = convert_birth_date(&"01 MAAR 2014".to_string());
		assert_eq!(birt_date, "2014-03-01".to_string());
		birt_date = convert_birth_date(&"01 APR 2014".to_string());
		assert_eq!(birt_date, "2014-04-01".to_string());
		birt_date = convert_birth_date(&"01 MEI 2014".to_string());
		assert_eq!(birt_date, "2014-05-01".to_string());
		birt_date = convert_birth_date(&"01 JUN 2014".to_string());
		assert_eq!(birt_date, "2014-06-01".to_string());
		birt_date = convert_birth_date(&"01 JUL 2014".to_string());
		assert_eq!(birt_date, "2014-07-01".to_string());
		birt_date = convert_birth_date(&"01 AUG 2014".to_string());
		assert_eq!(birt_date, "2014-08-01".to_string());
		birt_date = convert_birth_date(&"01 SEP 2014".to_string());
		assert_eq!(birt_date, "2014-09-01".to_string());
		birt_date = convert_birth_date(&"01 OKT 2014".to_string());
		assert_eq!(birt_date, "2014-10-01".to_string());
		birt_date = convert_birth_date(&"01 MÄR 2014".to_string());
		assert_eq!(birt_date, "2014-03-01".to_string());
		birt_date = convert_birth_date(&"01 DEZ 2014".to_string());
		assert_eq!(birt_date, "2014-12-01");
	}


	#[test]
	fn test_convert_gender() {
		let v_femme: Vec<u8> = vec![ 'F' as u8 ];
		let v_women: Vec<u8> = vec![ 'W' as u8 ];
		let v_vrouw: Vec<u8> = vec![ 'V' as u8 ];
		let v_man: Vec<u8> = vec![ 'M' as u8 ];

		let mut gender = copy_vector_to_gender(&v_femme, 0, 1);
		assert_eq!(gender, "F".to_string());
		let mut gender = copy_vector_to_gender(&v_women, 0, 1);
		assert_eq!(gender, "F".to_string());
		let mut gender = copy_vector_to_gender(&v_vrouw, 0, 1);
		assert_eq!(gender, "F".to_string());
		let mut gender = copy_vector_to_gender(&v_man, 0, 1);
		assert_eq!(gender, "M".to_string());
	}

	#[test]
	#[ignore]
	fn test_sign_verify_authentication() {
		let data = b"The quick brown fox jumps over the lazy dog";
		let testhash = hash(Type::SHA256, data);

		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let eid_card = EIdDonkeyCard::new(reader);
		// Sign
		println!("Start signature");
		let signature_res = eid_card.sign_with_auth_cert("1234".to_string(), &testhash);
		match signature_res {
			Ok(signature) => {
				// Verify
				println!("Signature succeeded");
				print!("signature: [");
				for c in signature.clone() {
					print!("{:02X}", c);
				}		
				println!("]");
				let mut file = File::open("./testcard_auth.pem").unwrap();
				let cert: X509 = X509::from_pem(&mut file).unwrap();
				let verify = cert.public_key().verify(&testhash[..], &signature[..]);
			},
			Err(e) => {
				assert!(false);
			}		
		}

	}

	#[test]
	#[ignore]
	fn test_sign_verify_signature() {
		let data = b"The quick brown fox jumps over the lazy dog";
		let testhash = hash(Type::SHA256, data);

		let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
		let eid_card = EIdDonkeyCard::new(reader);
		// Sign
		println!("Start signature");
		let signature_res = eid_card.sign_with_sign_cert("1234".to_string(), &testhash);
		match signature_res {
			Ok(signature) => {
				// Verify
				println!("Signature succeeded");
				print!("signature: [");
				for c in signature.clone() {
					print!("{:02X}", c);
				}		
				println!("]");
				let mut file = File::open("./testcard_auth.pem").unwrap();
				let cert: X509 = X509::from_pem(&mut file).unwrap();
				let verify = cert.public_key().verify(&testhash[..], &signature[..]);
			},
			Err(e) => {
				assert!(false);
			}		
		}

	}
}
