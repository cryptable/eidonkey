extern crate libc;
pub mod pcsc;
use std::io::prelude::*;
use std::fs::File;

static IDENTITY_FILE_ID: &'static[u8]		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31];
static IDENTITY_SIGN_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x32];
static ADDRESS_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33];
static ADDRESS_SIGN_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x34];
static PHOTO_FILE_ID: &'static[u8] 			= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x35];
static AUTHN_CERT_FILE_ID: &'static[u8] 	= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x38];
static SIGN_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x39];
static CA_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x3A];
static ROOT_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x3B];
static RRN_CERT_FILE_ID: &'static[u8] 		= &[0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x3C];
const TAG_TWO_FIRST_FIRST_NAMES: u8         = 8;
const TAG_NOBLE_CONDITION: u8               = 14;
const TAG_SPECIAL_STATUS: u8                = 16;
pub const EIDONKEY_READ_ERROR: u32 = 0x80120001;


pub struct EIdDonkeyCard {
	connection: pcsc::DonkeyCard,
	card_handle: pcsc::DonkeyCardConnect,
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
	pub address: String,
	pub bin_address: Vec<u8>,
	pub signature: Vec<u8>,
}

pub struct EIdPhoto {
	pub photo: Vec<u8>,
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

fn copy_vector_to_string(data: & Vec<u8>, offset: usize, len: u32) -> String {
	String::from_utf8(copy_vector(data, offset, len)).unwrap()
}

impl EIdDonkeyCard {
	pub fn list_readers() -> Result< Vec<String> , u32> {
		let connect = pcsc::DonkeyCard::new();
		let result = connect.list_readers();
		match result {
			Ok(readers) => Ok(readers),
			Err(e) => Err(e)
		}
	}

	pub fn new(reader: & String) -> Result< EIdDonkeyCard, u32 > {
		let connect = pcsc::DonkeyCard::new();
		let card_connect = connect.connect(reader);
		match card_connect {
			Ok(handle) => {
				Ok(EIdDonkeyCard {
					connection: connect,
					card_handle: handle
				})
			},
			Err(e) => Err(e),

		}
	}

	fn read_file(&self, file_loc: &[u8]) -> Result< Vec<u8>, u32> {
		let result = self.card_handle.transmit(&file_loc.to_vec());
		match result {
			Ok(resp) => {
				let read_length: usize = 0xFD;
				let mut data: Vec<u8> = Vec::new();
				let mut read_command: Vec<u8> = vec![0x00, 0xB0, 0x00, 0x00, 0xFD ];
				loop {
					let mut result = self.card_handle.transmit(&read_command);

					match result {
						Ok(resp) => {
							if (resp.sw[0] != 0x90) && (resp.sw[1] != 0x00) {
								print!("{:.*X}{:.*X}\n", 2, resp.sw[0], 2, resp.sw[1]);
								return Err(EIDONKEY_READ_ERROR)
							}
							if (resp.sw[0] == 0x6B) && (resp.sw[0] == 0x6B) {
								return Ok(data);
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
				let mut f = File::create("identity.bin").unwrap();
				f.write_all(&id);
				let id_sig_res = self.read_file(IDENTITY_SIGN_FILE_ID);
				match id_sig_res {
					Ok(id_sig) => {
						let mut pos: usize = 0;
						println!("card_number tag : {}", id[pos]);
						pos = pos + 1;
						let mut len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_card_number = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("chip_number tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let v_chip_number = copy_vector(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("validity_begin tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_validity_begin = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("validity_end tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_validity_end = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("delivery_municipality tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_delivery_municipality = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("national_number tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_national_number = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("name tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_name = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let mut s_second_first_name : Option<String>;
						if id[pos] == TAG_TWO_FIRST_FIRST_NAMES {
							println!("second_first_name tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							println!("pos : {}", pos);
							s_second_first_name = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_second_first_name = None;							
						}
						println!("third_first_name tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_third_first_name = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("nationality tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_nationality = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("birth_location tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_birth_location = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("birth_date tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_birth_date = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						println!("sex tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_sex = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let mut s_noble_condition : Option<String>;
						if id[pos] == TAG_NOBLE_CONDITION {
							println!("noble_condition tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							println!("pos : {}", pos);
							s_noble_condition = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_noble_condition = None;
						}
						println!("document_type tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
						let s_document_type = copy_vector_to_string(&id, pos, len.0);
						pos = pos + len.0 as usize;
						let s_special_status: Option<String>;
						if id[pos] == TAG_SPECIAL_STATUS {
							println!("special_status tag : {}", id[pos]);
							pos = pos + 1;
							len = get_data_len(&id, pos);
							pos = pos + len.1 as usize;
							println!("pos : {}", pos);
							s_special_status = Some(copy_vector_to_string(&id, pos, len.0));
							pos = pos + len.0 as usize;
						}
						else {
							s_special_status = None;
						}
						println!("hash_photo tag : {}", id[pos]);
						pos = pos + 1;
						len = get_data_len(&id, pos);
						pos = pos + len.1 as usize;
						println!("pos : {}", pos);
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
						let s_addr = String::from_utf8(addr.clone()).unwrap();
						Ok(EIdAddress{
							address: s_addr,
							bin_address: addr,
							signature: address_sig			
						})
					},
					Err(e) => Err(e),
				}
			},
			Err(e) => Err(e),
		}
	}

	pub fn reead_photo(&self) -> Result< EIdPhoto, u32> {
		let photo_res = self.read_file(PHOTO_FILE_ID);
		match photo_res {
			Ok(img) => {
				Ok(EIdPhoto {
					photo: img
				})
			},
			Err(e) => Err(e),
		}
	}

}

#[test]
#[ignore]
fn test_read_identity() {
	let ref reader = EIdDonkeyCard::list_readers().unwrap()[0];
	let eid_card = EIdDonkeyCard::new(reader).unwrap();
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
	let eid_card = EIdDonkeyCard::new(reader).unwrap();
	let address_res = eid_card.read_address();

	match address_res {
		Ok(addr) => {
			println!("address: {}", addr.address);
			print!("binary address: ");
			for c in addr.bin_address {
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
