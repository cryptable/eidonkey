// Error codes
pub const SCARD_S_SUCCESS: u32 				= 0x00000000; 
pub const SCARD_F_INTERNAL_ERROR: u32 		= 0x80100001; 
pub const SCARD_E_CANCELLED: u32 			= 0x80100002; 
pub const SCARD_E_INVALID_HANDLE: u32 		= 0x80100003; 
pub const SCARD_E_INVALID_PARAMETER: u32 	= 0x80100004; 
pub const SCARD_E_INVALID_TARGET: u32 		= 0x80100005; 
pub const SCARD_E_NO_MEMORY: u32 			= 0x80100006; 
pub const SCARD_F_WAITED_TOO_LONG: u32 		= 0x80100007; 
pub const SCARD_E_INSUFFICIENT_BUFFER: u32 	= 0x80100008; 
pub const SCARD_E_UNKNOWN_READER: u32 		= 0x80100009; 
pub const SCARD_E_TIMEOUT: u32 				= 0x8010000A; 
pub const SCARD_E_SHARING_VIOLATION: u32 	= 0x8010000B; 
pub const SCARD_E_NO_SMARTCARD: u32 		= 0x8010000C; 
pub const SCARD_E_UNKNOWN_CARD: u32 		= 0x8010000D; 
pub const SCARD_E_CANT_DISPOSE: u32 		= 0x8010000E; 
pub const SCARD_E_PROTO_MISMATCH: u32 		= 0x8010000F; 
pub const SCARD_E_NOT_READY: u32 			= 0x80100010; 
pub const SCARD_E_INVALID_VALUE: u32 		= 0x80100011; 
pub const SCARD_E_SYSTEM_CANCELLED: u32 	= 0x80100012; 
pub const SCARD_F_COMM_ERROR: u32 			= 0x80100013; 
pub const SCARD_F_UNKNOWN_ERROR: u32 		= 0x80100014; 
pub const SCARD_E_INVALID_ATR: u32 			= 0x80100015; 
pub const SCARD_E_NOT_TRANSACTED: u32 		= 0x80100016; 
pub const SCARD_E_READER_UNAVAILABLE: u32 	= 0x80100017; 
pub const SCARD_P_SHUTDOWN: u32 			= 0x80100018; 
pub const SCARD_E_PCI_TOO_SMALL: u32 		= 0x80100019; 
pub const SCARD_E_READER_UNSUPPORTED: u32 	= 0x8010001A; 
pub const SCARD_E_DUPLICATE_READER: u32 	= 0x8010001B; 
pub const SCARD_E_CARD_UNSUPPORTED: u32 	= 0x8010001C; 
pub const SCARD_E_NO_SERVICE: u32 			= 0x8010001D; 
pub const SCARD_E_SERVICE_STOPPED: u32 		= 0x8010001E; 
pub const SCARD_E_UNEXPECTED: u32 			= 0x8010001F; 
pub const SCARD_E_UNSUPPORTED_FEATURE: u32 	= 0x8010001F; 
pub const SCARD_E_ICC_INSTALLATION: u32 	= 0x80100020; 
pub const SCARD_E_ICC_CREATEORDER: u32 		= 0x80100021; 
pub const SCARD_E_DIR_NOT_FOUND: u32 		= 0x80100023; 
pub const SCARD_E_FILE_NOT_FOUND: u32 		= 0x80100024; 
pub const SCARD_E_NO_DIR: u32 				= 0x80100025; 
pub const SCARD_E_NO_FILE: u32 				= 0x80100026; 
pub const SCARD_E_NO_ACCESS: u32 			= 0x80100027; 
pub const SCARD_E_WRITE_TOO_MANY: u32 		= 0x80100028; 
pub const SCARD_E_BAD_SEEK: u32 			= 0x80100029; 
pub const SCARD_E_INVALID_CHV: u32 			= 0x8010002A; 
pub const SCARD_E_UNKNOWN_RES_MNG: u32 		= 0x8010002B; 
pub const SCARD_E_NO_SUCH_CERTIFICATE: u32 	= 0x8010002C; 
pub const SCARD_E_CERTIFICATE_UNAVAILABLE: u32 	= 0x8010002D; 
pub const SCARD_E_NO_READERS_AVAILABLE: u32 	= 0x8010002E; 
pub const SCARD_E_COMM_DATA_LOST: u32 		= 0x8010002F; 
pub const SCARD_E_NO_KEY_CONTAINER: u32 	= 0x80100030; 
pub const SCARD_E_SERVER_TOO_BUSY: u32 		= 0x80100031; 
pub const SCARD_W_UNSUPPORTED_CARD: u32 	= 0x80100065; 
pub const SCARD_W_UNRESPONSIVE_CARD: u32 	= 0x80100066; 
pub const SCARD_W_UNPOWERED_CARD: u32 		= 0x80100067; 
pub const SCARD_W_RESET_CARD: u32 			= 0x80100068; 
pub const SCARD_W_REMOVED_CARD: u32 		= 0x80100069; 
pub const SCARD_W_SECURITY_VIOLATION: u32 	= 0x8010006A; 
pub const SCARD_W_WRONG_CHV: u32 			= 0x8010006B; 
pub const SCARD_W_CHV_BLOCKED: u32 			= 0x8010006C; 
pub const SCARD_W_EOF: u32 					= 0x8010006D; 
pub const SCARD_W_CANCELLED_BY_USER: u32 	= 0x8010006E; 
pub const SCARD_W_CARD_NOT_AUTHENTICATED: u32 	= 0x8010006F; 

// Custom errors
pub const PARSING_READERS_ERROR: u32 	= 0x90010001;
pub const PARSING_RESPONSE_ERROR: u32 	= 0x90010002; 

// Shared mode
pub const SCARD_SHARE_EXCLUSIVE: u32 		= 0x0001;
pub const SCARD_SHARE_SHARED: u32 			= 0x0002;
pub const SCARD_SHARE_DIRECT: u32			= 0x0003;

// Protocols
pub const SCARD_PROTOCOL_T0: u32			= 0x0001;
pub const SCARD_PROTOCOL_T1: u32			= 0x0002;
pub const SCARD_PROTOCOL_RAW: u32			= 0x0004;
pub const SCARD_PROTOCOL_T15: u32			= 0x0008;
pub const SCARD_PROTOCOL_ANY: u32			= (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);

// Disposition
pub const SCARD_LEAVE_CARD: u32				= 0x0000;
pub const SCARD_RESET_CARD: u32				= 0x0001;
pub const SCARD_UNPOWER_CARD: u32			= 0x0002;
pub const SCARD_EJECT_CARD: u32				= 0x0003;

pub const MAX_ATR_SIZE: u32					= 33; 
pub const MAX_RECV_BUFFER: usize			= 2048;

pub struct ResponseAPDU {
	pub data: Vec<u8>,
	pub sw: Vec<u8>,
}

impl ResponseAPDU {
	fn parse(data: Vec<u8>) -> Result< ResponseAPDU, u32 > {

		if data.len() < 2 {
			Err(PARSING_RESPONSE_ERROR)
		}
		else {
			let mut data_clone = data.clone(); 
			let sw_temp = data_clone.split_off(data.len() - 2);
			Ok(ResponseAPDU {
				data: data_clone,
				sw: sw_temp,
			})
		}
	}
}

pub struct DonkeyCardStatus {
	pub status: u64,
	pub protocol: u64,
	pub reader_name: String,
	pub atr: Vec<u8>,
}

#[cfg(target_os="macos")]
pub mod pcsc {
	use super::*;
	use libc::c_void;
	use std::ptr;
	use std::mem;

	#[repr(C)]
	struct Scard_Reader_State
	{ 
	    reader: *const u8,
	    user_data: *const c_void,
	    current_state: u32,
	    event_state: u32,
	    atr_len: u32,
	    atr: [u8; 33],
	}

	#[repr(C)]
	struct Scard_IO_Request
	{
		proto: u32,
		pci_length: u32,
	}

	#[link(kind="framework", name = "PCSC")]
	extern {
		// LONG SCardEstablishContext (DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
	 	fn SCardEstablishContext(dwScope: u32, reserved2: *const u8, reserved2: *const u8, context: *mut u32) ->  u32;
	 	// LONG SCardReleaseContext (SCARDCONTEXT hContext)
	 	fn SCardReleaseContext(context: u32) ->  u32;
	 	// LONG SCardConnect (SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
	 	fn SCardConnect(context: u32, reader: *const u8, share_mode: u32, preferred_protocols: u32, card: *mut u32, active_protocol: *mut u32) -> u32;
		// LONG SCardReconnect (SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol)
	 	fn SCardReconnect(card: u32, shared_mode: u32, preferred_protocols: u32, initialization: u32, active_protocol: *mut u32) -> u32;
		// LONG SCardDisconnect (SCARDHANDLE hCard, DWORD dwDisposition)
		fn SCardDisconnect(card: u32, disposition: u32) -> u32;
		// LONG SCardBeginTransaction (SCARDHANDLE hCard)
		fn SCardBeginTransaction(card: u32) -> u32;
		// LONG SCardEndTransaction (SCARDHANDLE hCard, DWORD dwDisposition)
		fn SCardEndTransaction(card: u32, disposition: u32) -> u32;
		// LONG SCardStatus (SCARDHANDLE hCard, LPSTR szReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
		fn SCardStatus(card: u32, reader: *mut u8, reader_len: *mut usize, state: *mut u32, protocol: *mut u32, atr: *mut u8, atr_len: *mut usize) -> u32; 
		// LONG SCardGetStatusChange (SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders)
		fn SCardGetStatusChange(context: u32, timeout: u32,reader_state: *mut Scard_Reader_State, readers: u32) -> u32;
		// LONG SCardControl (SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned)
		fn SCardControl(card : u32, control_code: u32, send_buffer: *const u8, send_len: u32, receive_buffer: *mut u8, recv_len: u32, bytes_return: *mut u32) -> u32;
		// LONG SCardGetAttrib (SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
		fn SCardGetAttrib(card: u32, attr_id: u32, attr: *mut u8, attr_len: *mut u32) -> u32; 
		// LONG SCardSetAttrib (SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr, DWORD cbAttrLen)
		fn SCardSetAttrib(card: u32, attrId: u32, attr: *const u8, attr_len: u32) -> u32;
		// LONG SCardTransmit (SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
		fn SCardTransmit(card: u32, io_send_pci: *const Scard_IO_Request, send_buffer: *const u8, send_len: usize, io_recv_pci: *mut Scard_IO_Request, recv_buffer: *mut u8, recv_len: *mut usize) -> u32;
	  	// LONG SCardListReaders (SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
		fn SCardListReaders(context: u32, not_used: *const c_void, readers: *mut u8, nbr_readers: *mut usize) -> u32;
	 	// LONG SCardFreeMemory (SCARDCONTEXT hContext, LPCVOID pvMem)
	 	fn SCardFreeMemory(context: u32, mem: *const c_void) -> u32;
		// LONG SCardListReaderGroups (SCARDCONTEXT hContext, LPSTR mszGroups, LPDWORD pcchGroups)
		fn SCardListReaderGroups(context: u32, groups: *mut u8, nbr_groups: *mut u32) -> u32;
		// LONG SCardCancel (SCARDCONTEXT hContext)
		fn SCardCancel(context: u32) -> u32;
		// LONG SCardIsValidContext (SCARDCONTEXT hContext)
		fn SCardIsValidContext(context: u32) -> u32;
	}

	#[derive(Clone)]
	pub struct DonkeyCard {
		pub context: u32,
	}

	#[derive(Clone)]
	pub struct DonkeyCardConnect {
		pub context: u32,
		pub card_handle: u32,
		pub active_protocol: u32,
	}

	impl DonkeyCard {
	    pub fn new() -> Result<DonkeyCard, u32> {
	    	unsafe {
	    		let mut x: u32 = 0;
	    		let ret = SCardEstablishContext(0x0000, ptr::null(), ptr::null(), &mut x);
	    		trace!("Establish context {}: {:X}", x, ret);
				if ret == SCARD_S_SUCCESS {
	    			return Ok(DonkeyCard {
	    						context: x,
	    					})
	    		}
	    		else {
	    			return Err(ret)
	    		}
	    	}
	    }

	    pub fn list_readers(&self) -> Result< Vec<String> , u32> {
			unsafe {
				let mut size : usize = 0;
				let mut ret = SCardListReaders(self.context, ptr::null(), ptr::null_mut(),  &mut size);
				if ret == SCARD_S_SUCCESS {
					let mut readers: Vec<u8> = vec![0; size];
					ret = SCardListReaders(self.context, ptr::null(), readers.as_mut_ptr(),  &mut size);

					match String::from_utf8(readers) {
						Ok(reader_name) => {
							let mut v: Vec<String> = Vec::new();
							v.push(reader_name);
							return Ok(v);
						},
						Err(_) => { 
							return Err(PARSING_READERS_ERROR);
						},
					}
				} else {
					return Err(ret)
				}
			}
	   	}
	}

	impl Drop for DonkeyCard {
		fn drop(&mut self) {
			unsafe {
				let ret = SCardReleaseContext(self.context);
		        trace!("Dropping Context ![{}:{}]", self.context, ret);
		    }
	    }
	}

	impl DonkeyCardConnect {

	   	pub fn new(name: & String) -> Result< DonkeyCardConnect, u32> {
	   		unsafe {
	    		let mut context: u32 = 0;
	   			let mut handle: u32 = 0;
	   			let mut protocol: u32 = 0;
	   			// TODO: Use SCARD_SHARE_SHARED -> SCARD_SHARE_EXCLUSIVE
	   			// Don't share the card with different applications ...
	    		let ret1 = SCardEstablishContext(0x0000, ptr::null(), ptr::null(), &mut context);
	   			let ret2 = SCardConnect(context, name.as_bytes().as_ptr(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, 
	   				&mut handle, &mut protocol);
	   			if ret2 == SCARD_S_SUCCESS {
					trace!("context: {:?}", context);
					trace!("handle: {:?}", handle);
		   			let card_connect = DonkeyCardConnect {
		   				context: context,
		   				card_handle: handle,
		   				active_protocol: protocol
		   			};
	   				Ok(card_connect)
	   			}
	   			else {
	   				Err(ret2)
	   			}
	   		}
	   	}

		pub fn status(&self) -> Result< DonkeyCardStatus, u32 > {
			unsafe {
				let mut atr_size: usize = 0;
				let mut atr_data: Vec<u8>;
				let mut reader_size: usize = 0;
				let mut reader_name: Vec<u8>;
				let mut state: u32 = 0;
				let mut prot: u32 = 0;
				let mut ret = SCardStatus(self.card_handle, ptr::null_mut(), &mut reader_size,
					&mut state, &mut prot,
					ptr::null_mut(), &mut atr_size);
				if ret == SCARD_S_SUCCESS {
					reader_name = vec![0; (reader_size-1)];
					atr_data = vec![0; atr_size];
					ret = SCardStatus(self.card_handle, reader_name.as_mut_ptr(), &mut reader_size,
						&mut state, &mut prot,
						atr_data.as_mut_ptr(), &mut atr_size);

					match String::from_utf8(reader_name) {
						Ok(reader) => {
							return Ok(DonkeyCardStatus {
								status: state as u64,
								protocol: prot as u64,
								reader_name: reader,
								atr: atr_data
							});
						},
						Err(_) => { 
							return Err(PARSING_READERS_ERROR);
						},
					}
				}
				else {
					return Err(ret);
				}
			}
		}

		pub fn transmit(&self, sendbuffer: & Vec<u8> ) -> Result< ResponseAPDU, u32> {
			unsafe {
				trace!("transmit using handle: {:?}", self.card_handle);
				let scard_io_request_lg = mem::size_of::<Scard_IO_Request>();

				let scard_pci_send: Scard_IO_Request  = Scard_IO_Request { proto:SCARD_PROTOCOL_T0, 
					pci_length: scard_io_request_lg as u32};
				let mut scard_pci_recv: Scard_IO_Request  = Scard_IO_Request { proto:0x0000, 
					pci_length: scard_io_request_lg as u32};
				let mut recv_buffer: Vec<u8> = vec![0; MAX_RECV_BUFFER];
				let mut recv_len: usize = MAX_RECV_BUFFER;
				let ret = SCardTransmit(self.card_handle, &scard_pci_send, sendbuffer.as_ptr(), sendbuffer.len(),
					&mut scard_pci_recv, recv_buffer.as_mut_ptr(), &mut recv_len);
				if ret == SCARD_S_SUCCESS {
					trace!("Recv length [{}]", recv_len);
					recv_buffer.truncate(recv_len);
					return ResponseAPDU::parse(recv_buffer);
				}
				else {
					return Err(ret);
				}
			}
		}
	}

	impl Drop for DonkeyCardConnect {
		fn drop(&mut self) {
			unsafe {
				let ret1 = SCardDisconnect(self.card_handle, SCARD_LEAVE_CARD);
		        trace!("Disconnect ![{}:{}]", self.context, ret1);
				let ret2 = SCardReleaseContext(self.context);
		        trace!("Dropping Context ![{}:{}]", self.context, ret2);
		    }
	    }
	}
}

#[cfg(all(target_os="linux", target_pointer_width="64"))]
pub mod pcsc {
	use super::*;
	use libc::c_void;
	use std::ptr;
	use std::mem;

	#[repr(C)]
	struct Scard_Reader_State
	{ 
	    reader: *const u8,
	    user_data: *const c_void,
	    current_state: u64,
	    event_state: u64,
	    atr_len: u64,
	    atr: [u8; 33],
	}

	#[repr(C)]
	struct Scard_IO_Request
	{
		proto: u64,
		pci_length: u64,
	}

	#[link(name = "pcsclite")]
	extern {
		// LONG SCardEstablishContext (DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
	 	fn SCardEstablishContext(dwScope: u64, reserved2: *const u8, reserved2: *const u8, context: *mut i64) ->  i64;
	 	// LONG SCardReleaseContext (SCARDCONTEXT hContext)
	 	fn SCardReleaseContext(context: i64) ->  i64;
	 	// LONG SCardConnect (SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
	 	fn SCardConnect(context: i64, reader: *const u8, share_mode: u64, preferred_protocols: u64, card: *mut i64, active_protocol: *mut u64) -> i64;
		// LONG SCardReconnect (SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol)
	 	fn SCardReconnect(card: i64, shared_mode: u64, preferred_protocols: u64, initialization: u64, active_protocol: *mut u64) -> i64;
		// LONG SCardDisconnect (SCARDHANDLE hCard, DWORD dwDisposition)
		fn SCardDisconnect(card: i64, disposition: u64) -> i64;
		// LONG SCardBeginTransaction (SCARDHANDLE hCard)
		fn SCardBeginTransaction(card: i64) -> i64;
		// LONG SCardEndTransaction (SCARDHANDLE hCard, DWORD dwDisposition)
		fn SCardEndTransaction(card: i64, disposition: u64) -> i64;
		// LONG SCardStatus (SCARDHANDLE hCard, LPSTR szReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
		fn SCardStatus(card: i64, reader: *mut u8, reader_len: *mut u64, state: *mut u64, protocol: *mut u64, atr: *mut u8, atr_len: *mut u64) -> i64; 
		// LONG SCardGetStatusChange (SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders)
		fn SCardGetStatusChange(context: i64, timeout: u64,reader_state: *mut Scard_Reader_State, readers: u64) -> i64;
		// LONG SCardControl (SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned)
		fn SCardControl(card : i64, control_code: u64, send_buffer: *const u8, send_len: u64, receive_buffer: *mut u8, recv_len: u64, bytes_return: *mut u64) -> i64;
		// LONG SCardGetAttrib (SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
		fn SCardGetAttrib(card: i64, attr_id: u64, attr: *mut u8, attr_len: *mut u64) -> i64; 
		// LONG SCardSetAttrib (SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr, DWORD cbAttrLen)
		fn SCardSetAttrib(card: i64, attrId: u64, attr: *const u8, attr_len: u64) -> i64;
		// LONG SCardTransmit (SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength, SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
		fn SCardTransmit(card: i64, io_send_pci: *const Scard_IO_Request, send_buffer: *const u8, send_len: u64, io_recv_pci: *mut Scard_IO_Request, recv_buffer: *mut u8, recv_len: *mut u64) -> i64;
	  	// LONG SCardListReaders (SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
		fn SCardListReaders(context: i64, not_used: *const u8, readers: *mut u8, nbr_readers: *mut u64) -> i64;
	 	// LONG SCardFreeMemory (SCARDCONTEXT hContext, LPCVOID pvMem)
	 	fn SCardFreeMemory(context: i64, mem: *const c_void) -> i64;
		// LONG SCardListReaderGroups (SCARDCONTEXT hContext, LPSTR mszGroups, LPDWORD pcchGroups)
		fn SCardListReaderGroups(context: i64, groups: *mut u8, nbr_groups: *mut u64) -> i64;
		// LONG SCardCancel (SCARDCONTEXT hContext)
		fn SCardCancel(context: i64) -> i64;
		// LONG SCardIsValidContext (SCARDCONTEXT hContext)
		fn SCardIsValidContext(context: i64) -> i64;
	}

	#[derive(Clone)]
	pub struct DonkeyCard {
		pub context: i64,
	}

	#[derive(Clone)]
	pub struct DonkeyCardConnect {
		pub context: i64,
		pub card_handle: i64,
		pub active_protocol: u64,
	}

	impl DonkeyCard {
	    pub fn new() -> Result<DonkeyCard, u32> {
	    	unsafe {
	    		let mut x: i64 = 0;
	    		let ret = SCardEstablishContext(0x0000, ptr::null(), ptr::null(), &mut x);
	    		trace!("Establish context {:X}: {:X}", x, ret);
	    		if ret == SCARD_S_SUCCESS as i64 {
		    		return Ok(DonkeyCard {
		    				context: x,
		    			})
		    	}
		    	else {
		    		return Err(ret as u32)
		    	}
	    	}
	    }

	    pub fn list_readers(&self) -> Result< Vec<String> , u32> {
			unsafe {
				let mut size : u64 = 0;
				let mut ret = SCardListReaders(self.context, ptr::null(), ptr::null_mut(),  &mut size);
				if ret == SCARD_S_SUCCESS as i64 {
					let mut readers: Vec<u8> = vec![0; size as usize];
					ret = SCardListReaders(self.context, ptr::null(), readers.as_mut_ptr(),  &mut size);

					match String::from_utf8(readers) {
						Ok(reader_name) => {
							let mut v: Vec<String> = Vec::new();
							v.push(reader_name);
							return Ok(v);
						},
						Err(_) => { 
							return Err(PARSING_READERS_ERROR);
						},
					}
				} else {
					return Err(ret as u32)
				}
			}
	   	}
	}

	impl Drop for DonkeyCard {
		fn drop(&mut self) {
			unsafe {
				let ret = SCardReleaseContext(self.context);
		        trace!("Dropping Context! [{:X}:{:X}]", self.context, ret);
		    }
	    }
	}

	impl DonkeyCardConnect {

	   	pub fn new(name: & String) -> Result< DonkeyCardConnect, u32> {
	   		unsafe {
	    		let mut context: i64 = 0;
	   			let mut handle: i64 = 0;
	   			let mut protocol: u64 = 0;
	   			// TODO: Use SCARD_SHARE_SHARED -> SCARD_SHARE_EXCLUSIVE
	   			// Don't share the card with different applications ...
	    		let ret1 = SCardEstablishContext(0x0000, ptr::null(), ptr::null(), &mut context);
	   			let ret2 = SCardConnect(context, name.as_bytes().as_ptr(), SCARD_SHARE_SHARED as u64, SCARD_PROTOCOL_ANY as u64, 
	   				&mut handle, &mut protocol);
	   			if ret2 == SCARD_S_SUCCESS as i64 {
					trace!("context: {:X}", context);
					trace!("handle: {:X}", handle);
		   			let card_connect = DonkeyCardConnect {
		   				context: context,
		   				card_handle: handle,
		   				active_protocol: protocol
		   			};
	   				Ok(card_connect)
	   			}
	   			else {
	   				Err(ret2 as u32)
	   			}
	   		}
	   	}

		pub fn status(&self) -> Result< DonkeyCardStatus, u32 > {
			unsafe {
				let mut atr_size: u64 = 0;
				let mut atr_data: Vec<u8>;
				let mut reader_size: u64 = 0;
				let mut reader_name: Vec<u8>;
				let mut state: u64 = 0;
				let mut prot: u64 = 0;
				let mut ret = SCardStatus(self.card_handle, ptr::null_mut(), &mut reader_size,
					&mut state, &mut prot,
					ptr::null_mut(), &mut atr_size);
				if ret == SCARD_S_SUCCESS as i64 {
					reader_name = vec![0; (reader_size as usize - 1)];
					atr_data = vec![0; atr_size as usize];
					ret = SCardStatus(self.card_handle, reader_name.as_mut_ptr(), &mut reader_size,
						&mut state, &mut prot,
						atr_data.as_mut_ptr(), &mut atr_size);

					match String::from_utf8(reader_name) {
						Ok(reader) => {
							return Ok(DonkeyCardStatus {
								status: state,
								protocol: prot,
								reader_name: reader,
								atr: atr_data
							});
						},
						Err(_) => { 
							return Err(PARSING_READERS_ERROR);
						},
					}
				}
				else {
					return Err(ret as u32);
				}
			}
		}

		pub fn transmit(&self, sendbuffer: & Vec<u8> ) -> Result< ResponseAPDU, u32> {
			unsafe {
				trace!("transmit using handle: {:X}", self.card_handle);
				let scard_io_request_lg = mem::size_of::<Scard_IO_Request>();

				let scard_pci_send: Scard_IO_Request  = Scard_IO_Request { proto:SCARD_PROTOCOL_T0 as u64, 
					pci_length: scard_io_request_lg as u64 };
				let mut scard_pci_recv: Scard_IO_Request  = Scard_IO_Request { proto:0x0000, 
					pci_length: scard_io_request_lg as u64 };
				let mut recv_buffer: Vec<u8> = vec![0; MAX_RECV_BUFFER];
				let mut recv_len: u64 = MAX_RECV_BUFFER as u64;
				let ret = SCardTransmit(self.card_handle, &scard_pci_send, sendbuffer.as_ptr(), sendbuffer.len() as u64,
					&mut scard_pci_recv, recv_buffer.as_mut_ptr(), &mut recv_len);
				if ret == SCARD_S_SUCCESS as i64 {
					trace!("Recv length [{}]", recv_len);
					recv_buffer.truncate(recv_len as usize);
					return ResponseAPDU::parse(recv_buffer);
				}
				else {
					return Err(ret as u32);
				}
			}
		}
	}

	impl Drop for DonkeyCardConnect {
		fn drop(&mut self) {
			unsafe {
				let ret1 = SCardDisconnect(self.card_handle, SCARD_LEAVE_CARD as u64);
		        trace!("Disconnect ![{}:{}]", self.context, ret1);
				let ret2 = SCardReleaseContext(self.context);
		        trace!("Dropping Context ![{}:{}]", self.context, ret2);
		    }
	    }
	}	
}

#[cfg(test)]
mod tests {

	use super::pcsc::DonkeyCard;
	use super::pcsc::DonkeyCardConnect;

	#[test]
	fn test_list_reader() {
		let donkeycard = DonkeyCard::new().unwrap();
		let readers = donkeycard.list_readers();
		match readers {
			Ok(names) => {
				println!("context {:?}", donkeycard.context);
				println!("reader {}", names[0]);	
				assert!(true);
			},
			Err(code) => {
				println!("Error code {:?}", code);	
				assert!(false);			
			}
		}
	}

	#[test]
	fn test_connect_card(){
		let donkeycard = DonkeyCard::new().unwrap();
		let ref name = donkeycard.list_readers().unwrap()[0];
		let card = DonkeyCardConnect::new(name);	
		match card {
			Ok(donkeysc) => {
				println!("donkeysc.card_handle {:?}", donkeysc.card_handle);
				println!("card.active_protocol {:?}", donkeysc.active_protocol);
				assert!(true);			
			}
			Err(code) => {
				println!("Error code {:?}", code);	
				assert!(false);				
			}
		}
	}

	#[test]
	fn test_status_card(){
		let donkeycard = DonkeyCard::new().unwrap();
		let ref name = donkeycard.list_readers().unwrap()[0];
		let card = DonkeyCardConnect::new(name).unwrap();	
		let command: Vec<u8> = vec![0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33];
		let response = card.status();
		match response {
		    Ok(status) => {
	    		println!("Status {:X}", status.status);
	    		println!("Protocol {:X}", status.protocol);
	    		println!("Reader name {}", status.reader_name);
	    		print!("atr ");
	 			for chr in status.atr {
	        		print!("{:X},", chr);
	    		}
	    		print!("\n");
				assert!(true);			
			}
		    Err(code) =>  {
				println!("Error code {:?}", code);	
				assert!(false);				
			},
		}
	}


	// select identity file { 0x3F, 0x00, (byte) 0xDF, 0x01, 0x40, 0x31 }
	// CLA   INS   P1    P2    len
	// 0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31 
	// read binary file
	// 0x00, 0xB0, 0x00, 0x00, 0x00 };

	#[test]
	fn test_transmit_card(){
		let donkeycard = DonkeyCard::new().unwrap();
		let ref name = donkeycard.list_readers().unwrap()[0];
		let card = DonkeyCardConnect::new(name).unwrap();	
		let command: Vec<u8> = vec![0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x33];
		let response = card.transmit(&command);
		match response {
		    Ok(resp) => {
	        	print!("sw: ");
	 			for chr in resp.sw.iter() {
	        		print!("{:X}", chr);
	    		}
	        	print!("\n");
	        	print!("data: ");
	        	if resp.data.len() == 0 {
	        		print!("No data");
	        	}
	        	else {
		 			for chr in resp.data.iter() {
		        		print!("{:X}", chr);
		    		}        		
	        	}
	        	print!("\n");
				assert!(true);			
			}
		    Err(code) =>  {
				println!("Error code {:?}", code);	
				assert!(false);				
			},
		}
	}

	#[test]	
	fn test_transmit_readdata_card() {
		let donkeycard = DonkeyCard::new().unwrap();
		let ref name = donkeycard.list_readers().unwrap()[0];
		let card = DonkeyCardConnect::new(name).unwrap();	
		let command_select: Vec<u8> = vec![0x00, 0xA4, 0x08, 0x0C, 0x06, 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x31];
		let response_select = card.transmit(&command_select);
		match response_select {
		    Ok(resp) => {
	        	print!("sw: ");
	 			for chr in resp.sw.iter() {
	        		print!("{:X}", chr);
	    		}
	        	print!("\n");
	        	print!("data: ");
	        	if resp.data.len() == 0 {
	        		print!("No data");
	        	}
	        	else {
		 			for chr in resp.data.iter() {
		        		print!("{:X}", chr);
		    		}        		
	        	}
	        	print!("\n");
				let command_read: Vec<u8> = vec![0x00, 0xB0, 0x00, 0x00, 0xFD ];
				let response_read = card.transmit(&command_read);
				match response_read {
				    Ok(resp) => {
			        	print!("sw: ");
			 			for chr in resp.sw.iter() {
			        		print!("{:X}", chr);
			    		}
			        	print!("\n");
			        	print!("data: ");
			        	if resp.data.len() == 0 {
			        		print!("No data");
			        	}
			        	else {
				 			for chr in resp.data.iter() {
				        		print!("{:X}", chr);
				    		}        		
			        	}
			        	print!("\n");
			        	let identity = String::from_utf8(resp.data);
			        	match identity {
			        		Ok(id) => println!("identity = {}", id),
			        		Err(e) => println!("UTF8 error = {}", e)
			        	}
					},
					Err(code) =>  {
						println!("Error code {:?}", code);	
						assert!(false);				
					},
				}
				assert!(true);			
			},
		    Err(code) =>  {
				println!("Error code {:?}", code);	
				assert!(false);				
			}
		}
	}
}
