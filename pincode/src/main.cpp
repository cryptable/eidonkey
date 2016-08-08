/**
 * @brief: This application perform solely the pincode request to the user
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string>
#include <string.h>
#include "pincode.h"

using namespace std;

#define RET_OK					0
#define RET_INVALID_ARGUMENTS	101

#define PINCODE_AUTHENTICATION  1
#define PINCODE_SIGNATURE       2

/**
 * @brief: Print the usage of the pincode application
 */
void print_usage(int verbose) {
	if (verbose) {
		printf("pincode --type <signature|authentication> [--verbose] [--retries <number>] [--hash <hex-string>]\n");
	}
}

/**
 * @brief: print the json result
 */
void print_json(int error_code, const char *result) {
	printf("{\"result_code\":%d,\"result_data\":\"%s\"}",error_code, result);
}

int isnumber(const char *str) {
	while (*str != '\0') {
		if (!isdigit(*str)) {
			return 0;
		}
		str++;
	}
	return 1;
}

/**
 * @brief: This is the main entry of the application
 * @detail: The parameters given will be the pincode type (signature or authentication), 
 * the hash for visualization and the number of retries left
 */
int main(int argc, char *argv[]) {
	int    			ret = RET_OK;
	std::string 	ret_msg = "";
	char			*hash = NULL;
	char   			pincode[11];
	unsigned long	pincodeLg = sizeof(pincode);
	long    		nbrRetries = -1;
	char			*endptr = NULL;
	int         	type = 0;
	int 			verbose = 0;

	// Initialization
	memset(pincode, 0, sizeof(pincode));

	initPINCode();

	// Parsing arguments
	for (int i=0; i<argc; i++) {
		if ((strncmp(argv[i], "--verbose", sizeof("--verbose")) == 0) || 
			(strncmp(argv[i], "-v", sizeof("-v")) == 0)) {
			verbose = 1;
			continue;
		}

		if ((strncmp(argv[i], "--retries", sizeof("--retries")) == 0) || 
			(strncmp(argv[i], "-r", sizeof("-r")) == 0)) {
			i++;
			if (i>=argc) {
				ret_msg = "missing numeric argument for --retries";
				ret = RET_INVALID_ARGUMENTS;
			}
			else {
				char *n = argv[i];
				if (!isnumber((const char *)n)) {
					ret_msg = "Invalid number of retries";
					ret = RET_INVALID_ARGUMENTS;
				}
				else {
					nbrRetries = atoi(argv[i]);
				}
			}
			continue;
		}

		if ((strncmp(argv[i], "--type", sizeof("--type")) == 0) || 
			(strncmp(argv[i], "-t", sizeof("-t")) == 0)) {
			i++;
			if (i>=argc) {
				ret_msg = "missing numeric argument for --type";
				ret = RET_INVALID_ARGUMENTS;
			}
			else {
				if (strncmp(argv[i], "authentication", sizeof("authentication")) == 0) {
					type = PINCODE_AUTHENTICATION;
				}
				else if (strncmp(argv[i], "signature", sizeof("signature")) == 0) {
					type = PINCODE_SIGNATURE;
				}
				else {
					ret_msg = "Invalid pincode type <authentication|signature>";
					ret = RET_INVALID_ARGUMENTS;
				}
			}
			continue;
		}

		if ((strncmp(argv[i], "--hash", sizeof("--hash")) == 0) || 
			(strncmp(argv[i], "-h", sizeof("-h")) == 0)) {
			i++;
			if (i>=argc) {
				ret_msg = "missing numeric argument for --hash";
				ret = RET_INVALID_ARGUMENTS;
			}
			else {
				char *h = argv[i];
				char c = '\0';
				int  cntr = 0;
				// Basic Hexidecimal validation
				while ((c = toupper(h[cntr])) != '\0') {
					if (( c < '0' || c > '9' ) && (c != 'A') && (c != 'B') && (c != 'C') && (c != 'D') && (c != 'E') && (c != 'F')) {
						ret_msg = "hash has invalid hexadecimal characters";
						ret = RET_INVALID_ARGUMENTS;
						break;
					}
					cntr++;
					// check on maximum hash size (512)
					if (cntr > 128) {
						ret_msg = "hash parameter exceed maximal value";
						ret = RET_INVALID_ARGUMENTS;
						break;
					}
				}
				if (ret == RET_OK) {
					hash = argv[i];
				}
			}
			continue;
		}
	}

	// Start the main application 
	if (ret == RET_OK) {

		// Extra validation checks
		if (type == 0) {
			ret_msg = "Pincode type (--type) is obligatory";
			ret = RET_INVALID_ARGUMENTS;
			goto cleanup;
		}
		if ((type == PINCODE_SIGNATURE) && (hash == NULL)) {
			ret_msg = "Signature type needs hash value for visualization";
			ret = RET_INVALID_ARGUMENTS;
			goto cleanup;
		}

		if (type == PINCODE_AUTHENTICATION) {
			ret = getAuthenticationPINCode(nbrRetries, pincode, &pincodeLg);
		}
		else {
			ret = getSignaturePINCode(nbrRetries, hash, pincode, &pincodeLg);			
		}
		if (ret != PINCODE_OK) {
			ret_msg="Get PIN code failed";
			goto cleanup;
		}
		else {
			ret_msg=std::string(pincode);
		}
	}
	else {
		goto cleanup;
	}

	ret = 0;
cleanup:
	
	if (ret == RET_OK) {
		print_json(ret, ret_msg.c_str());
	}
	else {
		print_json(ret, ret_msg.c_str());
	}
		
	closePINCode();
	
	return ret;
}