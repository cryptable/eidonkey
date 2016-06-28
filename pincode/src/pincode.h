#ifndef PINCODE_H
#define PINCODE_H

#define PINCODE_OK 					0
#define PINCODE_NOT_ENTERED			1
#define PINCODE_BUFFER_TOO_SMALL	2
#define PINCODE_BUFFER_UNDEFINED	3

#ifdef __cplusplus
extern "C" {
#endif
	void initPINCode(void);
	unsigned long getAuthenticationPINCode(unsigned int nbrRetries, char *pinCode, unsigned long *len);
	unsigned long getSigningPINCode(unsigned int nbrRetries, char *pinCode, unsigned long *len);
	void closePINCode(void);
#ifdef __cplusplus
}
#endif

#endif