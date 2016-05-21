#ifndef __ENCRYPT_RSA_H__
#define __ENCRYPT_RSA_H__

#ifdef __cplusplus
extern "C" {
#endif

char *encrypt_publickey_fromfile(const char *input, char *pubkey_path);
char *decrypt_privatekey_fromfile(const char *input, char *prikey_path);
char *encrypt_privatekey_fromfile(const char *input, char *prikey_path);
char *decrypt_publickey_fromfile(const char *input, char *pubkey_path);
char *encrypt_publickey_fromcode(const char *input);
char *decrypt_privatekey_fromcode(const char *input);
char *encrypt_privatekey_fromcode(const char *input);
char *decrypt_publickey_fromcode(const char *input);

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /*__ENCRYPT_RSA_H__*/