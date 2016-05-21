#ifndef __ENCRYPT_DES_H__
#define __ENCRYPT_DES_H__

enum {
	GENERAL = 0,
	ECB,
	CBC,
	CFB,
	OFB,
	TRIPLE_ECB,
	TRIPLE_CBC
};

#ifdef __cplusplus
extern "C" {
#endif

char *encrypt_des(const char *leartext, size_t in_len, const char *key, int mode, size_t *out_len);
char *decrypt_des(const char *ciphertext, size_t in_len, const char *key, int mode, size_t *out_len);

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /*__ENCRYPT_DES_H__*/