#ifndef __BASE64_H__
#define __BASE64_H__

#ifdef __cplusplus
extern "C" {
#endif

char *base64_encode(const unsigned char *input, size_t length, size_t *out_len);
char *base64_decode(const unsigned char *input, size_t length, size_t *out_len);

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /*__BASE64_H__*/