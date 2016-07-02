#ifndef __HTTP_H__
#define __HTTP_H__

#ifdef __cplusplus
extern "C" {
#endif

void http_global_init();
void http_global_release();
char *http_encode(const char *input, int length);
void http_free_encoded(const char *encoded);
void http_set_connect_timeout(long seconds);
void http_set_transfer_timeout(long seconds);
char *http_post(const char *url, const char *data, const char *content_type, size_t *resp_len);

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /*__HTTP_H__*/