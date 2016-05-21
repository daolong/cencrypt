#ifndef __HTTP_H__
#define __HTTP_H__

#ifdef __cplusplus
extern "C" {
#endif

char * http_post(const char *url, const char *data, const char *content_type, size_t *resp_len);

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /*__HTTP_H__*/