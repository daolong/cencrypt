/**  
 *  Copyright (C) 2016 daolong.li@gmail.com
 */
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "common.h"
#include "base64.h"


char *base64_encode(const unsigned char *input, size_t length, size_t *out_len) 
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;
  char *buff = NULL;
  if (input == NULL) return NULL;
  
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // don't with new line
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  DEBUG("%s : in_len (%d), out_len (%d) \n", __func__, length, (int)bptr->length);
  buff = (char *)malloc(bptr->length+1);
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = '\0';
  *out_len = bptr->length;
  
  BIO_free_all(b64);
  
  return buff;
}

char *base64_decode(const unsigned char *input, size_t length, size_t *out_len)
{
  BIO *b64, *bmem;
  char *buffer = NULL;
  if (input == NULL) return NULL;
  buffer = (char *)malloc(length + 1);
  if (buffer == NULL) return NULL;
  memset(buffer, 0, length+1);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf((void *)input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);
  buffer[length] = '\0';
  DEBUG("%s : in_len (%d), out_len (%d) \n", __func__, length, (int)strlen(buffer));
  *out_len =  strlen(buffer);
  BIO_free_all(bmem);

  return buffer;    
}