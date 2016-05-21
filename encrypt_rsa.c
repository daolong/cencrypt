/**  
 *  Copyright (C) 2016 daolong.li@gmail.com
 */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "common.h"
#include "encrypt_rsa.h"
#include "common.h"

//note the line ending char \n is part of the key 
const static char *gPublicKey = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkxXb/sIXOMpElxpQSt+Y\n\
6Jqb1KzgqqOx9BSeoXO8QMAFh+9SZlHFSnFVSY18WVMOgDP/hNSLpi83RDdnU7Xg\n\
KXqkThM/TtLPyxfU/3MTVRUSlGop5X41zAO7L8sIBThdHWnr+EVNRJwiHRfIFnSO\n\
CGRznTwywpilb9BIKiMt008EXLReImUZ7BkkBELhCkKy4pfmcscUgp50C9Na/4DP\n\
J292wA96tUwFUKEFQJSpnC6UyxUdhk5CeVBwkhfVSjdJCMPsLV8mNWzK/FXeA6X1\n\
Ax7cDmhKHH+SdLph/Txrwm9nNfcxQROevf4Us6kHh8K8FhMWIzilriLDVQ+EsBTZ\n\
HwIDAQAB\n\
-----END PUBLIC KEY-----\n";

const static char *gPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAkxXb/sIXOMpElxpQSt+Y6Jqb1KzgqqOx9BSeoXO8QMAFh+9S\n\
ZlHFSnFVSY18WVMOgDP/hNSLpi83RDdnU7XgKXqkThM/TtLPyxfU/3MTVRUSlGop\n\
5X41zAO7L8sIBThdHWnr+EVNRJwiHRfIFnSOCGRznTwywpilb9BIKiMt008EXLRe\n\
ImUZ7BkkBELhCkKy4pfmcscUgp50C9Na/4DPJ292wA96tUwFUKEFQJSpnC6UyxUd\n\
hk5CeVBwkhfVSjdJCMPsLV8mNWzK/FXeA6X1Ax7cDmhKHH+SdLph/Txrwm9nNfcx\n\
QROevf4Us6kHh8K8FhMWIzilriLDVQ+EsBTZHwIDAQABAoIBACtvJBT6CdN6X4Dj\n\
g1xo5QWjSmsmVf3t8wnp4OI6hBf23GtE7+dJNGKETzQ2NMdH8JtJP6ZhAZAkl0Rs\n\
u/WLWtPE5Kotot9K/5OwyPRabhYM7/yl0RN1DrvdSjSV1xt7hnu+ILGi/WtKVASV\n\
Vj/TUXIG/+Epuq+eVhRLxFO1Kb4hP8PLbwNuVqfD9GSmM1qTENd/qk0V7MGRx+UG\n\
zEtBe/oBR3ZHE81xk9LJ/av3OrJOvMdMoIturCLkRFHUh9W+6HL7OynMbgvJEC83\n\
uPYTSHnj54RsOX7o8rDOYm3rL+aBl7Haa+ygPovIpTIPyEHYLkpS363kEUe1JMvl\n\
fwuEr/kCgYEAw4yfMEe9UOB64EWF+LSHVKfA0om698sFb5xJrueBWWurTm3S+X+2\n\
eoGvZprBJyxcRDPOqt0Wk8D0MpAxK5MJTOYOWU7IcIvrZhY81Xy7teFrgOIOc4AF\n\
yiQMUEndLu/EizYmlGgTorE9HfD9Qps4m/dqfuS7cSTsNLPGOMAwh5sCgYEAwI3m\n\
myvli50QfFN9xUirnxDO7pkAjZWicVScG5P1rm9ihBo44RQSopm+WvzNFdCydfj4\n\
pLAvjZOlwp22961hkjv6lPWIA/SSjRhCYaVtuZEncGLyLBM3h3LcI43qZdH/32E1\n\
5t7YLfH29eeM+8/DVZ66qPxhF/d2VeUaHQfZ5s0CgYEAvlVoOIkLNuZYE2T4Inws\n\
4PQrFYHjjv53+wunGGvTFeNbqQnyeNCbH6CMxhTI/kUKRYQbm2l4aTY9Od3pTh1e\n\
xw+BVeH97LXz2Li6W51942lWxurA4CDzAa6WoatTczUDG/EIGhk3S3qyHyuKhsMo\n\
lX57lKkz3MvwcNeuj1xZoBMCgYEAjc3y7oO9YLwiz+yMyyVhfptaSczT43E3WE7/\n\
SDAG1peg7biB+wBVWPnwfgF+53nyc38PXfmCi7kYceLERFKjcJZLTDgmGwOaid47\n\
xL2XuPl1GgdEYcElO9MS2/w/iwzEazWkBIpImk1/mkkUQr4XFI742EpFFulfdJJs\n\
UMTfbGECgYBbqu0tKzqUve7nLNRYuxI+fnl/BbV52/OHGa3PcjPAH+ruq4wMmVul\n\
L3Cu3gMil+a/xZhJOgqoskHJoBj6NIzj4GSaHrquFJ1aTlbB3U+d5qbHMVFyNWuk\n\
3oH45USzxIAukcLbfoeXQxyiMVEjSj/bhY3bxn4+Jfj712KnSPT3EA==\n\
-----END RSA PRIVATE KEY-----\n";

const static char *gPrivateKeyPkcs8 = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTFdv+whc4ykSX\n\
GlBK35jompvUrOCqo7H0FJ6hc7xAwAWH71JmUcVKcVVJjXxZUw6AM/+E1IumLzdE\n\
N2dTteApeqROEz9O0s/LF9T/cxNVFRKUainlfjXMA7svywgFOF0daev4RU1EnCId\n\
F8gWdI4IZHOdPDLCmKVv0EgqIy3TTwRctF4iZRnsGSQEQuEKQrLil+ZyxxSCnnQL\n\
01r/gM8nb3bAD3q1TAVQoQVAlKmcLpTLFR2GTkJ5UHCSF9VKN0kIw+wtXyY1bMr8\n\
Vd4DpfUDHtwOaEocf5J0umH9PGvCb2c19zFBE569/hSzqQeHwrwWExYjOKWuIsNV\n\
D4SwFNkfAgMBAAECggEAK28kFPoJ03pfgOODXGjlBaNKayZV/e3zCeng4jqEF/bc\n\
a0Tv50k0YoRPNDY0x0fwm0k/pmEBkCSXRGy79Yta08Tkqi2i30r/k7DI9FpuFgzv\n\
/KXRE3UOu91KNJXXG3uGe74gsaL9a0pUBJVWP9NRcgb/4Sm6r55WFEvEU7UpviE/\n\
w8tvA25Wp8P0ZKYzWpMQ13+qTRXswZHH5QbMS0F7+gFHdkcTzXGT0sn9q/c6sk68\n\
x0ygi26sIuREUdSH1b7ocvs7KcxuC8kQLze49hNIeePnhGw5fujysM5ibesv5oGX\n\
sdpr7KA+i8ilMg/IQdguSlLfreQRR7Uky+V/C4Sv+QKBgQDDjJ8wR71Q4HrgRYX4\n\
tIdUp8DSibr3ywVvnEmu54FZa6tObdL5f7Z6ga9mmsEnLFxEM86q3RaTwPQykDEr\n\
kwlM5g5ZTshwi+tmFjzVfLu14WuA4g5zgAXKJAxQSd0u78SLNiaUaBOisT0d8P1C\n\
mzib92p+5LtxJOw0s8Y4wDCHmwKBgQDAjeabK+WLnRB8U33FSKufEM7umQCNlaJx\n\
VJwbk/Wub2KEGjjhFBKimb5a/M0V0LJ1+PiksC+Nk6XCnbb3rWGSO/qU9YgD9JKN\n\
GEJhpW25kSdwYvIsEzeHctwjjepl0f/fYTXm3tgt8fb154z7z8NVnrqo/GEX93ZV\n\
5RodB9nmzQKBgQC+VWg4iQs25lgTZPgifCzg9CsVgeOO/nf7C6cYa9MV41upCfJ4\n\
0JsfoIzGFMj+RQpFhBubaXhpNj053elOHV7HD4FV4f3stfPYuLpbnX3jaVbG6sDg\n\
IPMBrpahq1NzNQMb8QgaGTdLerIfK4qGwyiVfnuUqTPcy/Bw166PXFmgEwKBgQCN\n\
zfLug71gvCLP7IzLJWF+m1pJzNPjcTdYTv9IMAbWl6DtuIH7AFVY+fB+AX7nefJz\n\
fw9d+YKLuRhx4sREUqNwlktMOCYbA5qJ3jvEvZe4+XUaB0RhwSU70xLb/D+LDMRr\n\
NaQEikiaTX+aSRRCvhcUjvjYSkUW6V90kmxQxN9sYQKBgFuq7S0rOpS97ucs1Fi7\n\
Ej5+eX8FtXnb84cZrc9yM8Af6u6rjAyZW6UvcK7eAyKX5r/FmEk6CqiyQcmgGPo0\n\
jOPgZJoeuq4UnVpOVsHdT53mpscxUXI1a6TegfjlRLPEgC6Rwtt+h5dDHKIxUSNK\n\
P9uFjdvGfj4l+PvXYqdI9PcQ\n\
-----END RSA PRIVATE KEY-----\n";

char *encrypt_publickey_fromfile(const char *input, char *pubkey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *en = NULL;
  int rsa_len = 0;
  int cipher_size = 0;
  
  if (input == NULL || pubkey_path == NULL) {
    DERROR("%s : bad argument\n", __func__);
    return NULL;
  }
  
  if ((fp = fopen(pubkey_path, "r")) == NULL) {
    DERROR("%s : open %s fail\n", __func__, pubkey_path);
    return NULL;
  }

  /* load public key */
  #if 0 // fail for PEM format, maybe for PKCS#1 format
  if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL) {
    DERROR("%s : PEM_read_RSAPublicKey fail\n", __func__);
    goto _fail;
  }
  #else
  rsa = RSA_new();
  if (PEM_read_RSA_PUBKEY(fp, &rsa, 0, 0) == NULL) {
    DERROR("%s : PEM_read_RSA_PUBKEY fail\n", __func__);
    goto _fail;
  }  
  #endif
  if (LOGV) RSA_print_fp(stdout, rsa, 0); 

  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  en = (char *)malloc(rsa_len + 1);
  if (en == NULL) goto _fail;
  memset(en, 0, rsa_len + 1);

  //cipher_size = RSA_public_encrypt(rsa_len, (unsigned char *)input, (unsigned char*)en, rsa, RSA_PKCS1_OAEP_PADDING);
  cipher_size = RSA_public_encrypt(rsa_len, (unsigned char *)input, (unsigned char*)en, rsa, RSA_NO_PADDING);
  DEBUG("%s : cipher_size = %d \n", __func__, cipher_size);
  if (cipher_size < 0) {
    DERROR("%s : RSA_public_encrypt fail\n", __func__);
    free(en);
    en = NULL;
    goto _fail;
  }
  
_fail:
  if (rsa != NULL) RSA_free(rsa);
  if (fp != NULL) fclose(fp); 
  return en;
}
 
char *decrypt_privatekey_fromfile(const char *input, char *prikey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *de = NULL;
  int rsa_len = 0;
  int plain_size = 0;
  
  if (input == NULL || prikey_path == NULL) {
    DERROR("%s : bad argument\n", __func__);
    return NULL;
  }
  
  if ((fp = fopen(prikey_path, "r")) == NULL) {
    DERROR("%s : open %s fail\n", __func__, prikey_path);
    return NULL;
  }

  if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
    DERROR("%s : PEM_read_RSAPrivateKey fail\n", __func__);
    goto _fail;
  }
  if (LOGV) RSA_print_fp(stdout, rsa, 0);

  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  de = (char *)malloc(rsa_len + 1);
  if (de == NULL) goto _fail;
  memset(de, 0, rsa_len + 1);

  //plain_size = RSA_private_decrypt(rsa_len, (unsigned char *)input, (unsigned char*)de, rsa, RSA_PKCS1_OAEP_PADDING);
  plain_size = RSA_private_decrypt(rsa_len, (unsigned char *)input, (unsigned char*)de, rsa, RSA_NO_PADDING);
  DEBUG("%s : plain_size = %d \n", __func__, plain_size);
  if (plain_size < 0) {
    DERROR("%s : RSA_private_decrypt fail\n", __func__);
    free(de);
    de = NULL;
    goto _fail;
  }
  
_fail:    
  if (rsa != NULL) RSA_free(rsa);
  if (fp != NULL) fclose(fp); 
  return de;
}

char *encrypt_privatekey_fromfile(const char *input, char *prikey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *en = NULL;
  int rsa_len = 0;
  int cipher_size = 0;
  
  if (input == NULL || prikey_path == NULL) {
    DERROR("%s : bad argument\n", __func__);
    return NULL;
  }
  
  if ((fp = fopen(prikey_path, "r")) == NULL) {
    DERROR("%s : open %s fail\n", __func__, prikey_path);
    return NULL;
  }

  if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
    DERROR("%s : PEM_read_RSAPrivateKey fail\n", __func__);
    goto _fail;
  }
  if (LOGV) RSA_print_fp(stdout, rsa, 0);

  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  en = (char *)malloc(rsa_len + 1);
  if (en == NULL) goto _fail;
  memset(en, 0, rsa_len + 1);  
  
  //cipher_size = RSA_private_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_PKCS1_PADDING);  
  //cipher_size = RSA_private_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_PKCS1_OAEP_PADDING); 
  cipher_size = RSA_private_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_NO_PADDING); 
  if (cipher_size < 0) {
    DERROR("%s : RSA_private_encrypt fail\n", __func__);
    free(en);
    en = NULL;
    goto _fail;
  }
  
_fail:
  if (rsa != NULL) RSA_free(rsa);
  if (fp != NULL) fclose(fp); 
  return en;
}

char *decrypt_publickey_fromfile(const char *input, char *pubkey_path) {
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *de = NULL;
  int rsa_len = 0;
  int plain_size = 0;
  
  if (input == NULL || pubkey_path == NULL) {
    DERROR("%s : bad argument\n", __func__);
    return NULL;
  }
  
  if ((fp = fopen(pubkey_path, "r")) == NULL) {
    DERROR("%s : open %s fail\n", __func__, pubkey_path);
    return NULL;
  }

  /* load public key */
  rsa = RSA_new();
  if (PEM_read_RSA_PUBKEY(fp, &rsa, 0, 0) == NULL) {
    DERROR("%s : PEM_read_RSA_PUBKEY fail\n", __func__);
    goto _fail;
  }  

  if (LOGV) RSA_print_fp(stdout, rsa, 0); 

  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  de = (char *)malloc(rsa_len + 1);
  if (de == NULL) goto _fail;
  memset(de, 0, rsa_len + 1);  
  
  //plain_size =  RSA_public_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de, rsa, RSA_PKCS1_PADDING);  
  //plain_size =  RSA_public_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de rsa, RSA_PKCS1_OAEP_PADDING);  
  plain_size =  RSA_public_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de, rsa, RSA_NO_PADDING);  
  DEBUG("%s : plain_size = %d \n", __func__, plain_size);
  if (plain_size < 0) {
    DERROR("%s : RSA_public_decrypt fail\n", __func__);
    free(de);
    de = NULL;
    goto _fail;
  }
  
_fail:    
  if (rsa != NULL) RSA_free(rsa);
  if (fp != NULL) fclose(fp); 
  return de;  
}

char *encrypt_publickey_fromcode(const char *input)
{
  int rsa_len = 0;
  int cipher_size = 0;
  RSA *rsa = NULL;
  char *en = NULL;    
  rsa = RSA_new() ;
  //load string key to bio object
  BIO* mem_bio = BIO_new_mem_buf((void*)gPublicKey, strlen(gPublicKey));
  if (mem_bio == NULL) return NULL;
  //convert bio to a key
  //rsa = PEM_read_bio_RSA_PUBKEY(mem_bio, NULL, NULL, NULL);
  rsa = PEM_read_bio_RSA_PUBKEY(mem_bio, &rsa, NULL, NULL);
  // return key size in byte
  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  en = (char *)malloc(rsa_len + 1);
  if (en == NULL) goto _fail;
  memset(en, 0, rsa_len + 1);

  // Encrypting using loaded public key
  //cipher_size = RSA_public_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_PKCS1_OAEP_PADDING);
  cipher_size = RSA_public_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_NO_PADDING);
  DEBUG("%s : cipher_size = %d \n", __func__, cipher_size);
  if (cipher_size < 0) {
    free(en);
    en = NULL;
    goto _fail;
  }
  
_fail:
  if (mem_bio != NULL) BIO_free(mem_bio);
  if (rsa != NULL) RSA_free(rsa);
  return en;
}

char *decrypt_privatekey_fromcode(const char *input)
{
  char *de = NULL;
  int rsa_len = 0;
  int plain_size = 0;
  RSA* rsa = RSA_new() ;
  BIO* mem_bio = BIO_new_mem_buf((void*)gPrivateKeyPkcs8, strlen(gPrivateKeyPkcs8));
  if (mem_bio == NULL) return NULL;
  // rsa = PEM_read_bio_RSAPrivateKey(mem_bio, NULL, NULL, NULL);
  rsa = PEM_read_bio_RSAPrivateKey(mem_bio, &rsa, NULL, NULL);
  if (rsa == NULL) goto _fail;
  
  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  de = (char *)malloc(rsa_len + 1);
  if (de == NULL) goto _fail;
  memset(de, 0, rsa_len + 1);
  
  //plain_size = RSA_private_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de, rsa, RSA_PKCS1_OAEP_PADDING);
  plain_size = RSA_private_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de, rsa, RSA_NO_PADDING);
  DEBUG("%s : plain_size = %d \n", __func__, plain_size);
  if (plain_size < 0) {
    free(de);
    de = NULL;
    goto _fail;
  }

_fail:  
  if (mem_bio != NULL) BIO_free(mem_bio);
  if (rsa != NULL) RSA_free(rsa);  
  return de;
}


char *encrypt_privatekey_fromcode(const char *input)
{
  char *en = NULL;
  int rsa_len = 0;
  int cipher_size = 0;
  RSA* rsa = RSA_new() ;
  BIO* mem_bio = BIO_new_mem_buf((void*)gPrivateKeyPkcs8, strlen(gPrivateKeyPkcs8));
  if (mem_bio == NULL) return NULL;
  // rsa = PEM_read_bio_RSAPrivateKey(mem_bio, NULL, NULL, NULL);
  rsa = PEM_read_bio_RSAPrivateKey(mem_bio, &rsa, NULL, NULL);
  if (rsa == NULL) goto _fail;
  
  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  en = (char *)malloc(rsa_len + 1);
  if (en == NULL) goto _fail;
  memset(en, 0, rsa_len + 1);  
  
  //cipher_size = RSA_private_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_PKCS1_OAEP_PADDING);
  cipher_size = RSA_private_encrypt(rsa_len, (unsigned char *)input, (unsigned char *)en, rsa, RSA_NO_PADDING);
  DEBUG("%s : cipher_size = %d \n", __func__, cipher_size);
  if (cipher_size < 0) {
    DERROR("%s : RSA_private_encrypt fail\n", __func__);
    free(en);
    en = NULL;
    goto _fail;
  }
  
_fail:
  if (mem_bio != NULL) BIO_free(mem_bio);
  if (rsa != NULL) RSA_free(rsa);
  return en;
}

char *decrypt_publickey_fromcode(const char *input)
{
  int rsa_len = 0;
  int plain_size = 0;
  RSA *rsa = NULL;
  char *de = NULL;    
  rsa = RSA_new() ;
  //load string key to bio object
  BIO* mem_bio = BIO_new_mem_buf((void*)gPublicKey, strlen(gPublicKey));
  if (mem_bio == NULL) return NULL;
  //convert bio to a key
  //rsa = PEM_read_bio_RSA_PUBKEY(mem_bio, NULL, NULL, NULL);
  rsa = PEM_read_bio_RSA_PUBKEY(mem_bio, &rsa, NULL, NULL);
  // return key size in byte
  rsa_len = RSA_size(rsa);
  DEBUG("%s : rsa_len = %d \n", __func__, rsa_len);
  de = (char *)malloc(rsa_len + 1);
  if (de == NULL) goto _fail;
  memset(de, 0, rsa_len + 1);  
  
  plain_size =  RSA_public_decrypt(rsa_len, (unsigned char *)input, (unsigned char *)de, rsa, RSA_NO_PADDING);  
  DEBUG("%s : plain_size = %d \n", __func__, plain_size);
  if (plain_size < 0) {
    DERROR("%s : RSA_public_decrypt fail\n", __func__);
    free(de);
    de = NULL;
    goto _fail;
  }
  
_fail:    
  if (mem_bio != NULL) BIO_free(mem_bio);
  if (rsa != NULL) RSA_free(rsa);
  return de;    
}