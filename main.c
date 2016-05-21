#include "common.h"
#include "encrypt_rsa.h"
#include "encrypt_des.h"
#include "base64.h"

#define PRIVATE_KEY_FILE "private.pem"
#define PUBLIC_KEY_FILE "public.pem"

#define TEST_NAME "Daolong Li"
#define TEST_NUMBER "9876543210"
#define TEST_CLASS "Electronic Science And Technology 03"
#define TEST_MEMO "GuangXi Univercity"


static char *gTestData0 = "Da wang jiao wo lai xun shan";

static char *gTestData1 = "\"The Story of the Stone\" (c. 1760), also known as \"The Dream of the Red Chamber\", is one of the greatest novels of Chinese literature. The fifth part of Cao Xueqin's magnificent saga, \"The Dreamer Awakes\", was carefully edited and completed by Gao E some decades later. It continues the story of the changing fortunes of the Jia dynasty, focussing on Bao-yu, now married to Bao-chai, after the tragic death of his beloved Dai-yu. Against such worldly elements as death, financial ruin, marriage, decadence and corruption, his karmic journey unfolds. Like a sleepwalker through life, Bao-yu is finally awakened by a vision, which reveals to him that life itself is merely a dream, 'as moonlight mirrored in the water'. ";

static char *gPassword = "xiyouji8";

static void rsa_test_code() 
{
  DTRACE("\n\n== rsa_test_code ==\n");
  DTRACE("encrypt public, decrypt private \n");
  char *cipher = encrypt_publickey_fromcode(gTestData0); 
  if (cipher != NULL) {
    char *plaintext = decrypt_privatekey_fromcode(cipher);
    if (plaintext != NULL) {
      DEBUG("The plaintext = %s \n", plaintext);
      free(plaintext);
      plaintext = NULL;
    }
    free(cipher);
    cipher = NULL;
  }
  
  DTRACE("\n\n  encrypt private, decrypt public\n");
  cipher = encrypt_privatekey_fromcode(gTestData0); 
  if (cipher != NULL) {
    char *plaintext = decrypt_publickey_fromcode(cipher);
    if (plaintext != NULL) {
      DEBUG("The plaintext = %s \n", plaintext);
      free(plaintext);
      plaintext = NULL;
    }
    free(cipher);
    cipher = NULL;
  }
}

static void rsa_test_file() 
{
  DEBUG("\n\n== rsa_test_file ==\n");
  DTRACE("encrypt public, decrypt private \n");
  char *cipher = encrypt_publickey_fromfile(gTestData0, PUBLIC_KEY_FILE);
  if (cipher != NULL) {
     char *plaintext = decrypt_privatekey_fromfile(cipher, PRIVATE_KEY_FILE); 
     if (plaintext != NULL) {
      DEBUG("The plaintext = %s \n", plaintext);
      free(plaintext);
     }
     free(cipher);
  }  
  
  DTRACE("\n\n  encrypt private, decrypt public\n");
  cipher = encrypt_privatekey_fromfile(gTestData0, PRIVATE_KEY_FILE); 
  if (cipher != NULL) {
    char *plaintext = decrypt_publickey_fromfile(cipher, PUBLIC_KEY_FILE);
    if (plaintext != NULL) {
      DEBUG("The plaintext = %s \n", plaintext);
      free(plaintext);
      plaintext = NULL;
    }
    free(cipher);
    cipher = NULL;
  }
}

static void rsa_test() 
{
  rsa_test_code();
  rsa_test_file(); 
}

static void base64_test()
{
    size_t out_len = 0;
    DEBUG("\n\n== base64_test ==\n");
    char *encode = (char *)base64_encode((const unsigned char *)gTestData1, strlen(gTestData1), &out_len);
    if (encode != NULL) {
      DEBUG("base64 encode string = %s \n", encode);
      char *decode = (char *)base64_decode((const unsigned char *)encode, strlen(encode), &out_len);
      if (decode != NULL) {
        DEBUG("base64 decode string = %s \n", decode);
        free(decode);
      }
      free(encode);
    }
}

static void base64_encode_test() {
  char buffer[1024];
  size_t out_len = 0;
  DO_CLEAR(buffer, 0, 1024);
  sprintf(buffer, "{\"name\"=\"%s\", \"number\"=\"%s\", \"class\"=\"%s\", \"memo\"=\"%s\"}",
    TEST_NAME, TEST_NUMBER, TEST_CLASS, TEST_MEMO);  
  char *encode = (char *)base64_encode((const unsigned char *)buffer, strlen(buffer), &out_len);
  DEBUG("\n\n== base64_encode_test ==\n");  
  if (encode != NULL) {
      DEBUG("base64 encode string = %s \n", encode);
      char *decode = (char *)base64_decode((const unsigned char *)encode, strlen(encode), &out_len);
      if (decode != NULL) {
        DEBUG("base64 decode string = %s \n", decode);
        free(decode);
      }
      free(encode);
    }
}
static void base64_decode_test()
{
  size_t out_len = 0;
  char *data = "AQu5tipIFxrn5lQd1LqVfXH+/eoAVvjazvF8nmNiD8sRbCtNRkjnT/vnFU3dFi1LEGmwTHgKma1KKa/ppB3cISm5pqGYRuKq7J0bhbaDkWtI3Pzi9ZdodLNBzkelCUHzBfqkZMEBk0SeMvWq7NbzQtPQGQZitukPjgP4u5dwGWstADdak6XKTzz0YgQ1Yp00jy/oFhXpq8sftFvaR2USXZE71WvHeg3a89yyVKUw+je/FEwndLaJVW5y3xldESU+A0nD3eVyrFVWRMj598BLBrHd/vI0+tpeUbozNlB3e4P3cNH+zd72gfEUkwTpfep90q0dKarJSoXp4viGPH3D1A==";
  char *decode = (char *)base64_decode((const unsigned char *)data, strlen(data), &out_len);
  DEBUG("\n\n== base64_decode_test ==\n");  
  if (decode != NULL) {
    int len = strlen(decode);
    DEBUG("length = %d\n", len);
    int i = 0;
    for (i = 0; i < len; i++) {
      DEBUG("%x ", (unsigned char)decode[i]);
    }
    DEBUG("\n");
    free(decode);
  }
}

#define URL "http://192.168.11.201:8085/auth?"
#define DUMP_RESPONSE 0
/*
static char *gResponseTestData = "HTTP/1.1 200 OK\n\
Content-Length: 38\n\
Server: http-kit\n\
Date: Wed, 18 May 2016 06:24:39 GMT\n\
\n\
Da wang shang ni yi kuai tang seng rou\n";
*/
static char *gResponseTestData = "HTTP/1.1 200 OK\n\
Content-Length: 349\n\
Server: http-kit\n\
Date: Thu, 19 May 2016 01:47:11 GMT\n\
\n\
D4Z4p/kWm+Py9AvuYf4POuHc6o1v5ZCn5QvIQr068Eprpm01rCKW7Q8fDIwfeQlcRZ3qONaA+DEt\n\
XbzLtOLwpYBG90dp63+XdgoFVkEx7FilGR2Ap8ol4vyD/Sqjwx2JpLgeXNXKhw55/PjMaC2drIii\n\
DeoDyVnvybU53r9UhB4fYQa8PnLo0BU7Df+8BNrTSaY4KJ95YTbMFFoJDVFxiC2doA3KaV7+D+VR\n\
eNz1iRWgvObetwQjHw4gJqfIMYi4mYWQJ30kHypU4earMsd+2HTk9TKed7nwPIsc+HOVFwyvr8TT\n\
KMrJObuZSUoRtqTVBbg1qkEJHrAe/D3EaWSKbg==";

/**
*@brief Geting content of response from server
*HACK: Now return the last line as content. 
*/
static char *getContent(const char *response, size_t size)
{
  int start = 0, end = 0;
  int i = 0, j = 0, l = 0;
  char line[10][1024];
  char *content = NULL;
  int content_size = 0;
  if (response == NULL || size <= 0) return NULL;
  #if DUMP_RESPONSE
  for (i = 0;  i < size; i++) 
    DEBUG("%x ", response[i]);
  DEBUG("\n");
  i = 0;
  #endif
  
  while(i < size) {
    while(response[i] != '\n') i++;
    //DEBUG("response[%d] = %x\n", i - 1, response[i - 1]);
    //DEBUG("response[%d] = %x\n", i, response[i]);
    end = i + 1;
    if (j < 10 && (end - start < 1024)) {
      DO_MEMCPY(line[j], (response + start), (end - start));
      //DEBUG("line len = %d\n", strlen(line[j]));
      if (strncmp(line[j], "Content-Length", strlen("Content-Length")) == 0) {
        char lenstr[10];
        int linelen = end - start;
        int k = 0;
        char *endptr;
        int prefixlen = strlen("Content-Length: ");
        DO_MEMCPY(lenstr, line[j] + prefixlen, linelen - prefixlen);
        //DEBUG("Content-Length: %s\n", lenstr);
        for (k = 0; k < (linelen - prefixlen); k++) {
          if (lenstr[k] == '\r' || lenstr[k] == '\n') {
            lenstr[k] = '\0';
          }  
        }
        content_size = strtoul(lenstr, &endptr, 0);
        DEBUG("Content Size: %d\n", content_size);
      }       
      j++;
    }
    start = end;
    i = end;
  }
  #if DUMP_RESPONSE
  DEBUG("j = %d \n", j);
  for (i = 0; i < j; i++) {
    DEBUG("line[%d] = %s \n", i, line[i]);
  }
  #endif
  if (content_size != 0) {
    start = size - content_size;
    content = DO_MALLOC(content_size + 1);
    if (content != NULL) {
      DO_CLEAR(content, 0, content_size + 1);
      DO_MEMCPY(content, response + start, content_size);
    }
  }
  
  return content;
}

static void getcontent_test() {
  DEBUG("\n\n== getcontent_test ==\n");  
  char *content = getContent(gResponseTestData, strlen(gResponseTestData));
  if (content != NULL) {
    DEBUG("content = %s\n", content);
    DO_FREE(content);
  }
}

static char *base64encode(const char *s, size_t *out_len) {
  return (char *)base64_encode(s, strlen(s), out_len); 
}

static char *base64encode_rsa(const char *s, size_t *out_len) {
  return (char *)base64_encode(s, 256, out_len); 
}

static char *base64encode_fixed(const char *s, int size, size_t *out_len) {
  return (char *)base64_encode(s, size, out_len);
}

static char *base64decode(const char *s, size_t *out_len) {
  return (char *)base64_decode(s, strlen(s), out_len); 
}

static char *base64decode_rsa(const char *s, size_t *out_len) {
  return (char *)base64_decode(s, 256, out_len); 
}

static char *base64decode_fixed(const char *s, int size, size_t *out_len) {
  return (char *)base64_decode(s, size, out_len);
}

static void http_test() 
{
  DEBUG("\n\n== http_test ==\n");  
  size_t resp_size = 0;
  char buffer[1024];
  size_t out_len = 0;
  DO_CLEAR(buffer, 0, 1024);
  sprintf(buffer, "name=%s&number=%s&class=%s&memo=%s", base64encode(TEST_NAME, &out_len),  base64encode(TEST_NUMBER, &out_len),
     base64encode(TEST_CLASS, &out_len),  base64encode(TEST_MEMO, &out_len));
  DEBUG("param = %s\n", buffer);
  char *res = http_post(URL, (const char *)&buffer, NULL, &resp_size);
  if (res != NULL) {
    DEBUG("%s : response =\n%s \n", __func__, res);
    char *content = getContent(res, resp_size);
    if (content != NULL) {
      DEBUG("content base64 = %s\n", content);
      char *decode = base64_decode((const unsigned char *)content, strlen(content), &out_len);
      if (decode != NULL) {
        DEBUG("content plaintext = %s \n", decode);
        DO_FREE(decode);
      }
      DO_FREE(content);
    }
    DO_FREE(res);
  }
}

void dump(const unsigned char *data) {
  int l = strlen(data);
  int i = 0;
  for (i = 0; i < 256; i++) {
    DEBUG("%x ", data[i]);
  }
  
  DEBUG("\n");
}

static void flow_test() {
  DEBUG("\n\n== flow_test ==\n");  
  size_t resp_size = 0;
  size_t out_len = 0;
  char buffer[1024];
  DO_CLEAR(buffer, 0, 1024);
  sprintf(buffer, "{\"name\"=\"%s\", \"number\"=\"%s\", \"class\"=\"%s\", \"memo\"=\"%s\"}", 
    TEST_NAME, TEST_NUMBER, TEST_CLASS, TEST_MEMO);
  DEBUG("param = %s\n", buffer);  
  int len = strlen(buffer);
  char *cipher = encrypt_publickey_fromcode(buffer);   
  if (cipher != NULL) {
    DEBUG("The cipher text = %s \n", cipher);
    dump((const unsigned char *)cipher);
    char *encoded = base64encode_rsa(cipher,&out_len);
    if (encoded != NULL) {
      DEBUG("%s : encoded = %s \n", __func__, encoded);
      char *decode = base64decode((const unsigned char *)encoded, &out_len);
      if (decode != NULL) {
        DEBUG("local : content encrypted = %s \n", decode);
        dump((const unsigned char *)decode);
        char *plaintext = decrypt_privatekey_fromcode(decode);
        if (plaintext != NULL) {
            DEBUG("local : content decrypted = %s \n", plaintext);
            DO_FREE(plaintext);
        }
        DO_FREE(decode);
      }
    }
    
    char *plaintext_local = decrypt_privatekey_fromcode(cipher);
    if (plaintext_local != NULL) {
        DEBUG("content decrypted local = %s \n", plaintext_local);
        DO_FREE(plaintext_local);
    }
    
    free(cipher);
    cipher = NULL;
  }   
}

// HACK : encrypted data from server decrypt fail!!!
// TODO : check difference between local and server?
static void auth_rsa_test()
{
  DEBUG("\n\n== auth_rsa_test ==\n");  
  size_t resp_size = 0;
  char buffer[512];
  DO_CLEAR(buffer, 0, 512);
  size_t out_len = 0;
  sprintf(buffer, "{\"name\"=\"%s\", \"number\"=\"%s\", \"class\"=\"%s\", \"memo\"=\"%s\"}", 
    TEST_NAME, TEST_NUMBER, TEST_CLASS, TEST_MEMO);
  DEBUG("param = %s\n", buffer);  
  char *cipher = encrypt_publickey_fromcode(buffer);   
  if (cipher != NULL) {
    DEBUG("The cipher text = %s \n", cipher);
    char *encoded = base64encode_rsa(cipher, &out_len);
    if (encoded != NULL) {
      DO_CLEAR(buffer, 0, 512);
      sprintf(buffer, "data=%s", encoded);
      DEBUG("%s : encoded = %s \n", __func__, encoded);
      char *res = http_post(URL, (const char *)&buffer, NULL, &resp_size);
      if (res != NULL) {
        DEBUG("%s : response =\n%s \n", __func__, res);
        char *content = getContent(res, resp_size);
        if (content != NULL) {
          DEBUG("content base64 = %s\n", content);
          char *decode = base64_decode((const unsigned char *)content, strlen(content), &out_len);
          if (decode != NULL) {
            DEBUG("content encrypted len = %d \n", out_len);
            DEBUG("content encrypted = %s \n", decode);
            dump(decode);
            //char *plaintext = decrypt_privatekey_fromcode(decode);
            char *plaintext = decrypt_publickey_fromcode(decode);
            if (plaintext != NULL) {
                DEBUG("content decrypted = %s \n", plaintext);
                DO_FREE(plaintext);
            }
            DO_FREE(decode);
          }
          DO_FREE(content);
        }
        DO_FREE(res);
      }
    }
    
    char *plaintext_local = decrypt_privatekey_fromcode(cipher);
    if (plaintext_local != NULL) {
        DEBUG("content decrypted local = %s \n", plaintext_local);
        DO_FREE(plaintext_local);
    }
    
    free(cipher);
    cipher = NULL;
  } 
}

static void des_dump(const char *data, size_t size) {
  if (data == NULL || size == 0) return;
  size_t i = 0;
  for (i = 0; i < size; i++) {
    DEBUG("%x ", (unsigned char)data[i]);
  }
  DEBUG("\n");
}

static char *des_getmode(int mode) {
  switch(mode) {
    case GENERAL: return "GENERAL"; break;
    case ECB: return "ECB"; break;
    case CBC: return "CBC"; break;
    case CFB: return "CFB"; break;
    case OFB: return "OFB"; break;
    case TRIPLE_ECB: return "TRIPLE_ECB"; break;
    case TRIPLE_CBC: return "TRIPLE_CBC"; break;
    default: return "UNKNOWN"; break;
  }
}

static void des_test_withmode(int mode)
{
  DEBUG("\n\n== des_test_withmode (%s) ==\n", des_getmode(mode));  
  char *testData = (char *)gTestData0;
  size_t out_len = 0;
  char *encrypted = encrypt_des((const char*)testData, strlen(testData), gPassword, mode, &out_len);
  if (encrypted != NULL) {
    des_dump(encrypted, out_len);
    char *plain = decrypt_des(encrypted, out_len, gPassword, mode, &out_len);
    if (plain != NULL) {
      DEBUG("%s : plain text =\n%s \n", __func__, plain);
      if (strncmp(plain, testData, strlen(testData)) == 0) {
        DEBUG("%s : Success \n", __func__);
      } else {
        DEBUG("%s : Fail \n", __func__);
      }
      DO_FREE(plain);
    }
    DO_FREE(encrypted);
  }
}

static void des_test() {
    des_test_withmode(ECB);
    des_test_withmode(CBC);
    des_test_withmode(CFB);
    des_test_withmode(TRIPLE_ECB);
    des_test_withmode(TRIPLE_CBC);
}

int main(int argc, char **argv)
{
  //rsa_test();
  //base64_test();
  //base64_encode_test();
  //base64_decode_test();
  //getcontent_test();
  //http_test(); 
  //flow_test();
  //auth_rsa_test();  
  //des_test();
  return 0;
}
