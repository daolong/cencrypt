#include <openssl/des.h>
#include <string.h>
#include "encrypt_des.h"

static unsigned char cbc_iv[8] = {'0', '1', 'A', 'B', 'a', 'b', '9', '8'};

char *encrypt_des(const char *cleartext, size_t in_len, const char *key, int mode, size_t *out_len)
{
	switch (mode) {
    case GENERAL:
    case ECB:
    {
      size_t i = 0;
      DES_cblock keyEncrypt;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8;
      unsigned char *cipher = (unsigned char *)malloc(*out_len);
      if (cipher == NULL) return NULL;
      memset(cipher, 0, *out_len);  
      
      memset(&keyEncrypt, 0, 8);
      if (key_len <= 8) 
        memcpy((void*)&keyEncrypt, key, key_len);
      else 
        memcpy((void*)&keyEncrypt, key, 8);

      DES_key_schedule keySchedule;
      DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

      const_DES_cblock inputText;
      DES_cblock outputText;
      
      for (i = 0; i < text_len / 8; i ++) {
        memcpy((void*)&inputText, (cleartext + i * 8), 8);
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
        memcpy((cipher + i * 8), (void*)&outputText, 8);
      }

      if (text_len % 8 != 0) {
        int tmp1 = text_len / 8 * 8;
        int tmp2 = text_len - tmp1;
        memset((void*)&inputText, 0, 8);
        memcpy((void*)&inputText, cleartext + tmp1, tmp2);

        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
        memcpy(cipher + tmp1, (void*)&outputText, 8);
      }
      return (char *)cipher;
    }
    break;
    case CBC:
    {
      DES_cblock keyEncrypt, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8;  
      unsigned char *cipher = (unsigned char*)malloc(*out_len + 16);
      if (cipher == NULL) return NULL;
      memset(cipher, 0, *out_len);
      
      memset((void*)&keyEncrypt, 0, 8);
      if (key_len <= 8) 
        memcpy((void*)&keyEncrypt, key, key_len);
      else 
        memcpy((void*)&keyEncrypt, key, 8);

      DES_key_schedule keySchedule;
      DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

      memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv)); 
      DES_ncbc_encrypt((const unsigned char*)cleartext, cipher, text_len, &keySchedule, &ivec, DES_ENCRYPT);

      return (char *)cipher;
    }
    break;
    case CFB:
    {
      DES_cblock keyEncrypt, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8;   
      unsigned char *cipher = (unsigned char*)malloc(*out_len);
      if (cipher == NULL) return NULL;
      memset(cipher, 0, *out_len);
      
      memset((void*)&keyEncrypt, 0, 8);
      if (key_len <= 8) 
        memcpy((void*)&keyEncrypt, key, key_len);
      else 
        memcpy((void*)&keyEncrypt, key, 8);

      DES_key_schedule keySchedule;
      DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

      memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv));
      DES_cfb_encrypt((const unsigned char*)cleartext, cipher, 8, text_len, &keySchedule, &ivec, DES_ENCRYPT);

      return (char *)cipher;
    }
    break;
    case TRIPLE_ECB:
    {
      size_t i = 0;
      DES_cblock ke1, ke2, ke3;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8;  
      unsigned char *cipher = malloc(*out_len);
      if (cipher == NULL) return NULL;
      memset(cipher, 0, *out_len);
      
      memset((void*)&ke1, 0, 8);
      memset((void*)&ke2, 0, 8);
      memset((void*)&ke2, 0, 8);
      if (key_len >= 24) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, 8);
        memcpy((void*)&ke3, key + 16, 8);
      } else if (key_len >= 16) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, 8);
        memcpy((void*)&ke3, key + 16, key_len - 16);
      } else if (key_len >= 8) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, key_len - 8);
        memcpy((void*)&ke3, key, 8);
      } else {
        memcpy((void*)&ke1, key, key_len);
        memcpy((void*)&ke2, key, key_len);
        memcpy((void*)&ke3, key, key_len);
      }

      DES_key_schedule ks1, ks2, ks3;
      DES_set_key_unchecked(&ke1, &ks1);
      DES_set_key_unchecked(&ke2, &ks2);
      DES_set_key_unchecked(&ke3, &ks3);

      const_DES_cblock inputText;
      DES_cblock outputText;

      for (i = 0; i < text_len / 8; i ++) {
        memcpy((void*)&inputText, cleartext + i * 8, 8);
        DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_ENCRYPT);
        memcpy(cipher + i * 8, (void*)&outputText, 8);
      }

      if (text_len % 8 != 0) {
        int tmp1 = text_len / 8 * 8;
        int tmp2 = text_len - tmp1;
        memset((void*)&inputText, 0, 8);
        memcpy((void*)&inputText, cleartext + tmp1, tmp2);

        DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_ENCRYPT);
        memcpy(cipher + tmp1, (void*)&outputText, 8);
      }

      return (char *)cipher;
    }
    break;
    case TRIPLE_CBC:
    {
      DES_cblock ke1, ke2, ke3, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8;       
      unsigned char *cipher = (unsigned char*)malloc(*out_len + 16);
      if (cipher == NULL) return NULL;
      memset(cipher, 0, *out_len);
      
      memset((void*)&ke1, 0, 8);
      memset((void*)&ke2, 0, 8);
      memset((void*)&ke2, 0, 8);

      if (key_len >= 24) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, 8);
        memcpy((void*)&ke3, key + 16, 8);
      } else if (key_len >= 16) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, 8);
        memcpy((void*)&ke3, key + 16, key_len - 16);
      } else if (key_len >= 8) {
        memcpy((void*)&ke1, key, 8);
        memcpy((void*)&ke2, key + 8, key_len - 8);
        memcpy((void*)&ke3, key, 8);
      } else {
        memcpy((void*)&ke1, key, key_len);
        memcpy((void*)&ke2, key, key_len);
        memcpy((void*)&ke3, key, key_len);
      }

      DES_key_schedule ks1, ks2, ks3;
      DES_set_key_unchecked(&ke1, &ks1);
      DES_set_key_unchecked(&ke2, &ks2);
      DES_set_key_unchecked(&ke3, &ks3);

      memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv));
      DES_ede3_cbc_encrypt((const unsigned char*)cleartext, cipher, text_len + 1, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);
      
      return (char *)cipher;
    }
    break;
    default:
    break;
	}
  
  return NULL;
}


char *decrypt_des(const char *ciphertext, size_t in_len, const char *key, int mode, size_t *out_len) 
{
	switch (mode) {
    case GENERAL:
    case ECB:
		{
      size_t i = 0;
			DES_cblock keyEncrypt;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8; 
      unsigned char *clear = (unsigned char *)malloc(*out_len); 
      if (clear == NULL) return NULL;
      memset(clear, 0, *out_len);
      
			memset((void*)&keyEncrypt, 0, 8);
			if (key_len <= 8) 
				memcpy((void*)&keyEncrypt, key, key_len);
			else 
				memcpy((void*)&keyEncrypt, key, 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			const_DES_cblock inputText;
			DES_cblock outputText;
			for (i = 0; i < text_len / 8; i ++) {
				memcpy((void*)&inputText, ciphertext + i * 8, 8);
				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
				memcpy(clear + i * 8, (void*)&outputText, 8);
			}

			if (text_len % 8 != 0) {
				int tmp1 = text_len / 8 * 8;
				int tmp2 = text_len - tmp1;
				memset((void*)&inputText, 0, 8);
				memcpy((void*)&inputText, ciphertext + tmp1, tmp2);

				DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
				memcpy(clear + tmp1, outputText, 8);
			}
      
      return (char *)clear;
		}
		break;
    case CBC:
		{
			DES_cblock keyEncrypt, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8; 
      unsigned char *clear = (unsigned char *)malloc(*out_len); 
      if (clear == NULL) return NULL;
      memset(clear, 0, *out_len);
      
			memset((void*)&keyEncrypt, 0, 8);
			if (key_len <= 8) 
				memcpy((void*)&keyEncrypt, key, key_len);
			else 
				memcpy((void*)&keyEncrypt, key, 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv));
			DES_ncbc_encrypt((const unsigned char*)ciphertext, clear, text_len, &keySchedule, &ivec, DES_DECRYPT);

			return (char *)clear;
		}
		break;
    case CFB:
		{
			DES_cblock keyEncrypt, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8; 
      unsigned char *clear = (unsigned char *)malloc(*out_len); 
      if (clear == NULL) return NULL;
      memset(clear, 0, *out_len);
      
			memset((void*)&keyEncrypt, 0, 8);
			if (key_len <= 8) 
				memcpy((void*)&keyEncrypt, key, key_len);
			else 
				memcpy((void*)&keyEncrypt, key, 8);

			DES_key_schedule keySchedule;
			DES_set_key_unchecked(&keyEncrypt, &keySchedule);	

			memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv));
			DES_cfb_encrypt((const unsigned char*)ciphertext, clear, 8, text_len, &keySchedule, &ivec, DES_DECRYPT);

			return (char *)clear;
		}
		break;
    case TRIPLE_ECB:
		{
      size_t i = 0;
			DES_cblock ke1, ke2, ke3;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8; 
      unsigned char *clear = (unsigned char *)malloc(*out_len); 
      if (clear == NULL) return NULL;
      memset(clear, 0, *out_len);
      
			memset((void*)&ke1, 0, 8);
			memset((void*)&ke2, 0, 8);
			memset((void*)&ke2, 0, 8);
			if (key_len >= 24) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, 8);
				memcpy((void*)&ke3, key + 16, 8);
			} else if (key_len >= 16) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, 8);
				memcpy((void*)&ke3, key + 16, key_len - 16);
			} else if (key_len >= 8) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, key_len - 8);
				memcpy((void*)&ke3, key, 8);
			} else {
				memcpy((void*)&ke1, key, key_len);
				memcpy((void*)&ke2, key, key_len);
				memcpy((void*)&ke3, key, key_len);
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			const_DES_cblock inputText;
			DES_cblock outputText;

			for (i = 0; i <  text_len / 8; i ++) {
				memcpy((void*)&inputText, ciphertext + i * 8, 8);
				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_DECRYPT);
				memcpy(clear + i * 8, (void*)&outputText, 8);
			}

			if (text_len % 8 != 0) {
				int tmp1 = text_len / 8 * 8;
				int tmp2 = text_len - tmp1;
				memset((void*)&inputText, 0, 8);
				memcpy((void*)&inputText, ciphertext + tmp1, tmp2);

				DES_ecb3_encrypt(&inputText, &outputText, &ks1, &ks2, &ks3, DES_DECRYPT);
				memcpy(clear + tmp1, (void*)&outputText, 8);
			}

			return (char *)clear;
		}
		break;
    case TRIPLE_CBC:
		{
			DES_cblock ke1, ke2, ke3, ivec;
      int key_len = strlen(key);
      size_t text_len = in_len; //strlen(cleartext);
      *out_len = ((text_len + 7) / 8 ) * 8; 
      unsigned char *clear = (unsigned char *)malloc(*out_len); 
      if (clear == NULL) return NULL;
      memset(clear, 0, *out_len);
      
			memset((void*)&ke1, 0, 8);
			memset((void*)&ke2, 0, 8);
			memset((void*)&ke2, 0, 8);
			if (key_len >= 24) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, 8);
				memcpy((void*)&ke3, key + 16, 8);
			} else if (key_len >= 16) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, 8);
				memcpy((void*)&ke3, key + 16, key_len - 16);
			} else if (key_len >= 8) {
				memcpy((void*)&ke1, key, 8);
				memcpy((void*)&ke2, key + 8, key_len - 8);
				memcpy((void*)&ke3, key, 8);
			} else {
				memcpy((void*)&ke1, key, key_len);
				memcpy((void*)&ke2, key, key_len);
				memcpy((void*)&ke3, key, key_len);
			}

			DES_key_schedule ks1, ks2, ks3;
			DES_set_key_unchecked(&ke1, &ks1);
			DES_set_key_unchecked(&ke2, &ks2);
			DES_set_key_unchecked(&ke3, &ks3);

			memcpy((void*)&ivec, (void*)&cbc_iv, sizeof(cbc_iv));

			DES_ede3_cbc_encrypt((const unsigned char*)ciphertext, clear, text_len, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

			return (char *)clear;
		}
		break;
    default:
    break;
	}

	return NULL;    
}