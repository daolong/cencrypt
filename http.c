#include <curl/curl.h>
#include "common.h"
#include "http.h"


#define RESPONSE_SIZE_DEFAULT 1024 /*Response data default size*/
#define RESPONSE_SIZE_MAX  (10 * 1024 *1024) /* Max response data size*/

static size_t gResSize = 0;

static size_t curl_cb_write(void *ptr, size_t size, size_t nmemb,
			    void *userdata)  
{  
  char *response = userdata;
	char *n;
  size_t len = size * nmemb;
	n = DO_REALLOC(response, gResSize + len + 1);
	if (n == NULL)
		return 0;
  response = n;
	DO_MEMCPY(n + gResSize, ptr, len);
	n[gResSize + len] = '\0';
	gResSize += len;
  return len;  
}  

static int curl_cb_debug(CURL *curl, curl_infotype info, char *buf, size_t len,
			 void *userdata)
{
	switch (info) {
	case CURLINFO_TEXT:
		break;
	case CURLINFO_HEADER_IN:
		break;
	case CURLINFO_HEADER_OUT:
		break;
	case CURLINFO_DATA_IN:
		break;
	case CURLINFO_DATA_OUT:
		break;
	case CURLINFO_SSL_DATA_IN:
		break;
	case CURLINFO_SSL_DATA_OUT:
		break;
	case CURLINFO_END:
		break;
	}
	return 0;
}

char * http_post(const char *url, const char *data, const char *content_type, size_t *resp_len)
{
  struct curl_slist *curl_hdr = NULL;  
  CURL *curl = NULL;  
  CURLcode res;  
  char *ret = NULL;
  long http = 0;
  
  if (url == NULL)
    return NULL;
  
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();  
  if (NULL == curl) {  
    DERROR("%s : curl init failed\n", __func__);
    return NULL;  
  }  
  
  ret = DO_MALLOC(RESPONSE_SIZE_DEFAULT);
  if (ret == NULL) {
    DERROR("%s : alloc response data failed\n", __func__);
    return NULL;      
  }  
  gResSize = 0;  
  curl_easy_setopt(curl, CURLOPT_URL, url); //url��ַ  
  curl_easy_setopt(curl, CURLOPT_POST, 1L); //�����ʷ�0��ʾ���β���Ϊpost  
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); //post����  
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_cb_debug);
	curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb_write); //�Է��ص����ݽ��в����ĺ�����ַ  
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ret); //����curl_cb_write�ĵ��ĸ�����ֵ  
  
  curl_easy_setopt(curl, CURLOPT_VERBOSE,1); //��ӡ������Ϣ  
  curl_easy_setopt(curl, CURLOPT_HEADER, 1); //����Ӧͷ��Ϣ����Ӧ��һ�𴫸� curl_cb_write
  if (content_type) {
		char ct[200];
		snprintf(ct, sizeof(ct), "Content-Type: %s", content_type);
		curl_hdr = curl_slist_append(curl_hdr, ct);
	}
  
  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {  
    DERROR("%s : curl_easy_perform failed, error = %s", __func__, curl_easy_strerror(res));
    switch (res)  {  
    case CURLE_UNSUPPORTED_PROTOCOL:  
      fprintf(stderr, "��֧�ֵ�Э��,��URL��ͷ��ָ��\n");  
    case CURLE_COULDNT_CONNECT:  
      fprintf(stderr, "�������ӵ�remote�������ߴ���\n");  
    case CURLE_HTTP_RETURNED_ERROR:  
      fprintf(stderr, "http���ش���\n");  
    case CURLE_READ_ERROR:  
      fprintf(stderr, "�������ļ�����\n");  
    default:  
      fprintf(stderr, "����ֵ:%d\n",res);  
    }  
    goto __fail;
  }  

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
	DEBUG("%s: Server response code %ld\n", __func__, http);
	if (http != 200) {
		DERROR("%s : HTTP POST failed - code %ld\n", __func__, http);
    goto __fail;
	}

	if (ret == NULL) {
    goto __fail;
  }

  curl_easy_cleanup(curl);
  if (resp_len)
		*resp_len = gResSize;
  return ret;
  
__fail:  
  if (ret != NULL) free(ret);
  curl_easy_cleanup(curl);  
  return NULL;
}