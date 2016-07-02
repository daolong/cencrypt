#include <curl/curl.h>
#include "common.h"
#include "http.h"


#define RESPONSE_SIZE_DEFAULT 1024           /*Response data default size*/
#define RESPONSE_SIZE_MAX  (10 * 1024 *1024) /* Max response data size*/

#define CONNECT_TIMEOUT_DEFAULT 3L   /*3 seconds*/
#define TRANSFER_TIMEOUT_DEFAULT 3L  /*3 seconds*/

#define USER_AGENT_DEFAULT "Libcurl(7.49.0)-HttpClient/1.0"

static size_t gResSize = 0;
static long gConnectTimeOut = CONNECT_TIMEOUT_DEFAULT;
static long gTransferTimeout = TRANSFER_TIMEOUT_DEFAULT;

void http_global_init()
{
  curl_global_init(CURL_GLOBAL_ALL);
}

void http_global_release()
{
  curl_global_cleanup();
}

char *http_encode(const char *input, int length)
{
  CURL *curl = curl_easy_init();
  if (input == NULL) return NULL;
  if (curl != NULL) {
    char *output = curl_easy_escape(curl, input, length);
    curl_easy_cleanup(curl);
    return output;
  }  
  
  return NULL;
}

void http_free_encoded(const char *encoded) {
  if (encoded != NULL) {
    curl_free(encoded);
  }
}

void http_set_connect_timeout(long seconds)
{
  if (seconds <= 0) {
    gConnectTimeOut = CONNECT_TIMEOUT_DEFAULT;
    return;
  }
  
  gConnectTimeOut = seconds;
}

void http_set_transfer_timeout(long seconds)
{
  if (seconds <= 0) {
    gTransferTimeout = seconds;
    return;
  }
  
  gTransferTimeout = seconds;
}

static size_t curl_cb_write(void *ptr, size_t size, size_t nmemb,
			    void *userdata)  
{  
  char *response = userdata;
  char *n;
  size_t len = size * nmemb;
  //DEBUG("response ptr = %p, gResSize = %d, len = %d\n", response, gResSize, len);
  if ((gResSize + len) > RESPONSE_SIZE_DEFAULT) {
    n = DO_REALLOC(response, gResSize + len + 1);
    if (n == NULL)
    return 0;
    response = n;
    DO_MEMCPY(n + gResSize, ptr, len);
    n[gResSize + len] = '\0';
  } else {
    DO_MEMCPY(response + gResSize, ptr, len);
    response[gResSize + len] = '\0';
  }
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
  
  curl = curl_easy_init();  
  if (NULL == curl) {  
    DERROR("%s : curl init failed\n", __func__);
    return NULL;  
  }  
  
  ret = DO_MALLOC(RESPONSE_SIZE_DEFAULT);
  if (ret == NULL) {
    DERROR("%s : alloc response data failed\n", __func__);
    curl_easy_cleanup(curl);
    return NULL;      
  }  
  gResSize = 0;  
  
  curl_easy_setopt(curl, CURLOPT_URL, url); //url address
  curl_easy_setopt(curl, CURLOPT_POST, 1L); //set to 1 for post  
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); //post parameter 
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_cb_debug);
	curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb_write); //response operate callback function
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ret); //the fourth parameter of curl_cb_write 
  
  /* timeout for the connect phase */
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, gConnectTimeOut); 
  /* set maximum time the request is allowed to take */
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, gTransferTimeout);
  
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT_DEFAULT);
  
  curl_easy_setopt(curl, CURLOPT_VERBOSE,1); //print debug message
  curl_easy_setopt(curl, CURLOPT_HEADER, 0); //don't pass header to curl_cb_write
  if (content_type) {
		char ct[200];
		snprintf(ct, sizeof(ct), "Content-Type: %s", content_type);
		curl_hdr = curl_slist_append(curl_hdr, ct);
	}

	// start post
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		DERROR("%s : curl_easy_perform failed, error = %s", __func__,
				curl_easy_strerror(res));
		switch (res) {
		case CURLE_UNSUPPORTED_PROTOCOL:
			fprintf(stderr, "unsupported protocl\n");
		case CURLE_COULDNT_CONNECT:
			fprintf(stderr, "can not conntect to remote host or proxy\n");
		case CURLE_HTTP_RETURNED_ERROR:
			fprintf(stderr, "http return error\n");
		case CURLE_READ_ERROR:
			fprintf(stderr, "read local file fail\n");
		default:
			fprintf(stderr, "return :%d\n", res);
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
  if (ret != NULL)
    free(ret);
  curl_easy_cleanup(curl);
  return NULL;
}