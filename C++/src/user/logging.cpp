#include "logging.hpp"
#include "parser.hpp"
#include "payload.hpp"
#include <cstdio>
#include <curl/curl.h>
#define DEBUG_LOGGER

void Logger::init(void *parser) {

  Parser *p = (Parser *)parser;

  int size = p->api_header->size();
  url = *p->api_url;

  if (url.empty()) {
    fprintf(stderr, "Logger::init Api url is empty.Loggging is disabled. \n");
    return;
  }

  if (size == 0) {
    fprintf(stderr,
            "Logger::init Api headers are empty.Loggging is disabled. \n");
    return;
  }

  for (const auto &header : *p->api_header) {
    this->headers[header.first] = header.second;
  }

  for (auto &[key, val] : headers) {
    std::string h = key + ": " + val;
    header_list = curl_slist_append(header_list, h.c_str());
  }

  this->timeout_ms = 200;

#ifdef DEBUG_LOGGER
  printf("------DEBUGGING LOGGER------------\n");
  printf("Api url : %s\n", url.c_str());
  printf("API headers .................\n");

  for (auto &[key, val] : headers) {
    printf("{%s : %s}\n", key.c_str(), val.c_str());
  }

  printf("-------------------------------------\n");
#endif
}
void Logger::log(void *payload) {
  const Payload *p = (const Payload *)payload;
  std::string data = serializePayload(p);

  CURL *curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "Logger: curl_easy_init() failed\n");
    return;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data.size());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    fprintf(stderr, "Logger: curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  } else {

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code < 200 || http_code >= 300) {
      fprintf(stderr, "Logger: server rejected log, HTTP %ld\n", http_code);
    }
  }

  curl_easy_cleanup(curl);
}