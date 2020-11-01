#ifndef FA_URL_H
#define FA_URL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct fa_url_s {
    char* schema;
    char* host;
    char* port;
    char* path;
    char* query;
    char* fragment;
    char* userinfo;
} fa_url_t;

fa_url_t *fa_parse_url (const char* buf, size_t buflen);

void fa_free_url (fa_url_t *url);

#ifdef __cplusplus
}
#endif
#endif