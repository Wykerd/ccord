#ifndef FA_URL_H
#define FA_URL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define FA_PATH_FIELDS \
    char* path; \
    char* query; \
    char* fragment; \
    char* userinfo; \

typedef struct fa_url_path_s {
    FA_PATH_FIELDS
} fa_url_path_t;

typedef struct fa_url_s {
    FA_PATH_FIELDS
    char* schema;
    char* host;
    char* port;
} fa_url_t;

fa_url_t *fa_parse_url (const char* buf, size_t buflen);

void fa_free_url (fa_url_t *url);

#ifdef __cplusplus
}
#endif
#endif