#include "url_parser.h"
#include "url.h"
#include <string.h>
#include <stdlib.h>

#define URL_ASSIGN(ptr, f) ptr = malloc(sizeof(char) * (u.field_data[f].len + 1)); \
    memcpy(ptr, buf + u.field_data[f].off, u.field_data[f].len); \
    ptr[u.field_data[f].len] = 0

fa_url_t *fa_parse_url (const char* buf, size_t buflen) {
    struct http_parser_url u;
    http_parser_url_init(&u);
    if (http_parser_parse_url(buf, buflen, 0, &u)) {
        return NULL;
    };

    fa_url_t *url;
    url = malloc(sizeof(fa_url_t));
    
    URL_ASSIGN(url->schema, UF_SCHEMA);
    URL_ASSIGN(url->host, UF_HOST);
    URL_ASSIGN(url->query, UF_QUERY);
    URL_ASSIGN(url->userinfo, UF_USERINFO);
    URL_ASSIGN(url->fragment, UF_FRAGMENT);

    if (!u.field_data[UF_PORT].len) {
        url->port = calloc(sizeof(char), 6);

        if (!strcmp(url->schema, "http")) {
            strcpy(url->port, "80");
        } else if (!strcmp(url->schema, "https")) {
            strcpy(url->port, "443");
        } else {
            url->port[0] = '0';
        }
    } else {
        URL_ASSIGN(url->port, UF_PORT);
    }

    if (!u.field_data[UF_PATH].len) {
        url->path = calloc(sizeof(char), 2);
        url->path[0] = '/';
    } else {
        URL_ASSIGN(url->path, UF_PATH);
    }

    return url;
}

#undef URL_ASSIGN

void fa_free_url (fa_url_t *url) {
    free(url->schema);
    free(url->host);
    free(url->port);
    free(url->path);
    free(url->query);
    free(url->fragment);
    free(url->userinfo);
    free(url);
    url = NULL;
};
