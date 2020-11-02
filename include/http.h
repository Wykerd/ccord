#ifndef FA_HTTP_H
#define FA_HTTP_H
/* Parsers */
#include "url.h"
#include <llhttp.h>
/* Event loop */ 
#include <uv.h>
/* TLS */
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FA_HTTPS_BUF_LEN 1024

typedef struct fa_http_header_s {
    char* field;
    char* value;
} fa_http_header_t;

typedef struct fa_http_headers_s {
    fa_http_header_t **headers;
    size_t len;
} fa_http_headers_t;

typedef struct fa_https_client_s {
    gnutls_session_t session;
    gnutls_certificate_credentials_t xcred;
    char recv_buf[FA_HTTPS_BUF_LEN];
    /* Async recv https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
    uv_idle_t hhandshake;
    uv_idle_t hread;
    uv_prepare_t hwrite;
} fa_https_client_t;

typedef struct fa_http_client_settings_s {
    int keep_alive; // default is 0 (false)
    unsigned int keep_alive_secs; // default is 1 (second)
} fa_http_client_settings_t;

typedef struct fa_http_client_s {
    /* HTTP Parser */
    llhttp_t parser;
    llhttp_settings_t parser_settings;
    /* TLS Client */
    fa_https_client_t *https;
    /* Loop */
    uv_loop_t *loop;
    /* Handles */
    uv_getaddrinfo_t getaddrinfo_req;
    uv_tcp_t tcp;
    uv_connect_t connect_req;
    /* Callbacks */
    void* connect_cb;
    void* err_cb;
    void* close_cb;
    void* upgrade_cb;
    void* header_cb; // called when a new header is parsed
    fa_http_header_t current_header; // the current header being parsed.
    /* URL */
    fa_url_t *url;
    /* Data */
    void *data;
    /* Settings */
    fa_http_client_settings_t settings;
} fa_http_client_t;

enum fa_http_client_error_type {
    FA_HC_E_GNUTLS,
    FA_HC_E_UVREADSTART,
    FA_HC_E_UVREAD,
    FA_HC_E_GETADDRINFO, // Error code: See UV_EIA_*
    FA_HC_E_UVTCPINIT,
    FA_HC_E_UVCONNECTREQ, // could not queue connect with uv_tcp_connect
    FA_HC_E_UVCONNECT, // thrown by uv_connect_cb
    FA_HC_E_UVWRITEREQ,
    FA_HC_E_UVWRITE,
    FA_HC_E_PARSE, // llhttp parse error
    FA_HC_E_INVALIDURL,
    FA_HC_E_UPGRADE, // A protovol upgrade was made but no upgrade_cb was set
    FA_HC_E_UNSUPPORTEDSCHEMA // the http client only supports http and https schemas!
};

typedef struct fa_http_client_err_s {
    enum fa_http_client_error_type type;
    ssize_t code;
} fa_http_client_err_t;

typedef void (*fa_http_client_connect_cb_t)(fa_http_client_t *client, fa_http_client_err_t *error);

typedef void (*fa_http_client_write_cb_t)(fa_http_client_t *client, fa_http_client_err_t *error);

typedef void (*fa_http_client_err_cb_t)(fa_http_client_t *client, fa_http_client_err_t *error);

typedef void (*fa_http_client_close_cb_t)(fa_http_client_t *client);

typedef void (*fa_http_client_upgrade_cb_t)(fa_http_client_t *client);

typedef void (*fa_http_client_header_cb_t)(fa_http_client_t *client, fa_http_header_t *header);

int fa_http_client_init (uv_loop_t *loop, fa_http_client_t *client);
void fa_http_client_shutdown (uv_shutdown_t *shutdown, fa_http_client_t *client, uv_shutdown_cb cb);
void fa_http_client_connect (fa_http_client_t *client, fa_http_client_connect_cb_t connect_cb, fa_http_client_err_cb_t err_cb, fa_http_client_close_cb_t close_cb);
int fa_http_client_write (fa_http_client_t *client, uv_buf_t *buf, fa_http_client_write_cb_t write_cb);
void fa_http_client_set_url (fa_http_client_t *client, const char* url);


#ifdef __cplusplus
}
#endif
#endif