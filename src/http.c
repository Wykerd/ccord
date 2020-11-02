#include "http.h"
/* Standard Library */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Networking */
#include <netdb.h>

typedef struct fa__http_client_write_data_s {
    fa_http_client_t *client;
    fa_http_client_write_cb_t cb;
} fa__http_client_write_data_t;

typedef struct fa__http_client_tls_write_data_s {
    fa_http_client_t *client;
    fa_http_client_write_cb_t cb;
    uv_buf_t *buf;
} fa__http_client_tls_write_data_t;

static int fa__http_header_field_cb (llhttp_t *parser, const char *at, size_t length) {
    fa_http_client_t *client = parser->data;

    free(client->current_header.field);
    client->current_header.field = malloc(length + sizeof(char));
    memcpy(client->current_header.field, at, length);
    client->current_header.field[length] = 0;
    client->current_header.field_len = length;
    return 0;
}

static int fa__http_header_value_cb (llhttp_t *parser, const char *at, size_t length) {
    fa_http_client_t *client = parser->data;

    free(client->current_header.value);
    client->current_header.value = malloc(length + sizeof(char));
    memcpy(client->current_header.value, at, length);
    client->current_header.value[length] = 0;
    client->current_header.value_len = length;

    (*(fa_http_client_header_cb_t)client->header_cb)(client, &client->current_header);

    return 0;
}

int fa_http_client_init (uv_loop_t *loop, fa_http_client_t *client) {
    client->loop = loop;
    client->https = NULL;
    client->url = NULL;
    llhttp_settings_init(&client->parser_settings);
    llhttp_init(&client->parser, HTTP_RESPONSE, &client->parser_settings);
    client->parser.data = client;
    client->settings.keep_alive = 0;
    client->settings.keep_alive_secs = 1;
    // Clear the callbacks
    client->connect_cb = NULL;
    client->err_cb = NULL;
    client->close_cb = NULL;
    client->upgrade_cb = NULL;
    client->header_cb = NULL;
    // Initialize the current_header
    client->current_header.field = calloc(sizeof(char), 1);
    client->current_header.value = calloc(sizeof(char), 1);
    client->current_header.field_len = 0;
    client->current_header.value_len = 0;
    // Header parsing
    client->parser_settings.on_header_field = *fa__http_header_field_cb;
    client->parser_settings.on_header_value = *fa__http_header_value_cb;
    return 0;
};

void fa_http_client_shutdown (uv_shutdown_t *shutdown, fa_http_client_t *client, uv_shutdown_cb cb) {
    if (client->https != NULL) {
        // TODO ERROR CHECK
        gnutls_bye(client->https->session, GNUTLS_SHUT_RDWR);
        
        gnutls_deinit(client->https->session);
        gnutls_certificate_free_credentials(client->https->xcred);

        free(client->https);
        client->https = NULL;
    }
    
    if (client->url != NULL) {
        fa_free_url(client->url);
        client->url = NULL;
    }

    free(client->current_header.field);
    free(client->current_header.value);

    uv_shutdown(shutdown, (uv_stream_t *)&client->tcp, cb);
};

static void fa__http_client_alloc_cb (
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf
) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

static void fa__http_client_read_cb (uv_stream_t *tcp, ssize_t nread, const uv_buf_t * buf) {
    fa_http_client_t *client = tcp->data;

    if (nread > 0) {
        llhttp_errno_t err = llhttp_execute(&client->parser, buf->base, nread);
        if (err != HPE_OK) {
            fa_http_client_err_t error = {
                .type = FA_HC_E_PARSE,
                .code = err
            };

            // kill reading
            uv_read_stop(tcp);

            (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
        }

        if (client->parser.upgrade == 1) {
            // A protocol upgrade has occurred! Lets notify and switch if possible
            if (client->upgrade_cb != NULL) {
                // kill the reading - this must be resumed in the callback
                uv_read_stop(tcp);
                
                (*(fa_http_client_upgrade_cb_t)client->upgrade_cb)(client);
            } else {
                fa_http_client_err_t error = {
                    .type = FA_HC_E_UPGRADE,
                    .code = 0
                };

                // kill reading
                uv_read_stop(tcp);

                (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
            }
        }
    } else {
        if (nread != UV_EOF) {
            fa_http_client_err_t error = {
                .type = FA_HC_E_UVREAD,
                .code = nread
            };

            // kill reading
            uv_read_stop(tcp);

            (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
        } else {
            // kill reading
            uv_read_stop(tcp);
            (*(fa_http_client_close_cb_t)client->close_cb)(client);
        }
    }

    free(buf->base);
}

static void fa__http_client_tls_read_cb (uv_idle_t* handle) {
    fa_http_client_t *client = handle->data;

    // check whether there is data to read
    ssize_t rval;
    // (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
    rval = gnutls_record_recv(client->https->session, client->https->recv_buf, FA_HTTPS_BUF_LEN);

    // nothing to read yet 
    if (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED) return;

    if (rval > 0) {
        llhttp_errno_t err = llhttp_execute(&client->parser, client->https->recv_buf, rval);
        if (err != HPE_OK) {
            fa_http_client_err_t error = {
                .type = FA_HC_E_PARSE,
                .code = err
            };

            // kill reading
            uv_idle_stop(handle);

            (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
        }

        if (client->parser.upgrade == 1) {
            // A protocol upgrade has occurred! Lets notify and switch if possible
            if (client->upgrade_cb != NULL) {
                // kill the reading - this must be resumed in the callback
                uv_idle_stop(handle);
                
                (*(fa_http_client_upgrade_cb_t)client->upgrade_cb)(client);
            } else {
                fa_http_client_err_t error = {
                    .type = FA_HC_E_UPGRADE,
                    .code = 0
                };

                // kill reading
                uv_idle_stop(handle);

                (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
            }
        }
    } else if (rval < 0 && gnutls_error_is_fatal(rval) == 0) {
        fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(rval));
        goto clean_close;
    } else if (rval < 0) {
        fprintf(stderr, "*** Error: %s\n", gnutls_strerror(rval));
            
        fa_http_client_err_t error = {
            .type = FA_HC_E_GNUTLS,
            .code = rval
        };

        // kill reading
        uv_idle_stop(handle);

        (*(fa_http_client_err_cb_t)client->err_cb)(client, &error);
    } else if (rval == 0) {
        fprintf(stderr, "- Peer has closed the TLS connection\n");

clean_close: 
        // kill reading
        uv_idle_stop(handle);

        (*(fa_http_client_close_cb_t)client->close_cb)(client);
    };
}

static void fa__http_client_tls_handshake_cb (uv_idle_t* handle) {
    fa_http_client_t *client = handle->data;

    int ret;

    ret = gnutls_handshake(client->https->session);

    if (ret < 0 && gnutls_error_is_fatal(ret) == 0) return;

    if (ret < 0) {
        fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));

        fa_http_client_err_t error = {
            .type = FA_HC_E_GNUTLS,
            .code = ret
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        uv_idle_stop(handle);

        return;
    } else {
        uv_idle_stop(handle);
        // now we are connected and ready to receive data
        uv_idle_init(client->loop, &client->https->hread);
        client->https->hread.data = client;

        uv_idle_start(&client->https->hread, fa__http_client_tls_read_cb);

        // Connected and ready for write
        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, NULL);
    }
};

static void fa__http_client_tcp_connect_cb (
    uv_connect_t* req, 
    int status
) {
    fa_http_client_t *client = req->data;

    if (status != 0) {
        fa_http_client_err_t error = {
            .type = FA_HC_E_UVCONNECT,
            .code = status
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    };

    // Keep alive
    if (client->settings.keep_alive) {
        uv_tcp_keepalive(&client->tcp, 1, client->settings.keep_alive_secs);
    }

    int r;

    if (!strcmp(client->url->schema, "https")) {
        client->https = malloc(sizeof(fa_https_client_t));
        memset(client->https, 0, sizeof(fa_https_client_t));

        int ret;

        /* X509 stuff */
        ret = gnutls_certificate_allocate_credentials(&client->https->xcred);
        if (ret < 0) goto cleanup;

        /* sets the system trusted CAs for Internet PKI */
        ret = gnutls_certificate_set_x509_system_trust(client->https->xcred);
        if (ret < 0) goto cleanup;

        /* Initialize TLS session */
        ret = gnutls_init(&client->https->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
        if (ret < 0) goto cleanup;

        ret = gnutls_server_name_set(client->https->session, GNUTLS_NAME_DNS, client->url->host, strlen(client->url->host));
        if (ret < 0) goto cleanup;

        /* It is recommended to use the default priorities */
        ret = gnutls_set_default_priority(client->https->session);
        if (ret < 0) goto cleanup;

        /* put the x509 credentials to the current session */
        ret = gnutls_credentials_set(client->https->session, GNUTLS_CRD_CERTIFICATE, client->https->xcred);
        if (ret < 0) goto cleanup;

        gnutls_session_set_verify_cert(client->https->session, client->url->host, 0);

        uv_os_fd_t sock_fd; 
        uv_fileno((uv_handle_t *)&client->tcp, &sock_fd);

        gnutls_transport_set_int(client->https->session, sock_fd);
        gnutls_handshake_set_timeout(client->https->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        uv_idle_init(client->loop, &client->https->hhandshake);
        client->https->hhandshake.data = client;

        uv_idle_start(&client->https->hhandshake, fa__http_client_tls_handshake_cb);

        return;
cleanup:
        uv_read_stop(req->handle);
        
        fa_http_client_err_t error = {
            .type = FA_HC_E_GNUTLS,
            .code = ret
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    } else if (!strcmp(client->url->schema, "http")) {
        // Start monitoring for responses
        r = uv_read_start(req->handle, *fa__http_client_alloc_cb, *fa__http_client_read_cb);

        if (r != 0) {
            uv_read_stop(req->handle);

            fa_http_client_err_t error = {
                .type = FA_HC_E_UVREADSTART,
                .code = r
            };

            (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

            return;
        }

        // Connected and ready for write
        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, NULL);
    } else {
        fa_http_client_err_t error = {
            .type = FA_HC_E_UNSUPPORTEDSCHEMA,
            .code = 0
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);
    }
}

static void fa__http_client_tcp_connect (
    fa_http_client_t *client,
    struct sockaddr *addr
) {
    int r;

    r = uv_tcp_init(client->loop, &client->tcp);
    if (r != 0) {
        fa_http_client_err_t error = {
            .type = FA_HC_E_UVTCPINIT,
            .code = r
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    };

    client->tcp.data = client;
    client->connect_req.data = client;

    r = uv_tcp_connect(&client->connect_req, &client->tcp, addr, *fa__http_client_tcp_connect_cb);

    if (r != 0) {
        fa_http_client_err_t error = {
            .type = FA_HC_E_UVCONNECTREQ,
            .code = r
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    };
}

static void fa__http_client_getaddrinfo_cb (
    uv_getaddrinfo_t* req,
    int status,
    struct addrinfo* res
) {
    if (status < 0) {
        fa_http_client_t *client = req->data;

        fa_http_client_err_t error = {
            .type = FA_HC_E_GETADDRINFO,
            .code = status
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    };

    fa__http_client_tcp_connect(req->data, res->ai_addr);

    uv_freeaddrinfo(res);
}

void fa_http_client_connect (fa_http_client_t *client, fa_http_client_connect_cb_t connect_cb, fa_http_client_err_cb_t err_cb, fa_http_client_close_cb_t close_cb) {
    client->connect_cb = connect_cb;
    client->err_cb = err_cb;
    client->close_cb = close_cb;

    if (client->url == NULL) {
        fa_http_client_err_t error = {
            .type = FA_HC_E_INVALIDURL,
            .code = 0
        };

        (*(fa_http_client_connect_cb_t)client->connect_cb)(client, &error);

        return;
    }

    struct sockaddr_in dest;

    int r = uv_ip4_addr(client->url->host, atoi(client->url->port), &dest);

    if (r != 0) {
        client->getaddrinfo_req.data = client;

        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        uv_getaddrinfo(
            client->loop,
            &client->getaddrinfo_req,
            *fa__http_client_getaddrinfo_cb,
            client->url->host,
            client->url->port,
            &hints
        );
    } else {
        fa__http_client_tcp_connect(client, (struct sockaddr *)&dest);
    }
}

void fa_http_client_set_url (fa_http_client_t *client, const char* url) {
    client->url = fa_parse_url(url, strlen(url));
}

static void fa__http_client_write_cb (uv_write_t* req, int status) {
    fa__http_client_write_data_t *write_data = req->data;

    if (status != 0) {
        fa_http_client_err_t error = {
            .type = FA_HC_E_UVWRITE,
            .code = status
        };

        (*(fa_http_client_write_cb_t)write_data->cb)(write_data->client, &error);

        free(req->data);

        return;
    }

    (*(fa_http_client_write_cb_t)write_data->cb)(write_data->client, NULL);

    free(req->data);
};

static void fa__http_client_tls_write_cb (uv_idle_t* handle) {
    fa__http_client_tls_write_data_t *write_data = handle->data;
    ssize_t rval;

    rval = gnutls_record_send(write_data->client->https->session, write_data->buf->base, write_data->buf->len);

    if (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED) return;

    if (rval < 0) {
         fa_http_client_err_t error = {
            .type = FA_HC_E_GNUTLS,
            .code = rval
        };

        (*(fa_http_client_write_cb_t)write_data->cb)(write_data->client, &error);
    } else {
        (*(fa_http_client_write_cb_t)write_data->cb)(write_data->client, NULL);
    }

    uv_idle_stop(handle);

    free(handle->data);
    free(handle);
}

int fa_http_client_write (fa_http_client_t *client, uv_buf_t *buf, fa_http_client_write_cb_t write_cb) {
    if (client->https != NULL) {
        uv_idle_t *writer = malloc(sizeof(uv_idle_t));

        fa__http_client_tls_write_data_t *write_data = malloc(sizeof(fa__http_client_tls_write_data_t));

        write_data->cb = write_cb;
        write_data->client = client;
        write_data->buf = buf;

        writer->data = write_data;

        uv_idle_init(client->loop, writer);
        uv_idle_start(writer, *fa__http_client_tls_write_cb);

    } else {
        int r;
        uv_write_t write_req;

        fa__http_client_write_data_t *write_data = malloc(sizeof(fa__http_client_write_data_t));

        write_data->cb = write_cb;
        write_data->client = client;

        write_req.data = write_data;

        r = uv_write(&write_req, client->connect_req.handle, buf, 1, *fa__http_client_write_cb);

        if (r != 0) {
            printf("Error: uv_write\n");

            fa_http_client_err_t error = {
                .type = FA_HC_E_UVWRITEREQ,
                .code = r
            };

            (*(fa_http_client_write_cb_t)client->connect_cb)(client, &error);

            return 1;
        }
    }

    return 0;
}

/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */
static const char tokens[256] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
       ' ',     '!',      0,      '#',     '$',     '%',     '&',    '\'',
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        0,       0,      '*',     '+',      0,      '-',     '.',      0,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
       '0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
       '8',     '9',      0,       0,       0,       0,       0,       0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
       'x',     'y',     'z',      0,       0,       0,      '^',     '_',
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
       '`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
       'x',     'y',     'z',      0,      '|',      0,      '~',       0 };

#define TOKEN(c) ((c == ' ') ? 0 : tokens[(unsigned char)c])

static const char auth[] = "authorization";
static const char host[] = "host";
static const char content_type[] = "content-type";
static const char http_version[] = "HTTP/1.1";

static const uv_buf_t content_type_header[2] = {
    {
        .base = "Content-Type",
        .len = 12
    },
    {
        .base = "application/octet-stream",
        .len = 24
    }
};

static const uv_buf_t content_length_header = {
    .base = "Content-Length",
    .len = 14
};

void fa_http_headers_init (fa_http_headers_t *headers) {
    headers->base = malloc(sizeof(fa_http_header_t *));
    headers->len = 0;
};

fa_http_request_err_t fa_http_headers_push_buf (fa_http_headers_t *headers, uv_buf_t *field, uv_buf_t *value) {
    headers->base = realloc(headers->base, sizeof(fa_http_header_t *) * ++headers->len);
    
    headers->base[headers->len - 1] = malloc(sizeof(fa_http_header_t));

    headers->base[headers->len - 1]->field = malloc(sizeof(char) * (field->len + 1));
    headers->base[headers->len - 1]->value = malloc(sizeof(char) * (value->len + 1));
    headers->base[headers->len - 1]->field_len = field->len;
    headers->base[headers->len - 1]->value_len = value->len;

    for (size_t i = 0; i < field->len; i++) {
        char tok = TOKEN(field->base[i]);
        if (!tok) return FA_HR_E_FIELD_NAME;
        headers->base[headers->len - 1]->field[i] = field->base[i];
    };

    headers->base[headers->len - 1]->field[field->len] = 0;

    // TODO: Field Value validation
    memcpy(headers->base[headers->len - 1]->value, value->base, value->len);
    headers->base[headers->len - 1]->value[value->len] = 0;

    return FA_HR_E_OK;
};

fa_http_request_err_t fa_http_headers_push (fa_http_headers_t *headers, char* field, char* value) {
    uv_buf_t field_buf = {
        .base = field,
        .len = strlen(field)
    };

    uv_buf_t value_buf = {
        .base = value,
        .len = strlen(value)
    };
    
    return fa_http_headers_push_buf(headers, &field_buf, &value_buf);
}

void fa_http_headers_free (fa_http_headers_t *headers) {
    for (size_t i = 0; i < headers->len; i++) {
        free(headers->base[i]->field);
        free(headers->base[i]->value);
        free(headers->base[i]);
    }
    free(headers->base);
}

fa_http_request_t *fa_http_request_init (fa_http_client_t *client, const char* method) {
    fa_http_request_t *req = malloc(sizeof(fa_http_request_t));

    fa_http_headers_init(&req->headers);

    size_t method_len = strlen(method);
    req->method = malloc(sizeof(char) * (method_len + 1));
    memcpy(req->method, method, method_len);
    req->method[method_len] = 0;

    req->client = client;

    return req;
};

uv_buf_t *fa_http_request_header_with_path (fa_http_request_t *req, fa_url_path_t *path, int include_content_type) {
    int has_host = 0, has_auth = 0, has_content_type = !include_content_type;

    uv_buf_t *header = malloc(sizeof(uv_buf_t));

    // Request line
    size_t method_len = strlen(req->method);
    size_t path_len = strlen(path->path);
    size_t query_len = strlen(path->query);

    // Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    size_t request_line_len = method_len + 1 + (path_len ? path_len : 1) + (query_len ? query_len + 1 : 0) + 1 + 8 + 2;

    size_t header_len = request_line_len;

    // First pass calculate size + has host etc
    for (size_t i = 0; i < req->headers.len; i++) {
        header_len += req->headers.base[i]->field_len + 2 + req->headers.base[i]->value_len + 2;
    };

    // the header terminator CRLF
    header_len += 2;

    // allocate the memory
    header->len = header_len;
    header->base = malloc(header->len);

    size_t cursor = 0;

    // Add the request line
    memcpy(header->base, req->method, method_len);
    cursor += method_len;
    header->base[cursor++] = ' ';
    memcpy(header->base + cursor, path_len ? path->path : "/", (path_len ? path_len : 1));
    cursor += path_len ? path_len : 1;
    if (query_len) {
        header->base[cursor++] = '?';
        memcpy(header->base + cursor, path->query, query_len);
    };
    header->base[cursor++] = ' ';
    memcpy(header->base + cursor, http_version, 8);
    cursor += 8;
    header->base[cursor++] = '\r';
    header->base[cursor++] = '\n';

    // Add the headers
    for (size_t i = 0; i < req->headers.len; i++) {
        int is_auth = (req->headers.base[i]->field_len == 13) && (!has_auth), 
            is_host = (req->headers.base[i]->field_len == 4) && (!has_host),
            is_content_length = (req->headers.base[i]->field_len == 12) && (!has_content_type);
        
        for (size_t x = 0; x < req->headers.base[i]->field_len; x++) {
            if (is_auth) is_auth = TOKEN(req->headers.base[i]->field[x]) == auth[x]; 
            if (is_host) is_host = TOKEN(req->headers.base[i]->field[x]) == host[x];
            if (is_content_length) is_content_length = TOKEN(req->headers.base[i]->field[x]) == content_type[x];
            header->base[cursor++] = req->headers.base[i]->field[x];
        };

        has_host = has_host || is_host;
        has_auth = has_auth || is_auth;
        has_content_type = has_content_type || is_content_length;

        header->base[cursor++] = ':';
        header->base[cursor++] = ' ';
        memcpy(header->base + cursor, req->headers.base[i]->value, req->headers.base[i]->value_len);
        cursor += req->headers.base[i]->value_len;
        header->base[cursor++] = '\r';
        header->base[cursor++] = '\n';
    };

    size_t orig_header_len = req->headers.len;

    if (!has_host) {
        uv_buf_t field = {
            .base = "Host",
            .len = 4
        };

        uv_buf_t value = {
            .base = req->client->url->host,
            .len = strlen(req->client->url->host)
        };

        fa_http_headers_push_buf(&req->headers, &field, &value);

        header_len += field.len + 2 + value.len + 2;
    };

    if (!has_auth) {
        size_t userinfo_len = strlen(path->userinfo);
        if (userinfo_len > 0) {
            // add basic auth
            gnutls_datum_t data, result;
            data.data = (unsigned char*)path->userinfo;
            data.size = userinfo_len;
            if (gnutls_base64_encode2(&data, &result) != GNUTLS_E_SUCCESS) goto skip_auth;
            
            uv_buf_t field = {
                .base = "Authorization",
                .len = 13
            };

            uv_buf_t value;

            value.len = (sizeof(char) * 6) + result.size;
            value.base = malloc(value.len);
            memcpy(value.base, "Basic ", sizeof(char) * 6);
            memcpy(value.base + (sizeof(char) * 6), result.data, result.size);

            fa_http_headers_push_buf(&req->headers, &field, &value);

            gnutls_free(&result);
            free(value.base);

            header_len += field.len + 2 + value.len + 2;
        };
    };

skip_auth:

    // If BODY != NULL this field will be set application/octet-stream as to rfc2616 spec
    if (!has_content_type) {
        fa_http_headers_push_buf(&req->headers, (uv_buf_t *)&content_type_header[0], (uv_buf_t *)&content_type_header[1]);
        header_len += content_type_header[0].len + 2 + content_type_header[1].len + 2;
    };

    size_t additional_len = header_len - header->len;

    if (additional_len) {
        header->len = header_len;
        header->base = realloc(header->base, header->len);

        for (size_t i = orig_header_len; i < req->headers.len; i++) {
            memcpy(header->base + cursor, req->headers.base[i]->field, req->headers.base[i]->field_len);
            cursor += req->headers.base[i]->field_len;
            header->base[cursor++] = ':';
            header->base[cursor++] = ' ';
            memcpy(header->base + cursor, req->headers.base[i]->value, req->headers.base[i]->value_len);
            cursor += req->headers.base[i]->value_len;
            header->base[cursor++] = '\r';
            header->base[cursor++] = '\n';
        }
    };

    header->base[cursor++] = '\r';
    header->base[cursor++] = '\n';

    return header;
};

uv_buf_t *fa_http_request_header (fa_http_request_t *req, int include_content_type) {
    return fa_http_request_header_with_path(req, (fa_url_path_t *)req->client->url, include_content_type);
};

uv_buf_t *fa_http_request_serialize_with_path (fa_http_request_t *req, uv_buf_t *body, fa_url_path_t *path) {
    if ((body != NULL) && body->len) {
        uv_buf_t value;
        value.len = snprintf(NULL, 0, "%zu", body->len);
        value.base = malloc(value.len);
        snprintf(value.base, value.len, "%zu", body->len);

        fa_http_headers_push_buf(&req->headers, (uv_buf_t *)&content_length_header, &value);

        free(value.base);
    }

    uv_buf_t *serial = fa_http_request_header_with_path(req, (fa_url_path_t *)req->client->url, body != NULL);

    if ((body != NULL) && body->len) {
        size_t cursor = serial->len;
        serial->len += body->len;
        serial->base = realloc(serial->base, serial->len);
        memcpy(serial->base + cursor, body->base, body->len);
    };

    return serial;
};

uv_buf_t *fa_http_request_serialize (fa_http_request_t *req, uv_buf_t *body) {
    return fa_http_request_serialize_with_path(req, body, (fa_url_path_t *)req->client->url);
};

void fa_http_request_serialize_free (uv_buf_t *buf) {
    free(buf->base);
    free(buf);
    buf = NULL;
};

void fa_http_request_free (fa_http_request_t *req) {
    fa_http_headers_free(&req->headers);
    free(req->method);
    free(req);
    req = NULL;
};
