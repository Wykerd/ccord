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

int fa_http_client_init (uv_loop_t *loop, fa_http_client_t *client) {
    client->loop = loop;
    client->https = NULL;
    client->url = NULL;
    llhttp_settings_init(&client->parser_settings);
    llhttp_init(&client->parser, HTTP_RESPONSE, &client->parser_settings);
    client->parser.data = client;
    client->settings.keep_alive = 0;
    client->settings.keep_alive_secs = 1;
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

    ssize_t parsed;

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

int fa_http_client_connect (fa_http_client_t *client, fa_http_client_connect_cb_t connect_cb, fa_http_client_err_cb_t err_cb, fa_http_client_close_cb_t close_cb) {
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
