#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int on_body_recv (llhttp_t* parser, const char *at, size_t length) {
    // fwrite(at, length, sizeof(char), stdout);

    return 0;
}

void on_header (fa_http_client_t *client, fa_http_header_t *header) {
    printf("HEADER\n%s: %s\n", header->field, header->value);
};

void write_cb (fa_http_client_t *client, fa_http_client_err_t *error) {
    fa_http_request_serialize_free(client->data);
    puts("WROTE DATA");
}

void client_connect_cb (fa_http_client_t *client, fa_http_client_err_t *err) {
    if (err != NULL) printf("Status %d\n", err->code);
    else puts("Connected");

    fa_http_request_t *req = fa_http_request_init(client, "GET");

    fa_http_headers_push(&req->headers, "Connection", "close");

    uv_buf_t *resbuf = fa_http_request_serialize(req, NULL);

    fwrite(resbuf->base, resbuf->len, sizeof(char), stdout);

    fa_http_request_free(req);

    client->data = resbuf;

    fa_http_client_write (client, resbuf, *write_cb);
}

void client_err_cb (fa_http_client_t *client, fa_http_client_err_t *err) {
    puts("An error occurred");
}

void client_close_cb (fa_http_client_t *client) {
    free(client);
    puts("Stream closed");
}

int on_message_complete (llhttp_t* parser) {
    puts("\n-- MESSAGE COMPLETE\n");

    // client_connect_cb(parser->data, NULL);

    return 0;
}

void create_client () {
    const char* url_raw = "https://www.example.com";

    uv_loop_t *loop = uv_default_loop();

    fa_http_client_t *client = malloc(sizeof(fa_http_client_t));

    fa_http_client_init(loop, client);

    client->parser_settings.on_body = *on_body_recv;
    client->parser_settings.on_message_complete = *on_message_complete;
    client->header_cb = *on_header;

    fa_http_client_set_url(client, url_raw);

    fa_http_client_connect (client, *client_connect_cb, *client_err_cb, *client_close_cb);
};

int main () {
    gnutls_global_init();

    uv_loop_t *loop = uv_default_loop();

    create_client();
    create_client();
    create_client();
    create_client();

    uv_run(loop, UV_RUN_DEFAULT);
}