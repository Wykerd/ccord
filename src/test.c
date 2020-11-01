#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int on_body_recv (llhttp_t* parser, const char *at, size_t length) {
    fwrite(at, length, sizeof(char), stdout);

    return 0;
}

const char* request = "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: bazcal/3.0\r\nConnection: close\r\n\r\n";

void write_cb (fa_http_client_t *client, fa_http_client_err_t *error) {
    free(client->data);
    puts("WROTE DATA");
}

void client_connect_cb (fa_http_client_t *client, fa_http_client_err_t *err) {
    if (err != NULL) printf("Status %d\n", err->code);
    else puts("Connected");

    uv_buf_t *resbuf = malloc(sizeof(uv_buf_t));
    
    resbuf->base = (char *)request;
    resbuf->len = strlen(request);

    client->data = resbuf;

    fa_http_client_write (client, resbuf, *write_cb);
}

void client_err_cb (fa_http_client_t *client, fa_http_client_err_t *err) {
    puts("An error occurred");
}

void client_close_cb (fa_http_client_t *client) {
    puts("Stream closed");
}

int main () {
    gnutls_global_init();

    const char* url_raw = "https://www.example.com";

    uv_loop_t *loop = uv_default_loop();

    fa_http_client_t client;

    fa_http_client_init(loop, &client);

    client.parser_settings.on_body = *on_body_recv;

    fa_http_client_connect (&client, url_raw, *client_connect_cb, *client_err_cb, *client_close_cb);

    uv_run(loop, UV_RUN_DEFAULT);
}