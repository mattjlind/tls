#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include "bearssl.h"
#include "wm_https.h"
#include "wm_cert_store.h"

#pragma comment(lib, "ws2.lib")

#define WM_HTTPS_IOBUF_SIZE BR_SSL_BUFSIZE_BIDI
#define WM_HTTPS_RECV_CHUNK 1024
#define WM_HTTPS_TIMEOUT_MS 5000
#define WM_HTTPS_REQUEST_SIZE 4096

static br_ssl_client_context g_wm_ssl_client;
static br_x509_minimal_context g_wm_x509_minimal;
static unsigned char g_wm_iobuf[WM_HTTPS_IOBUF_SIZE];

static void
wm_https_zero_result(wm_https_result *result)
{
    if (result != 0) {
        result->ok = 0;
        result->tls_error = 0;
        result->wsa_error = 0;
        result->http_bytes = 0;
    }
}

static int
wm_https_connect_ipv4(const char *host, unsigned short port, SOCKET *out_sock, int *out_wsa_error)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    struct hostent *host_entry;
    int timeout_ms;
    unsigned long ip_addr;

    *out_sock = INVALID_SOCKET;
    if (out_wsa_error != 0) {
        *out_wsa_error = 0;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        return 0;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        WSACleanup();
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    ip_addr = inet_addr(host);
    if (ip_addr != INADDR_NONE) {
        addr.sin_addr.s_addr = ip_addr;
    } else {
        host_entry = gethostbyname(host);
        if (host_entry == 0 || host_entry->h_addr_list == 0 || host_entry->h_addr_list[0] == 0) {
            if (out_wsa_error != 0) {
                *out_wsa_error = WSAGetLastError();
                if (*out_wsa_error == 0) {
                    *out_wsa_error = WSAHOST_NOT_FOUND;
                }
            }
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        memcpy(&addr.sin_addr, host_entry->h_addr_list[0], sizeof(addr.sin_addr));
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    timeout_ms = WM_HTTPS_TIMEOUT_MS;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
        (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR)
    {
        /* WinCE stacks may reject SO_RCVTIMEO with WSAENOPROTOOPT.
         * This timeout is optional for the synchronous test client.
         */
        if (out_wsa_error != 0) {
            *out_wsa_error = 0;
        }
    }

    *out_sock = sock;
    return 1;
}

static void
wm_https_disconnect(SOCKET sock)
{
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    WSACleanup();
}

static void
wm_https_append_request_text(char *request, int request_size, size_t *used, const char *text)
{
    size_t chunk_len;
    size_t request_cap;

    if (request == 0 || request_size <= 0 || used == 0 || text == 0) {
        return;
    }

    request_cap = (size_t)request_size;
    if (*used >= request_cap - 1) {
        return;
    }

    chunk_len = strlen(text);
    if (chunk_len > request_cap - *used - 1) {
        chunk_len = request_cap - *used - 1;
    }
    memcpy(request + *used, text, chunk_len);
    *used += chunk_len;
    request[*used] = '\0';
}

static void
wm_https_append_request_data(char *request, int request_size, size_t *used, const char *data, size_t data_len)
{
    size_t request_cap;

    if (request == 0 || request_size <= 0 || used == 0 || data == 0) {
        return;
    }

    request_cap = (size_t)request_size;
    if (*used >= request_cap - 1) {
        return;
    }

    if (data_len > request_cap - *used - 1) {
        data_len = request_cap - *used - 1;
    }
    memcpy(request + *used, data, data_len);
    *used += data_len;
    request[*used] = '\0';
}

static void
wm_https_build_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *request,
    int request_size
)
{
    size_t used;
    size_t request_cap;
    size_t body_len;
    char port_text[16];
    int include_port;

    if (request_size <= 0) {
        return;
    }

    request[0] = '\0';
    request_cap = (size_t)request_size;
    used = 0;

    body_len = body != 0 ? strlen(body) : 0;
    include_port = !((port == 443) || (port == 80));

    wm_https_append_request_text(request, request_size, &used,
        (method != 0 && method[0] != '\0') ? method : "GET");
    wm_https_append_request_text(request, request_size, &used, " ");
    wm_https_append_request_text(request, request_size, &used,
        (path != 0 && path[0] != '\0') ? path : "/");
    wm_https_append_request_text(request, request_size, &used, " HTTP/1.1\r\nHost: ");
    wm_https_append_request_text(request, request_size, &used, host);
    if (include_port) {
        _snprintf(port_text, sizeof(port_text), ":%u", (unsigned)port);
        port_text[sizeof(port_text) - 1] = '\0';
        wm_https_append_request_text(request, request_size, &used, port_text);
    }
    wm_https_append_request_text(request, request_size, &used,
        "\r\nUser-Agent: Mozilla/5.0 (Windows CE; ARM; HP iPAQ 212)"
        "\r\nAccept: */*"
        "\r\nConnection: close");
    if (extra_headers != 0 && extra_headers[0] != '\0') {
        wm_https_append_request_text(request, request_size, &used, "\r\n");
        wm_https_append_request_text(request, request_size, &used, extra_headers);
    }
    if (body_len > 0) {
        char length_text[32];

        _snprintf(length_text, sizeof(length_text), "\r\nContent-Length: %u",
            (unsigned)body_len);
        length_text[sizeof(length_text) - 1] = '\0';
        wm_https_append_request_text(request, request_size, &used, length_text);
    }
    wm_https_append_request_text(request, request_size, &used, "\r\n\r\n");
    if (body_len > 0) {
        wm_https_append_request_data(request, request_size, &used, body, body_len);
    }
}

static int
wm_tls_exchange_internal(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    SOCKET sock;
    br_ssl_client_context *sc;
    br_x509_minimal_context *xc;
    unsigned state;
    int sent_request;
    int response_len;
    int ok;
    const br_x509_trust_anchor *trust_anchors;
    size_t trust_anchor_count;
    const char *sni_name;

    wm_https_zero_result(result);

    if (host == 0 || request_text == 0 || response == 0 || response_size <= 1) {
        return 0;
    }

    response[0] = '\0';
    sc = &g_wm_ssl_client;
    xc = &g_wm_x509_minimal;
    sni_name = (sni_host != 0 && sni_host[0] != '\0') ? sni_host : host;

    if (!wm_https_connect_ipv4(host, port, &sock, (result != 0) ? &result->wsa_error : 0)) {
        return 0;
    }

    memset(sc, 0, sizeof(*sc));
    memset(xc, 0, sizeof(*xc));
    memset(g_wm_iobuf, 0, sizeof(g_wm_iobuf));

    if (!wm_cert_store_init()) {
        wm_https_disconnect(sock);
        return 0;
    }

    trust_anchors = wm_cert_store_anchors();
    trust_anchor_count = wm_cert_store_anchor_count();

    br_ssl_client_init_full(sc, xc, trust_anchors, trust_anchor_count);
    br_ssl_engine_set_versions(&sc->eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_buffer(&sc->eng, g_wm_iobuf, sizeof(g_wm_iobuf), 1);

    if (!br_ssl_client_reset(sc, sni_name, 0)) {
        if (result != 0) {
            result->tls_error = br_ssl_engine_last_error(&sc->eng);
        }
        wm_https_disconnect(sock);
        return 0;
    }

    sent_request = 0;
    response_len = 0;
    ok = 0;

    while (1) {
        state = br_ssl_engine_current_state(&sc->eng);

        if (state & BR_SSL_CLOSED) {
            if (result != 0) {
                result->tls_error = br_ssl_engine_last_error(&sc->eng);
            }
            break;
        }

        if (state & BR_SSL_SENDREC) {
            unsigned char *buf;
            size_t len;

            buf = br_ssl_engine_sendrec_buf(&sc->eng, &len);
            while (len > 0) {
                int wr;

                wr = send(sock, (const char *)buf, (int)len, 0);
                if (wr <= 0) {
                    if (result != 0) {
                        result->wsa_error = WSAGetLastError();
                    }
                    wm_https_disconnect(sock);
                    return 0;
                }

                br_ssl_engine_sendrec_ack(&sc->eng, (size_t)wr);
                buf = br_ssl_engine_sendrec_buf(&sc->eng, &len);
            }
            continue;
        }

        if ((state & BR_SSL_SENDAPP) && !sent_request) {
            unsigned char *buf;
            size_t len;
            size_t qlen;

            buf = br_ssl_engine_sendapp_buf(&sc->eng, &len);
            qlen = strlen(request_text);

            if (len >= qlen) {
                memcpy(buf, request_text, qlen);
                br_ssl_engine_sendapp_ack(&sc->eng, qlen);
                br_ssl_engine_flush(&sc->eng, 0);
                sent_request = 1;
            }
            continue;
        }

        if (state & BR_SSL_RECVREC) {
            unsigned char *buf;
            size_t len;
            int rd;
            int want;

            buf = br_ssl_engine_recvrec_buf(&sc->eng, &len);
            if (len == 0) {
                break;
            }

            want = (len < WM_HTTPS_RECV_CHUNK) ? (int)len : WM_HTTPS_RECV_CHUNK;
            rd = recv(sock, (char *)buf, want, 0);
            if (rd == SOCKET_ERROR) {
                if (result != 0) {
                    result->wsa_error = WSAGetLastError();
                }
                wm_https_disconnect(sock);
                return 0;
            }
            if (rd == 0) {
                if (result != 0) {
                    result->tls_error = br_ssl_engine_last_error(&sc->eng);
                }
                break;
            }

            br_ssl_engine_recvrec_ack(&sc->eng, (size_t)rd);
            continue;
        }

        if (state & BR_SSL_RECVAPP) {
            unsigned char *buf;
            size_t len;
            int take;

            buf = br_ssl_engine_recvapp_buf(&sc->eng, &len);
            if (len > 0) {
                take = (int)len;
                if (response_len + take >= response_size) {
                    take = response_size - response_len - 1;
                }

                if (take > 0) {
                    memcpy(response + response_len, buf, take);
                    response_len += take;
                    response[response_len] = '\0';
                    ok = 1;
                }

                br_ssl_engine_recvapp_ack(&sc->eng, len);
                continue;
            }
        }
    }

    wm_https_disconnect(sock);

    if (result != 0) {
        result->ok = ok;
        result->http_bytes = response_len;
    }
    return ok;
}

int
wm_https_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    char request[WM_HTTPS_REQUEST_SIZE];

    if (host == 0 || path == 0 || response == 0 || response_size <= 1) {
        return 0;
    }

    wm_https_build_request(host, port, method, path, extra_headers, body,
        request, sizeof(request));
    return wm_tls_exchange_internal(host, port, host, request,
        response, response_size, result);
}

int
wm_https_get(
    const char *host,
    unsigned short port,
    const char *path,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    return wm_https_request(host, port, "GET", path, 0, 0,
        response, response_size, result);
}

int
wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    return wm_tls_exchange_internal(host, port, sni_host, request_text,
        response, response_size, result);
}
