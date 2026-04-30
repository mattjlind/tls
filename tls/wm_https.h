#ifndef WM_HTTPS_H
#define WM_HTTPS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

/* HTTPS GET using a compiled-in BearSSL trust-anchor set.
 * Notes:
 *  - host may be a DNS hostname or a numeric IPv4 string
 *  - response is always NUL-terminated if response_size > 0
 *  - returns 1 on success, 0 on failure
 */
int wm_https_get(
    const char *host,
    unsigned short port,
    const char *path,
    char *response,
    int response_size,
    wm_https_result *result
);

int wm_https_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *response,
    int response_size,
    wm_https_result *result
);

/* Generic TLS text exchange for protocol scripting (IMAP/POP3/etc.).
 * request_text is sent once after handshake; response is collected until close.
 */
int wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
);

#ifdef __cplusplus
}
#endif

#endif
