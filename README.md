# tls

Windows Mobile / WinCE TLS helper DLL built on BearSSL.

This project builds `wm_https.dll`, which exposes a small C API for:
- HTTPS GET requests
- Generic HTTPS requests (custom method/headers/body)
- Raw TLS text exchange (for simple protocol scripting)

## Output

When built for `Windows Mobile 6 Professional SDK (ARMV4I)`, outputs are under:
- `tls\Windows Mobile 6 Professional SDK (ARMV4I)\Release\wm_https.dll`
- `tls\Windows Mobile 6 Professional SDK (ARMV4I)\Release\wm_https.lib`
- `tls\wm_https.h` (public header)

## Build

1. Open `tls.sln` in Visual Studio 2008.
2. Select configuration `Release` and platform `Windows Mobile 6 Professional SDK (ARMV4I)`.
3. Build the `tls` project.

## Public API

Declared in `tls\wm_https.h`:

```c
typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

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

int wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
);
```

## Linking in another project

1. Add `tls\wm_https.h` to your include path.
2. Link against `wm_https.lib`.
3. Deploy `wm_https.dll` with your executable on device/emulator.
4. Ensure `ws2.lib` is available in your build (the DLL itself already uses Winsock internally).

## Example: HTTPS GET

```c
#include <stdio.h>
#include "wm_https.h"

int main(void)
{
    char response[4096];
    wm_https_result res;

    if (wm_https_get("www.wikipedia.org", 443, "/", response, sizeof(response), &res)) {
        printf("Success, bytes=%d\n", res.http_bytes);
        printf("%s\n", response);
        return 0;
    }

    printf("FAIL tls=%d wsa=%d bytes=%d\n", res.tls_error, res.wsa_error, res.http_bytes);
    return 1;
}
```

## Certificate trust notes

The DLL uses a compiled-in trust-anchor set (`wm_cert_store.c`) and validates TLS chains against those anchors.

If a target server chain is not rooted in one of those anchors, the handshake fails (`tls_error` set in `wm_https_result`).

## Exported symbols

Defined in `tls\wm_https.def`:
- `wm_https_get`
- `wm_https_request`
- `wm_tls_exchange`

## Test app

`tls\main_example.c` contains a WinCE sample (`WinMain`) that calls `wm_https_get` against several hosts and shows results in a message box.
