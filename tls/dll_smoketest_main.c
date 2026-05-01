#include <windows.h>
#include <stdio.h>

typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

typedef int (*wm_https_get_fn)(
    const char *host,
    unsigned short port,
    const char *path,
    char *response,
    int response_size,
    wm_https_result *result
);

typedef int (*wm_https_request_fn)(
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

typedef int (*wm_tls_exchange_fn)(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
);

static void show_ascii_message(const char *titleA, const char *textA)
{
    WCHAR wtitle[128];
    WCHAR wtext[4096];

    MultiByteToWideChar(CP_ACP, 0, titleA, -1, wtitle, 128);
    MultiByteToWideChar(CP_ACP, 0, textA, -1, wtext, 4096);
    MessageBox(NULL, wtext, wtitle, MB_OK);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    HMODULE h;
    wm_https_get_fn p_get;
    wm_https_request_fn p_req;
    wm_tls_exchange_fn p_tls;
    DWORD e_get;
    DWORD e_req;
    DWORD e_tls;
    WCHAR wpath[MAX_PATH];
    char apath[MAX_PATH];
    char msg[4096];

    (void)hInst;
    (void)hPrev;
    (void)lpCmd;
    (void)nShow;

    h = LoadLibrary(TEXT("wm_https.dll"));
    if (h == NULL) {
        _snprintf(msg, sizeof(msg), "LoadLibrary(wm_https.dll) failed. GetLastError=%lu", (unsigned long)GetLastError());
        msg[sizeof(msg) - 1] = '\0';
        show_ascii_message("DLL Smoke Test", msg);
        return 1;
    }

    p_get = (wm_https_get_fn)GetProcAddressA(h, "wm_https_get");
    e_get = GetLastError();
    p_req = (wm_https_request_fn)GetProcAddressA(h, "wm_https_request");
    e_req = GetLastError();
    p_tls = (wm_tls_exchange_fn)GetProcAddressA(h, "wm_tls_exchange");
    e_tls = GetLastError();

    if (GetModuleFileName(h, wpath, MAX_PATH) > 0) {
        WideCharToMultiByte(CP_ACP, 0, wpath, -1, apath, MAX_PATH, NULL, NULL);
    } else {
        strcpy(apath, "(unknown)");
    }

    if (p_get == NULL || p_req == NULL || p_tls == NULL) {
        if (p_get == NULL) {
            p_get = (wm_https_get_fn)GetProcAddress(h, (LPCSTR)1);
        }
        if (p_req == NULL) {
            p_req = (wm_https_request_fn)GetProcAddress(h, (LPCSTR)2);
        }
        if (p_tls == NULL) {
            p_tls = (wm_tls_exchange_fn)GetProcAddress(h, (LPCSTR)3);
        }

        if (p_get != NULL && p_req != NULL && p_tls != NULL) {
            _snprintf(msg, sizeof(msg),
                "Name lookup failed, ordinal fallback worked.\r\nDLL path: %s\r\n"
                "name errs: get=%lu req=%lu tls=%lu",
                apath, (unsigned long)e_get, (unsigned long)e_req, (unsigned long)e_tls);
            msg[sizeof(msg) - 1] = '\0';
            show_ascii_message("DLL Smoke Test", msg);
        } else {
        _snprintf(msg, sizeof(msg),
            "GetProcAddress failed.\r\nDLL path: %s\r\n"
            "wm_https_get=%p (err=%lu)\r\nwm_https_request=%p (err=%lu)\r\nwm_tls_exchange=%p (err=%lu)",
            apath,
            p_get, (unsigned long)e_get,
            p_req, (unsigned long)e_req,
            p_tls, (unsigned long)e_tls);
        msg[sizeof(msg) - 1] = '\0';
        show_ascii_message("DLL Smoke Test", msg);
        FreeLibrary(h);
        return 2;
        }
    }

    {
        char response[1024];
        wm_https_result res;
        int ok;

        response[0] = '\0';
        ok = p_get("www.wikipedia.org", 443, "/", response, sizeof(response), &res);
        if (ok) {
            _snprintf(msg, sizeof(msg), "Load/GetProc OK. HTTPS call succeeded, bytes=%d", res.http_bytes);
        } else {
            _snprintf(msg, sizeof(msg), "Load/GetProc OK. HTTPS call failed, tls=%d wsa=%d bytes=%d",
                res.tls_error, res.wsa_error, res.http_bytes);
        }
        msg[sizeof(msg) - 1] = '\0';
        show_ascii_message("DLL Smoke Test", msg);
    }

    FreeLibrary(h);
    return 0;
}
