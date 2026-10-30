/* src/httpnet.c without Goose (scripts/httpnet_check.py): connect, write, read, timeouts,
   errors, and the idle-closed test, against servers on 127.0.0.1.
   drive HTTP_PORT SILENT_PORT */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { const uint8_t *data; int64_t len; } httpnet_slice;
typedef struct { uint8_t *data; int64_t len; } httpnet_buf;
int64_t httpnet_connect(httpnet_slice host, int32_t port, int32_t timeout_ms);
int64_t httpnet_read(int64_t fd, httpnet_buf buf, int32_t timeout_ms);
int64_t httpnet_write(int64_t fd, httpnet_slice data, int32_t timeout_ms);
int32_t httpnet_readable(int64_t fd);
void httpnet_close(int64_t fd);
static httpnet_slice S(const char *s) { httpnet_slice x = { (const uint8_t *)s, (int64_t)strlen(s) }; return x; }
static int fails;
static void check(const char *name, int ok, long long v) { printf("%s %s (%lld)\n", ok ? "ok  " : "FAIL", name, v); if (!ok) fails++; }
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: drive HTTP_PORT SILENT_PORT\n"); return 2; }
    int http = atoi(argv[1]), silent = atoi(argv[2]);
    static uint8_t buf[1 << 16];
    httpnet_buf b = { buf, sizeof buf };
    int64_t fd = httpnet_connect(S("127.0.0.1"), http, 5000);
    check("connect", fd >= 0, fd);
    int64_t n = httpnet_write(fd, S("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 5000);
    check("write", n == 27, n);
    int64_t got = 0, r;
    while ((r = httpnet_read(fd, b, 5000)) > 0) got += r;
    check("read to the end", got > 0 && r == 0, got);
    httpnet_close(fd);
    fd = httpnet_connect(S("localhost"), http, 5000);
    check("connect by name", fd >= 0, fd);
    httpnet_write(fd, S("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 5000);
    r = httpnet_read(fd, b, 5000);
    check("read by name", r > 12 && memcmp(buf, "HTTP/1.", 7) == 0, r);
    httpnet_close(fd);
    fd = httpnet_connect(S("127.0.0.1"), silent, 5000);
    check("connect silent", fd >= 0, fd);
    check("idle and open: not readable", httpnet_readable(fd) == 0, 0);
    r = httpnet_read(fd, b, 300);
    check("read times out", r == -4, r);
    httpnet_close(fd);
    r = httpnet_connect(S("127.0.0.1"), 1, 3000);
    check("refused", r == -3, r);
    r = httpnet_connect(S("no-such-host.invalid"), 80, 3000);
    check("does not resolve", r == -2, r);
    r = httpnet_connect(S(""), 80, 1000);
    check("empty host", r == -1, r);
    fd = httpnet_connect(S("127.0.0.1"), http, 5000);
    httpnet_write(fd, S("GET / HTTP/1.0\r\n\r\n"), 5000);
    while ((r = httpnet_read(fd, b, 5000)) > 0) {}
    check("closed by the server: readable", httpnet_readable(fd) == 1, 0);
    httpnet_close(fd);
    printf("%d failed\n", fails);
    return fails != 0;
}
