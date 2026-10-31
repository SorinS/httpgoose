/* upfile on its own: a file read in pieces, its size, read again after a
   rewind; standard input; a missing file. Exit status 0 if all is right. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } upfile_slice;
typedef struct { uint8_t *data; int64_t len; } upfile_buf;
int64_t upfile_open(upfile_slice path);
int64_t upfile_size(int64_t fd);
int64_t upfile_read(int64_t fd, upfile_buf buf);
int upfile_rewind(int64_t fd);
void upfile_close(int64_t fd);

static int fails;
static void check(const char *what, int ok) { printf("%s %s\n", ok ? "ok  " : "FAIL", what); if (!ok) fails++; }

int main(int argc, char **argv) {
    long long want_size = argc > 1 ? atoll(argv[1]) : -1;
    static uint8_t want[300000], got[300000];
    for (int i = 0; i < 300000; i++) want[i] = (uint8_t)(i * 7 + (i >> 8));
    want[100] = '\r'; want[101] = '\n'; want[102] = 0x1a;    /* text-mode traps */
    FILE *f = fopen("up.bin", "wb");
    fwrite(want, 1, sizeof want, f);
    fclose(f);
    upfile_slice p = { (const uint8_t *)"up.bin", 6 };
    int64_t fd = upfile_open(p);
    check("open", fd >= 0);
    check("size", upfile_size(fd) == 300000);
    for (int pass = 0; pass < 2; pass++) {
        int64_t at = 0, n;
        uint8_t chunk[65536];
        while ((n = upfile_read(fd, (upfile_buf){ chunk, sizeof chunk })) > 0) {
            if (at + n > (int64_t)sizeof got) { at = -1; break; }
            memcpy(got + at, chunk, (size_t)n);
            at += n;
        }
        check(pass ? "read again after the rewind, byte for byte" : "read in pieces, byte for byte",
              at == 300000 && memcmp(got, want, sizeof want) == 0);
        if (!pass) check("rewind", upfile_rewind(fd) == 1);
    }
    upfile_close(fd);
    upfile_slice missing = { (const uint8_t *)"no-such-file", 12 };
    check("a missing file", upfile_open(missing) == -1);
    upfile_slice dash = { (const uint8_t *)"-", 1 };
    int64_t in = upfile_open(dash);
    check(want_size < 0 ? "stdin (a pipe) is descriptor 0, of no size" : "stdin (a file) is descriptor 0, of its size", in == 0 && upfile_size(in) == want_size);
    uint8_t buf[100];
    int64_t n = upfile_read(in, (upfile_buf){ buf, sizeof buf });
    check("stdin read in binary mode", n == 5 && memcmp(buf, "a\r\nb\n", 5) == 0);
    remove("up.bin");
    return fails ? 1 : 0;
}
