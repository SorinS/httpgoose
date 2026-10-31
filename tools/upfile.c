/* upfile: goose-http's reads of a file to upload (-T), a piece at a time,
   so a large one is not held in memory. POSIX and Windows. A path
   arrives as a Goose slice, { data, len }; "-" is standard input. */

#if defined(_WIN32)
#  include <fcntl.h>
#  include <io.h>
#  include <sys/stat.h>
#  define open_ _open
#  define read_ _read
#  define close_ _close
#  define O_FLAGS (_O_RDONLY | _O_BINARY)
#else
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  define open_ open
#  define read_ read
#  define close_ close
#  define O_FLAGS O_RDONLY
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } upfile_slice;
typedef struct { uint8_t *data; int64_t len; } upfile_buf;

/* A descriptor for the file, or -1. */
int64_t upfile_open(upfile_slice path) {
    if (path.len == 1 && path.data[0] == '-') {
#if defined(_WIN32)
        _setmode(0, _O_BINARY);
#endif
        return 0;
    }
    char *p = malloc((size_t)path.len + 1);
    if (!p) return -1;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    int fd = open_(p, O_FLAGS);
    free(p);
    return fd < 0 ? -1 : fd;
}

/* The size of a regular file, or -1 (standard input, a pipe). */
int64_t upfile_size(int64_t fd) {
#if defined(_WIN32)
    struct _stat64 st;
    if (_fstat64((int)fd, &st) != 0 || (st.st_mode & _S_IFMT) != _S_IFREG) return -1;
#else
    struct stat st;
    if (fstat((int)fd, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
#endif
    return (int64_t)st.st_size;
}

/* Bytes read into buf, 0 at the end, -1 on an error. */
int64_t upfile_read(int64_t fd, upfile_buf buf) {
    for (;;) {
        unsigned n = buf.len > (1 << 30) ? (1u << 30) : (unsigned)buf.len;
        int64_t r = read_((int)fd, buf.data, n);
        if (r < 0 && errno == EINTR) continue;
        return r < 0 ? -1 : r;
    }
}

/* Back to the start of a regular file: 1, or 0 if it cannot be. */
int upfile_rewind(int64_t fd) {
#if defined(_WIN32)
    return _lseeki64((int)fd, 0, SEEK_SET) == 0;
#else
    return lseek((int)fd, 0, SEEK_SET) == 0;
#endif
}

void upfile_close(int64_t fd) {
    if (fd > 0) close_((int)fd);
}
