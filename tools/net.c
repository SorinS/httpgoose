/* The operating system's part of tools/httpd.goose and tools/http.goose:
   TCP sockets, waiting on one descriptor, processes for connections, and
   resolving paths. POSIX: macOS and Linux. Each function returns -1 (or a
   negative value) on failure; strings arrive as Goose slices,
   { data, len }, not NUL-terminated. */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct { const uint8_t *data; int64_t len; } net_slice;
typedef struct { uint8_t *data; int64_t len; } net_buf;

/* A slice as a C string, in a buffer of the caller's. */
static int cstring(net_slice s, char *out, size_t cap) {
    if (s.len < 0 || (size_t)s.len >= cap) return -1;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    if (memchr(out, 0, (size_t)s.len)) return -1;
    return 0;
}

void net_init(void) { signal(SIGPIPE, SIG_IGN); }

int32_t net_connect(net_slice host, int32_t port) {
    char h[256], p[16];
    if (cstring(host, h, sizeof h) < 0) return -1;
    snprintf(p, sizeof p, "%d", (int)port);
    struct addrinfo hints = {0}, *res, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return fd;
}

/* A listening socket on addr (a numeric address: "127.0.0.1", "::1"), or
   -1. Port 0 picks one (net_local_port says which). */
int32_t net_listen(net_slice addr, int32_t port) {
    char a[64], p[16];
    if (cstring(addr, a, sizeof a) < 0) return -1;
    snprintf(p, sizeof p, "%d", (int)port);
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    if (getaddrinfo(a, p, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, 128) < 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

int32_t net_local_port(int32_t fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &len) < 0) return -1;
    if (ss.ss_family == AF_INET) return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    return -1;
}

int32_t net_accept(int32_t fd) {
    int c;
    do { c = accept(fd, NULL, NULL); } while (c < 0 && errno == EINTR);
    if (c >= 0) {
        int one = 1;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return c;
}

int64_t net_read(int32_t fd, net_buf buf) {
    ssize_t n;
    do { n = read(fd, buf.data, (size_t)buf.len); } while (n < 0 && errno == EINTR);
    return n;
}

/* All of data, or -1. */
int64_t net_write(int32_t fd, net_slice data) {
    int64_t off = 0;
    while (off < data.len) {
        ssize_t n = write(fd, data.data + off, (size_t)(data.len - off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += n;
    }
    return off;
}

void net_close(int32_t fd) { if (fd >= 0) close(fd); }
void net_shutdown_write(int32_t fd) { if (fd >= 0) shutdown(fd, SHUT_WR); }

/* 1 if fd is readable (or closed), 0 on timeout, -1 on error. */
int32_t net_wait(int32_t fd, int32_t timeout_ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    int r;
    do { r = poll(&p, 1, timeout_ms); } while (r < 0 && errno == EINTR);
    return r;
}

/* fork(), the child with default SIGCHLD; -1 on failure. */
int32_t proc_fork(void) { return fork(); }
void proc_exit(int32_t code) { _exit(code); }

/* Reaps children that have exited, without waiting. */
void proc_reap(void) { while (waitpid(-1, NULL, WNOHANG) > 0) {} }

/* The canonical absolute path of an existing path (symbolic links
   resolved), or -1. */
int64_t fs_realpath(net_slice path, net_buf out) {
    char p[PATH_MAX], r[PATH_MAX];
    if (cstring(path, p, sizeof p) < 0) return -1;
    if (!realpath(p, r)) return -1;
    size_t n = strlen(r);
    if ((int64_t)n > out.len) return -1;
    memcpy(out.data, r, n);
    return (int64_t)n;
}
