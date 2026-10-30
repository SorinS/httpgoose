/* httpnet: the sockets of http.client (client.goose). TCP connections
   with a deadline on connecting, reads and writes with timeouts, and a
   check whether an idle connection has been closed. POSIX (macOS, Linux)
   and Windows (Winsock). A socket is an int64_t; strings arrive as Goose
   slices, { data, len }, not NUL-terminated.

   Results: >= 0 on success, else one of the HTTPNET_E* codes below. */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET sock_t;
#  define BAD_SOCK INVALID_SOCKET
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <time.h>
#  include <unistd.h>
typedef int sock_t;
#  define BAD_SOCK (-1)
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } httpnet_slice;
typedef struct { uint8_t *data; int64_t len; } httpnet_buf;

#define HTTPNET_EARG     (-1)   /* a host or port that cannot be used */
#define HTTPNET_ERESOLVE (-2)   /* the name does not resolve */
#define HTTPNET_ECONNECT (-3)   /* refused or unreachable */
#define HTTPNET_ETIMEOUT (-4)
#define HTTPNET_EIO      (-5)   /* reset, or another error on the socket */

static int64_t now_ms(void) {
#if defined(_WIN32)
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

#if defined(_WIN32)
static int started;
static void start(void) {
    if (!started) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        started = 1;
    }
}
static int sock_poll(sock_t s, short events, int timeout_ms) {
    WSAPOLLFD p;
    p.fd = s;
    p.events = events;
    p.revents = 0;
    int r = WSAPoll(&p, 1, timeout_ms);
    if (r > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL)) && !(p.revents & events)) return 1;
    return r;
}
static void set_nonblocking(sock_t s, int on) { u_long v = on ? 1 : 0; ioctlsocket(s, FIONBIO, &v); }
static void sock_close(sock_t s) { closesocket(s); }
static int in_progress(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
static void start(void) {}
static int sock_poll(sock_t s, short events, int timeout_ms) {
    struct pollfd p = { s, events, 0 };
    int r;
    do { r = poll(&p, 1, timeout_ms); } while (r < 0 && errno == EINTR);
    return r;
}
static void set_nonblocking(sock_t s, int on) {
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}
static void sock_close(sock_t s) { close(s); }
static int in_progress(void) { return errno == EINPROGRESS; }
#endif

/* The time left before a deadline (ms), for poll: -1 for none. */
static int left(int64_t deadline) {
    if (deadline == 0) return -1;
    int64_t l = deadline - now_ms();
    return l < 0 ? 0 : (int)(l > 0x7fffffff ? 0x7fffffff : l);
}

/* A connection to host:port, each of its addresses tried in turn until
   timeout_ms (0: none) has passed. The host is a name or a numeric
   address, without brackets. */
int64_t httpnet_connect(httpnet_slice host, int32_t port, int32_t timeout_ms) {
    char h[256], p[16];
    if (host.len <= 0 || host.len >= (int64_t)sizeof h || port <= 0 || port > 65535) return HTTPNET_EARG;
    memcpy(h, host.data, (size_t)host.len);
    h[host.len] = 0;
    if (memchr(h, 0, (size_t)host.len)) return HTTPNET_EARG;
    snprintf(p, sizeof p, "%d", (int)port);
    start();
    int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return HTTPNET_ERESOLVE;
    int64_t result = HTTPNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        set_nonblocking(s, 1);
        int ok = connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0;
        if (!ok && in_progress()) {
            int r = sock_poll(s, POLLOUT, left(deadline));
            if (r == 0) {
                sock_close(s);
                result = HTTPNET_ETIMEOUT;
                break;
            }
            int err = 0;
            socklen_t len = sizeof err;
            ok = r > 0 && getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) == 0 && err == 0;
        }
        if (!ok) {
            sock_close(s);
            if (deadline && now_ms() >= deadline) { result = HTTPNET_ETIMEOUT; break; }
            continue;
        }
        set_nonblocking(s, 0);
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
#if defined(SO_NOSIGPIPE)
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* Up to buf.len bytes: how many, 0 at the end of the stream, or an error;
   HTTPNET_ETIMEOUT if nothing came within timeout_ms (0: wait for ever). */
int64_t httpnet_read(int64_t fd, httpnet_buf buf, int32_t timeout_ms) {
    sock_t s = (sock_t)fd;
    if (timeout_ms > 0) {
        int r = sock_poll(s, POLLIN, timeout_ms);
        if (r == 0) return HTTPNET_ETIMEOUT;
        if (r < 0) return HTTPNET_EIO;
    }
    int64_t n;
    size_t want = buf.len > (1 << 30) ? (size_t)1 << 30 : (size_t)buf.len;
#if defined(_WIN32)
    n = recv(s, (char *)buf.data, (int)want, 0);
#else
    do { n = recv(s, buf.data, want, 0); } while (n < 0 && errno == EINTR);
#endif
    return n < 0 ? HTTPNET_EIO : n;
}

/* All of data, or an error; HTTPNET_ETIMEOUT if the peer takes nothing
   for timeout_ms (0: wait for ever). */
int64_t httpnet_write(int64_t fd, httpnet_slice data, int32_t timeout_ms) {
    sock_t s = (sock_t)fd;
    int64_t off = 0;
    while (off < data.len) {
        if (timeout_ms > 0) {
            int r = sock_poll(s, POLLOUT, timeout_ms);
            if (r == 0) return HTTPNET_ETIMEOUT;
            if (r < 0) return HTTPNET_EIO;
        }
        int64_t want = data.len - off;
        if (want > (1 << 30)) want = 1 << 30;
        int64_t n;
#if defined(_WIN32)
        n = send(s, (const char *)data.data + off, (int)want, 0);
#elif defined(MSG_NOSIGNAL)
        do { n = send(s, data.data + off, (size_t)want, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
#else
        do { n = send(s, data.data + off, (size_t)want, 0); } while (n < 0 && errno == EINTR);
#endif
        if (n <= 0) return HTTPNET_EIO;
        off += n;
    }
    return off;
}

/* Whether something has come on an idle connection: 1 (bytes, its end,
   or an error: either way it cannot carry a new request), 0 if nothing. */
int32_t httpnet_readable(int64_t fd) {
    int r = sock_poll((sock_t)fd, POLLIN, 0);
    return r != 0 ? 1 : 0;
}

void httpnet_close(int64_t fd) {
    if (fd >= 0) sock_close((sock_t)fd);
}
