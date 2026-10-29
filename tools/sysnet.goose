// The operating system for tools/httpd.goose and tools/http.goose: the C
// of tools/net.c, declared for Goose, and a few helpers. Each root file's
// .build sidecar compiles net.c.
namespace sysnet;

import std;
import os;

extern fn net_init();
extern fn net_connect(host: const u8[:], port: i32) -> i32;
extern fn net_listen(addr: const u8[:], port: i32) -> i32;
extern fn net_local_port(fd: i32) -> i32;
extern fn net_accept(fd: i32) -> i32;
extern fn net_read(fd: i32, buf: u8[:]) -> i64;
extern fn net_write(fd: i32, data: const u8[:]) -> i64;
extern fn net_close(fd: i32);
extern fn net_shutdown_write(fd: i32);
// 1 if fd is readable or closed, 0 on timeout, -1 on error.
extern fn net_wait(fd: i32, timeout_ms: i32) -> i32;
extern fn proc_fork() -> i32;
extern fn proc_exit(code: i32);
extern fn proc_reap();
extern fn fs_realpath(path: const u8[:], out: u8[:]) -> i64;

// Reads what is there (up to 64 KB) into a builder: how many bytes, 0 at
// the end, -1 on error.
fn read_some(fd: i32, out: u8[>..]&) -> i64 {
    var buf: u8[65536] = [0; 65536];
    let n = net_read(fd, buf);
    if n > 0 { out.append(buf[..n]); }
    return n;
}

// The canonical path, or "" if there is none.
fn realpath(path: const u8[:]) -> u8[>..] {
    var buf: u8[4096] = [0; 4096];
    var out: u8[>..] = [];
    let n = fs_realpath(path, buf);
    if n > 0 { out.append(buf[..n]); }
    return out;
}
