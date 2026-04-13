#!/usr/bin/env python3
"""
Network probe server — run on a VPS outside the filter.
Listens on a base port and a range around it for TCP, UDP, HTTP, and TLS.
Pairs with network_probe_client.py running inside the filtered network.

Usage:
    sudo python3 network_probe_server.py <base_port>

This will listen on:
    TCP  base_port          (raw echo)
    UDP  base_port          (raw echo)
    TCP  base_port+1        (HTTP — replies with HTTP 200)
    TCP  base_port+2        (TLS — self-signed, replies after handshake)
    TCP  base_port+3        (DNS over TCP mock — echoes DNS-shaped replies)
    UDP  base_port+3        (DNS over UDP mock)
    TCP/UDP base_port+10..+19  (port range scan targets)

Also responds to ICMP echo if the OS allows (most Linux does by default).
"""

import os
import socket
import ssl
import struct
import sys
import signal
import tempfile
import threading
import time

BANNER = b"PROBE_OK"
RUN = True


def log(tag: str, msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"  [{ts}] [{tag}] {msg}")


# ---------------------------------------------------------------------------
# TCP echo
# ---------------------------------------------------------------------------
def tcp_echo(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sock.settimeout(2.0)
    log("TCP-ECHO", f"listening :{port}")
    while RUN:
        try:
            conn, addr = sock.accept()
            log("TCP-ECHO", f"connection from {addr[0]}:{addr[1]}")
            with conn:
                conn.settimeout(5.0)
                data = conn.recv(4096)
                conn.sendall(BANNER + b" " + data)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# UDP echo
# ---------------------------------------------------------------------------
def udp_echo(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(2.0)
    log("UDP-ECHO", f"listening :{port}")
    while RUN:
        try:
            data, addr = sock.recvfrom(4096)
            log("UDP-ECHO", f"packet from {addr[0]}:{addr[1]} ({len(data)}B)")
            sock.sendto(BANNER + b" " + data, addr)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# HTTP server (minimal)
# ---------------------------------------------------------------------------
HTTP_RESP = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 8\r\n"
    b"Connection: close\r\n\r\n"
    b"PROBE_OK"
)


def http_handler(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sock.settimeout(2.0)
    log("HTTP", f"listening :{port}")
    while RUN:
        try:
            conn, addr = sock.accept()
            log("HTTP", f"connection from {addr[0]}:{addr[1]}")
            with conn:
                conn.settimeout(5.0)
                conn.recv(4096)
                conn.sendall(HTTP_RESP)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# TLS server (self-signed cert generated at startup)
# ---------------------------------------------------------------------------
def _generate_self_signed() -> tuple[str, str]:
    """Generate a self-signed cert+key using openssl CLI, return (cert_path, key_path)."""
    d = tempfile.mkdtemp(prefix="probe_tls_")
    cert = os.path.join(d, "cert.pem")
    key = os.path.join(d, "key.pem")
    os.system(
        f'openssl req -x509 -newkey rsa:2048 -keyout {key} -out {cert} '
        f'-days 1 -nodes -subj "/CN=probe" 2>/dev/null'
    )
    return cert, key


def tls_handler(port: int) -> None:
    try:
        cert, key = _generate_self_signed()
    except Exception as e:
        log("TLS", f"cannot generate cert: {e} — skipping TLS listener")
        return

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(cert, key)
    except Exception as e:
        log("TLS", f"cannot load cert: {e} — skipping TLS listener")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sock.settimeout(2.0)
    log("TLS", f"listening :{port}")
    while RUN:
        try:
            conn, addr = sock.accept()
            log("TLS", f"connection from {addr[0]}:{addr[1]}")
            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
                tls_conn.settimeout(5.0)
                tls_conn.recv(4096)
                tls_conn.sendall(BANNER)
                tls_conn.shutdown(socket.SHUT_RDWR)
                tls_conn.close()
            except (ssl.SSLError, OSError) as e:
                log("TLS", f"handshake/IO error from {addr}: {e}")
                conn.close()
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# DNS mock (replies with a valid-looking DNS response)
# ---------------------------------------------------------------------------
def _make_dns_response(query: bytes) -> bytes:
    """Build a minimal DNS response echoing the query ID + a fixed A record."""
    if len(query) < 12:
        return b""
    txid = query[:2]
    flags = struct.pack("!H", 0x8180)  # standard response, no error
    counts = struct.pack("!HHHH", 1, 1, 0, 0)
    qsection = query[12:]
    # answer: pointer to name in question, type A, class IN, TTL 60, 4 bytes, 1.2.3.4
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return txid + flags + counts + qsection + answer


def dns_tcp_handler(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sock.settimeout(2.0)
    log("DNS-TCP", f"listening :{port}")
    while RUN:
        try:
            conn, addr = sock.accept()
            log("DNS-TCP", f"query from {addr[0]}:{addr[1]}")
            with conn:
                conn.settimeout(5.0)
                raw = conn.recv(4096)
                if len(raw) > 2:
                    query = raw[2:]  # strip 2-byte length prefix
                    resp = _make_dns_response(query)
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


def dns_udp_handler(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(2.0)
    log("DNS-UDP", f"listening :{port}")
    while RUN:
        try:
            data, addr = sock.recvfrom(4096)
            log("DNS-UDP", f"query from {addr[0]}:{addr[1]}")
            resp = _make_dns_response(data)
            if resp:
                sock.sendto(resp, addr)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# Port-range listeners (simple TCP accept + UDP echo on base+10..+19)
# ---------------------------------------------------------------------------
def port_range_tcp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        return
    sock.listen(8)
    sock.settimeout(2.0)
    while RUN:
        try:
            conn, addr = sock.accept()
            log("PORT-TCP", f":{port} from {addr[0]}:{addr[1]}")
            with conn:
                conn.sendall(BANNER)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


def port_range_udp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        return
    sock.settimeout(2.0)
    while RUN:
        try:
            data, addr = sock.recvfrom(4096)
            log("PORT-UDP", f":{port} from {addr[0]}:{addr[1]}")
            sock.sendto(BANNER, addr)
        except socket.timeout:
            continue
        except OSError:
            if RUN:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    global RUN
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <base_port>", file=sys.stderr)
        print("  Listens on base_port..base_port+19 for various probes.", file=sys.stderr)
        sys.exit(1)

    base = int(sys.argv[1])
    if not (1 <= base <= 65500):
        print("Base port must be 1-65500.", file=sys.stderr)
        sys.exit(1)

    def stop(*_a):
        global RUN
        RUN = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    threads: list[threading.Thread] = []

    def start(fn, *args):
        t = threading.Thread(target=fn, args=args, daemon=True)
        t.start()
        threads.append(t)

    # Core listeners
    start(tcp_echo, base)
    start(udp_echo, base)
    start(http_handler, base + 1)
    start(tls_handler, base + 2)
    start(dns_tcp_handler, base + 3)
    start(dns_udp_handler, base + 3)

    # Port range
    for offset in range(10, 20):
        start(port_range_tcp, base + offset)
        start(port_range_udp, base + offset)

    print(f"Probe server running. Base port: {base}")
    print(f"  TCP/UDP echo : {base}")
    print(f"  HTTP          : {base + 1}")
    print(f"  TLS           : {base + 2}")
    print(f"  DNS mock      : {base + 3}")
    print(f"  Port range    : {base + 10}..{base + 19} (TCP+UDP)")
    print("Ctrl+C to stop.\n")

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
