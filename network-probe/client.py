#!/usr/bin/env python3
"""
Network probe client — run from inside the filtered network (e.g. Iran).
Tests every practical network layer/protocol to find what passes through.

Usage:
    sudo python3 network_probe_client.py <server_ip> <base_port>

The server must be running network_probe_server.py on the same base_port.
Run with sudo to enable raw-socket tests (SYN, ACK, FIN, XMAS, NULL, ICMP, GRE, IPIP).
"""

import json
import os
import platform
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

BANNER = b"PROBE_OK"
TIMEOUT = 8
PING_TIMEOUT = 5
IS_ROOT = os.geteuid() == 0 if hasattr(os, "geteuid") else False


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

class Results:
    def __init__(self):
        self._rows: list[dict] = []
        self._lock = threading.Lock()

    def add(self, category: str, name: str, passed: bool, ms: float, detail: str = ""):
        with self._lock:
            self._rows.append({
                "cat": category,
                "name": name,
                "ok": passed,
                "ms": ms,
                "detail": detail,
            })
            tag = "\033[32mPASS\033[0m" if passed else "\033[31mFAIL\033[0m"
            d = f" — {detail}" if detail else ""
            print(f"  [{tag}] {name:.<52s} {ms:7.0f}ms{d}")

    def summary(self):
        print("\n" + "=" * 72)
        print("SUMMARY")
        print("=" * 72)
        cats = sorted(set(r["cat"] for r in self._rows))
        for cat in cats:
            rows = [r for r in self._rows if r["cat"] == cat]
            p = sum(1 for r in rows if r["ok"])
            print(f"\n  [{cat}]  {p}/{len(rows)} passed")
            for r in rows:
                tag = "OK" if r["ok"] else "--"
                print(f"    {tag}  {r['name']}")

        passed = [r for r in self._rows if r["ok"]]
        failed = [r for r in self._rows if not r["ok"]]
        print(f"\nTotal: {len(passed)} passed, {len(failed)} failed out of {len(self._rows)} tests")

        if passed:
            print("\nOpen paths you can exploit:")
            for r in passed:
                print(f"  + {r['name']}")
        print()


R = Results()


def timed(fn):
    """Run fn(), return (result, elapsed_ms)."""
    t0 = time.monotonic()
    try:
        ok = fn()
    except Exception:
        ok = False
    return ok, (time.monotonic() - t0) * 1000


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _get_src_ip() -> bytes:
    """Best-effort source IP (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return socket.inet_aton(ip)
    except Exception:
        return socket.inet_aton("0.0.0.0")


def _resolve(host: str) -> bytes:
    try:
        return socket.inet_aton(socket.gethostbyname(host))
    except socket.gaierror:
        return socket.inet_aton(host)


# ═══════════════════════════════════════════════════════════════════════════
# L3 — ICMP
# ═══════════════════════════════════════════════════════════════════════════

def test_icmp_ping(host: str) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    wflag = "-w" if platform.system() == "Windows" else "-W"
    try:
        r = subprocess.run(
            ["ping", flag, "1", wflag, str(PING_TIMEOUT), host],
            capture_output=True, timeout=PING_TIMEOUT + 3,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def test_raw_icmp_echo(host: str) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(TIMEOUT)
    pid = os.getpid() & 0xFFFF
    payload = b"\xab" * 56
    hdr = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
    cs = _checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", 8, 0, cs, pid, 1)
    s.sendto(hdr + payload, (host, 0))
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        data, addr = s.recvfrom(1024)
        if len(data) >= 28 and data[20] == 0:  # ICMP echo reply
            s.close()
            return True
    s.close()
    return False


def test_icmp_timestamp(host: str) -> bool:
    """ICMP timestamp request (type 13). Some filters block echo but allow others."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(TIMEOUT)
    pid = os.getpid() & 0xFFFF
    originate = int(time.time()) & 0xFFFFFFFF
    payload = struct.pack("!III", originate, 0, 0)
    hdr = struct.pack("!BBHHH", 13, 0, 0, pid, 1)
    cs = _checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", 13, 0, cs, pid, 1)
    s.sendto(hdr + payload, (host, 0))
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        data, _ = s.recvfrom(1024)
        if len(data) >= 28 and data[20] == 14:  # ICMP timestamp reply
            s.close()
            return True
    s.close()
    return False


# ═══════════════════════════════════════════════════════════════════════════
# L4 — TCP (socket-level)
# ═══════════════════════════════════════════════════════════════════════════

def test_tcp_connect(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    s.close()
    return True


def test_tcp_data(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    s.sendall(b"DATA_TEST")
    data = s.recv(128)
    s.close()
    return data.startswith(BANNER)


def test_tcp_large_payload(host: str, port: int) -> bool:
    """Send a large payload — detect MTU/size-based filtering."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    s.sendall(b"X" * 8192)
    data = s.recv(128)
    s.close()
    return data.startswith(BANNER)


# ═══════════════════════════════════════════════════════════════════════════
# L4 — UDP
# ═══════════════════════════════════════════════════════════════════════════

def test_udp(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    s.sendto(b"UDP_TEST", (host, port))
    data, _ = s.recvfrom(128)
    s.close()
    return data.startswith(BANNER)


def test_udp_large(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    s.sendto(b"U" * 1400, (host, port))
    data, _ = s.recvfrom(128)
    s.close()
    return data.startswith(BANNER)


# ═══════════════════════════════════════════════════════════════════════════
# L7 — DNS
# ═══════════════════════════════════════════════════════════════════════════

def _build_dns_query(domain: str = "example.com") -> bytes:
    txid = struct.pack("!H", os.getpid() & 0xFFFF)
    flags = struct.pack("!H", 0x0100)  # standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    qtype = struct.pack("!HH", 1, 1)  # A record, IN class
    return txid + flags + counts + qname + qtype


def test_dns_udp(host: str, port: int) -> bool:
    """DNS query over UDP to our mock server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    s.sendto(_build_dns_query(), (host, port))
    data, _ = s.recvfrom(512)
    s.close()
    return len(data) >= 12 and (data[2] & 0x80) != 0  # QR bit set = response


def test_dns_tcp(host: str, port: int) -> bool:
    """DNS query over TCP to our mock server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    q = _build_dns_query()
    s.sendall(struct.pack("!H", len(q)) + q)
    raw = s.recv(512)
    s.close()
    if len(raw) > 2:
        resp = raw[2:]
        return len(resp) >= 12 and (resp[2] & 0x80) != 0
    return False


def test_dns_public(resolver: str = "8.8.8.8") -> bool:
    """DNS query to a public resolver (Google 8.8.8.8) — tests if UDP/53 is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    s.sendto(_build_dns_query("google.com"), (resolver, 53))
    data, _ = s.recvfrom(512)
    s.close()
    return len(data) >= 12 and (data[2] & 0x80) != 0


# ═══════════════════════════════════════════════════════════════════════════
# L7 — HTTP
# ═══════════════════════════════════════════════════════════════════════════

def test_http(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = s.recv(4096)
    s.close()
    return b"PROBE_OK" in data


# ═══════════════════════════════════════════════════════════════════════════
# L7 — TLS
# ═══════════════════════════════════════════════════════════════════════════

def test_tls(host: str, port: int) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    s = ctx.wrap_socket(raw, server_hostname=host)
    s.connect((host, port))
    s.sendall(b"TLS_TEST")
    data = s.recv(128)
    s.close()
    return data.startswith(BANNER)


def test_tls_with_sni(host: str, port: int, sni: str = "www.google.com") -> bool:
    """TLS with a fake SNI — tests if SNI-based filtering is in play."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    s = ctx.wrap_socket(raw, server_hostname=sni)
    s.connect((host, port))
    s.sendall(b"SNI_TEST")
    data = s.recv(128)
    s.close()
    return data.startswith(BANNER)


# ═══════════════════════════════════════════════════════════════════════════
# Raw TCP flag tests (require root)
# ═══════════════════════════════════════════════════════════════════════════

def _build_raw_tcp(host: str, port: int, flags: int, src_port: int = 0) -> tuple[bytes, socket.socket]:
    """Build a raw TCP segment with given flags. Returns (packet, raw_socket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(TIMEOUT)
    if src_port == 0:
        src_port = 40000 + (os.getpid() % 20000)
    seq = 0xAAAA0000 | (os.getpid() & 0xFFFF)
    ack_seq = 0

    src_ip = _get_src_ip()
    dst_ip = _resolve(host)

    tcp_hdr = struct.pack("!HHLLBBHHH",
                          src_port, port, seq, ack_seq,
                          0x50, flags, 0xFFFF, 0, 0)
    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
    cs = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBH", src_port, port, seq, ack_seq,
                          0x50, flags, 0xFFFF) + struct.pack("!HH", cs, 0)
    return tcp_hdr, s


def _raw_tcp_probe(host: str, port: int, flags: int, expect_any_reply: bool = True) -> bool:
    """Send a raw TCP packet with given flags. Return True if we get any TCP reply."""
    pkt, s = _build_raw_tcp(host, port, flags)
    s.sendto(pkt, (host, port))
    deadline = time.monotonic() + TIMEOUT
    dst_ip = _resolve(host)
    while time.monotonic() < deadline:
        try:
            data, addr = s.recvfrom(1024)
        except socket.timeout:
            break
        if len(data) >= 40:
            # Verify it's from the right host + port
            ip_src = data[12:16]
            if ip_src == dst_ip:
                s.close()
                return True
    s.close()
    return False


def test_raw_syn(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x02)  # SYN


def test_raw_ack(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x10)  # ACK


def test_raw_fin(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x01)  # FIN


def test_raw_syn_ack(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x12)  # SYN+ACK


def test_raw_psh_ack(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x18)  # PSH+ACK


def test_raw_rst(host: str, port: int) -> bool:
    return _raw_tcp_probe(host, port, 0x04)  # RST


def test_raw_xmas(host: str, port: int) -> bool:
    """XMAS scan: FIN+PSH+URG. Stateful firewalls drop these."""
    return _raw_tcp_probe(host, port, 0x29)  # FIN+PSH+URG


def test_raw_null(host: str, port: int) -> bool:
    """NULL scan: no flags at all."""
    return _raw_tcp_probe(host, port, 0x00)


# ═══════════════════════════════════════════════════════════════════════════
# IP protocol tests (require root): GRE, IPIP, ESP
# ═══════════════════════════════════════════════════════════════════════════

def _test_ip_proto(host: str, proto: int) -> bool:
    """Send a raw IP packet with a given protocol number, see if any ICMP unreachable comes back."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        s.settimeout(TIMEOUT)
        s.sendto(b"\x00" * 16, (host, 0))
        try:
            data, _ = s.recvfrom(1024)
            s.close()
            return True
        except socket.timeout:
            s.close()
            # No reply ≠ necessarily blocked; but for GRE/IPIP/ESP,
            # getting ICMP unreachable or protocol reply = path open.
            # Timeout often means filtered. We also try the ICMP approach.
            return False
    except (PermissionError, OSError):
        return False


def test_gre(host: str) -> bool:
    """IP protocol 47 (GRE) — used by PPTP and GRE tunnels."""
    return _test_ip_proto(host, 47)


def test_ipip(host: str) -> bool:
    """IP protocol 4 (IP-in-IP) — used by some tunnels."""
    return _test_ip_proto(host, 4)


def test_esp(host: str) -> bool:
    """IP protocol 50 (ESP) — used by IPsec."""
    return _test_ip_proto(host, 50)


# ═══════════════════════════════════════════════════════════════════════════
# Fragmentation test
# ═══════════════════════════════════════════════════════════════════════════

def test_fragment(host: str) -> bool:
    """Send fragmented ICMP (two fragments). Some DPI can't reassemble."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(TIMEOUT)

        src_ip = _get_src_ip()
        dst_ip = _resolve(host)
        ident = os.getpid() & 0xFFFF
        pid = os.getpid() & 0xFFFF

        # Build ICMP echo request (payload = 64 bytes)
        icmp_payload = b"\xcc" * 64
        icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
        cs = _checksum(icmp_hdr + icmp_payload)
        icmp_hdr = struct.pack("!BBHHH", 8, 0, cs, pid, 1)
        icmp_pkt = icmp_hdr + icmp_payload  # 72 bytes

        # Fragment 1: first 32 bytes of ICMP, MF=1
        frag1_data = icmp_pkt[:32]
        ip1 = struct.pack("!BBHHHBBH4s4s",
                          0x45, 0, 20 + len(frag1_data), ident,
                          (1 << 13) | 0,  # MF=1, offset=0
                          64, socket.IPPROTO_ICMP, 0, src_ip, dst_ip)
        ip1_cs = _checksum(ip1)
        ip1 = ip1[:10] + struct.pack("!H", ip1_cs) + ip1[12:]

        # Fragment 2: remaining bytes, MF=0, offset=32/8=4
        frag2_data = icmp_pkt[32:]
        ip2 = struct.pack("!BBHHHBBH4s4s",
                          0x45, 0, 20 + len(frag2_data), ident,
                          0 | 4,  # MF=0, offset=4 (in 8-byte units)
                          64, socket.IPPROTO_ICMP, 0, src_ip, dst_ip)
        ip2_cs = _checksum(ip2)
        ip2 = ip2[:10] + struct.pack("!H", ip2_cs) + ip2[12:]

        s.sendto(ip1 + frag1_data, (host, 0))
        s.sendto(ip2 + frag2_data, (host, 0))

        # Listen for echo reply
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.settimeout(TIMEOUT)
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            data, _ = icmp_sock.recvfrom(1024)
            if len(data) >= 28 and data[20] == 0:
                icmp_sock.close()
                s.close()
                return True
        icmp_sock.close()
        s.close()
        return False
    except (PermissionError, OSError):
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Traceroute (TTL-based)
# ═══════════════════════════════════════════════════════════════════════════

def test_traceroute(host: str, max_hops: int = 20) -> str:
    """ICMP-based traceroute. Returns the hop where packets stop (filtering point)."""
    last_hop = 0
    last_addr = ""
    dst_ip = _resolve(host)
    pid = os.getpid() & 0xFFFF
    for ttl in range(1, max_hops + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(3.0)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            payload = b"\x00" * 56
            hdr = struct.pack("!BBHHH", 8, 0, 0, pid, ttl)
            cs = _checksum(hdr + payload)
            hdr = struct.pack("!BBHHH", 8, 0, cs, pid, ttl)
            s.sendto(hdr + payload, (host, 0))
            data, addr = s.recvfrom(1024)
            last_hop = ttl
            last_addr = addr[0]
            if addr[0] == socket.inet_ntoa(dst_ip):
                s.close()
                return f"reached in {ttl} hops"
            s.close()
        except socket.timeout:
            # No response at this TTL — likely the filter point
            try:
                s.close()
            except Exception:
                pass
            if last_hop > 0:
                return f"stopped at hop {ttl} (last seen: hop {last_hop} = {last_addr})"
            return f"no response from hop 1 — network may be fully down"
        except (PermissionError, OSError) as e:
            return f"error at hop {ttl}: {e}"
    return f"did not reach target in {max_hops} hops (last: hop {last_hop} = {last_addr})"


# ═══════════════════════════════════════════════════════════════════════════
# Port range scan
# ═══════════════════════════════════════════════════════════════════════════

def test_port_range(host: str, base: int) -> tuple[list[int], list[int]]:
    """Test TCP+UDP on base+10..base+19 to find port-specific filtering."""
    tcp_open = []
    udp_open = []
    for p in range(base + 10, base + 20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((host, p))
            d = s.recv(64)
            s.close()
            if d.startswith(BANNER):
                tcp_open.append(p)
        except (socket.error, OSError):
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            s.sendto(b"P", (host, p))
            d, _ = s.recvfrom(64)
            s.close()
            if d.startswith(BANNER):
                udp_open.append(p)
        except (socket.error, OSError):
            pass
    return tcp_open, udp_open


# ═══════════════════════════════════════════════════════════════════════════
# Well-known ports (no probe server needed)
# ═══════════════════════════════════════════════════════════════════════════

def test_wellknown_tcp(host: str) -> dict[int, bool]:
    ports = [22, 53, 80, 443, 993, 995, 8080, 8443, 8880, 2083, 2096]
    out = {}
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((host, p))
            s.close()
            out[p] = True
        except (socket.error, OSError):
            out[p] = False
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def run_test(cat: str, name: str, fn):
    ok, ms = timed(fn)
    R.add(cat, name, ok, ms)


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <server_ip> <base_port>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    base = int(sys.argv[2])

    print(f"Target: {host}  base_port: {base}")
    print(f"Root: {'yes' if IS_ROOT else 'no (raw tests will be skipped)'}")
    print(f"Probe server expected on ports {base}..{base + 19}")
    print("=" * 72)
    print()

    # ── L3: ICMP ──────────────────────────────────────────────────────
    print("[L3 — ICMP]")
    run_test("L3-ICMP", "ICMP echo (ping)", lambda: test_icmp_ping(host))
    if IS_ROOT:
        run_test("L3-ICMP", "Raw ICMP echo", lambda: test_raw_icmp_echo(host))
        run_test("L3-ICMP", "ICMP timestamp (type 13)", lambda: test_icmp_timestamp(host))
        run_test("L3-ICMP", "Fragmented ICMP", lambda: test_fragment(host))
    else:
        for n in ["Raw ICMP echo", "ICMP timestamp (type 13)", "Fragmented ICMP"]:
            R.add("L3-ICMP", n, False, 0, "skipped — needs root")
    print()

    # ── L4: TCP ───────────────────────────────────────────────────────
    print("[L4 — TCP]")
    run_test("L4-TCP", f"TCP connect :{base}", lambda: test_tcp_connect(host, base))
    run_test("L4-TCP", f"TCP data (PSH) :{base}", lambda: test_tcp_data(host, base))
    run_test("L4-TCP", f"TCP large payload (8KB) :{base}", lambda: test_tcp_large_payload(host, base))
    print()

    # ── L4: UDP ───────────────────────────────────────────────────────
    print("[L4 — UDP]")
    run_test("L4-UDP", f"UDP echo :{base}", lambda: test_udp(host, base))
    run_test("L4-UDP", f"UDP large (1400B) :{base}", lambda: test_udp_large(host, base))
    print()

    # ── L4: Raw TCP flags ─────────────────────────────────────────────
    print("[L4 — Raw TCP flags]")
    if IS_ROOT:
        run_test("L4-RAW-TCP", f"SYN :{base}", lambda: test_raw_syn(host, base))
        run_test("L4-RAW-TCP", f"ACK :{base}", lambda: test_raw_ack(host, base))
        run_test("L4-RAW-TCP", f"FIN :{base}", lambda: test_raw_fin(host, base))
        run_test("L4-RAW-TCP", f"SYN+ACK :{base}", lambda: test_raw_syn_ack(host, base))
        run_test("L4-RAW-TCP", f"PSH+ACK :{base}", lambda: test_raw_psh_ack(host, base))
        run_test("L4-RAW-TCP", f"RST :{base}", lambda: test_raw_rst(host, base))
        run_test("L4-RAW-TCP", f"XMAS (FIN+PSH+URG) :{base}", lambda: test_raw_xmas(host, base))
        run_test("L4-RAW-TCP", f"NULL (no flags) :{base}", lambda: test_raw_null(host, base))
    else:
        for n in ["SYN", "ACK", "FIN", "SYN+ACK", "PSH+ACK", "RST", "XMAS", "NULL"]:
            R.add("L4-RAW-TCP", f"{n} :{base}", False, 0, "skipped — needs root")
    print()

    # ── IP protocols ──────────────────────────────────────────────────
    print("[IP protocols]")
    if IS_ROOT:
        run_test("IP-PROTO", "GRE (proto 47)", lambda: test_gre(host))
        run_test("IP-PROTO", "IP-in-IP (proto 4)", lambda: test_ipip(host))
        run_test("IP-PROTO", "ESP (proto 50)", lambda: test_esp(host))
    else:
        for n in ["GRE (proto 47)", "IP-in-IP (proto 4)", "ESP (proto 50)"]:
            R.add("IP-PROTO", n, False, 0, "skipped — needs root")
    print()

    # ── L7: DNS ───────────────────────────────────────────────────────
    print("[L7 — DNS]")
    run_test("L7-DNS", f"DNS over UDP (mock server :{base + 3})", lambda: test_dns_udp(host, base + 3))
    run_test("L7-DNS", f"DNS over TCP (mock server :{base + 3})", lambda: test_dns_tcp(host, base + 3))
    run_test("L7-DNS", "DNS to 8.8.8.8:53 (public)", lambda: test_dns_public("8.8.8.8"))
    run_test("L7-DNS", "DNS to 1.1.1.1:53 (public)", lambda: test_dns_public("1.1.1.1"))
    print()

    # ── L7: HTTP ──────────────────────────────────────────────────────
    print("[L7 — HTTP]")
    run_test("L7-HTTP", f"HTTP GET :{base + 1}", lambda: test_http(host, base + 1))
    print()

    # ── L7: TLS ───────────────────────────────────────────────────────
    print("[L7 — TLS]")
    run_test("L7-TLS", f"TLS handshake :{base + 2}", lambda: test_tls(host, base + 2))
    run_test("L7-TLS", f"TLS w/ fake SNI (google.com) :{base + 2}", lambda: test_tls_with_sni(host, base + 2, "www.google.com"))
    run_test("L7-TLS", f"TLS w/ fake SNI (microsoft.com) :{base + 2}", lambda: test_tls_with_sni(host, base + 2, "www.microsoft.com"))
    print()

    # ── Port range ────────────────────────────────────────────────────
    print("[Port range scan]")
    tcp_open, udp_open = test_port_range(host, base)
    total_range = list(range(base + 10, base + 20))
    R.add("PORT-SCAN", f"TCP ports {base + 10}-{base + 19}",
           len(tcp_open) > 0, 0,
           f"{len(tcp_open)}/10 open: {tcp_open}" if tcp_open else "all filtered")
    R.add("PORT-SCAN", f"UDP ports {base + 10}-{base + 19}",
           len(udp_open) > 0, 0,
           f"{len(udp_open)}/10 open: {udp_open}" if udp_open else "all filtered")
    print()

    # ── Well-known ports ──────────────────────────────────────────────
    print("[Well-known ports — TCP connect]")
    wk = test_wellknown_tcp(host)
    for p, ok in wk.items():
        R.add("WELL-KNOWN", f"TCP :{p}", ok, 0, "open" if ok else "filtered/closed")
    print()

    # ── Traceroute ────────────────────────────────────────────────────
    if IS_ROOT:
        print("[Traceroute]")
        tr_result = test_traceroute(host)
        print(f"  Traceroute: {tr_result}")
        print()

    # ── Summary ───────────────────────────────────────────────────────
    R.summary()

    # Save JSON report
    report = "probe_results.json"
    with open(report, "w") as f:
        json.dump(R._rows, f, indent=2)
    print(f"Full results saved to {report}")


if __name__ == "__main__":
    main()
