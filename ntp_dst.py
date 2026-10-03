#!/usr/bin/python3
"""
DST-spoofing NTP server.

Some clocks (an old Chinese clock movement at the venue, in our case)
have no DST setting and rely on whatever an NTP server says. This server
proxies a real upstream NTP source and adds a configurable seasonal
offset on top — used at our site to push a fixed-timezone clock forward
one hour during Australian DST.

Network setup: an iptables NAT rule on the gateway redirects the clock's
outgoing NTP traffic (UDP/123) to this host on UDP/124 (default below)
so the system's regular NTP daemon on UDP/123 remains untouched.
"""
import os
import socket
import struct
import threading
import time

# ── Config (env-overridable) ──────────────────────────────────────────────────
LISTEN_PORT = int(os.environ.get("NTP_DST_PORT", "124"))
UPSTREAM_HOST = os.environ.get("NTP_DST_UPSTREAM", "au.pool.ntp.org")
UPSTREAM_PORT = int(os.environ.get("NTP_DST_UPSTREAM_PORT", "123"))
DST_OFFSET_SECONDS = int(os.environ.get("NTP_DST_OFFSET", "3600"))
REFRESH_INTERVAL = int(os.environ.get("NTP_DST_REFRESH", "60"))

NTP_EPOCH_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01

# ── State ─────────────────────────────────────────────────────────────────────
# Cache the offset between upstream wall-clock and the local system clock so
# we can answer clients without hitting upstream on every request. Refreshed
# periodically in a background thread.
_offset_lock = threading.Lock()
_upstream_offset = 0.0       # seconds: upstream_unix - local_unix
_last_upstream_ok = 0.0       # local unix time of last successful sync
_upstream_ip = "0.0.0.0"      # last upstream IP we synced to (for ref ID)


def query_upstream():
    """Send one NTP request upstream. Returns (upstream_unix_time, server_ip)
    on success, (None, None) on failure."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    request = b"\x1b" + 47 * b"\0"  # NTPv3 client request, mode=3
    try:
        info = socket.getaddrinfo(UPSTREAM_HOST, UPSTREAM_PORT,
                                  socket.AF_INET, socket.SOCK_DGRAM)
        server_ip = info[0][4][0]
        s.sendto(request, (server_ip, UPSTREAM_PORT))
        data, _ = s.recvfrom(1024)
        if len(data) < 48:
            return None, None
        li = data[0] >> 6
        mode = data[0] & 0x7
        stratum = data[1]
        if mode != 4 or li == 3 or not 1 <= stratum <= 15:
            print(f"[upstream] {server_ip} rejected reply: "
                  f"mode={mode} li={li} stratum={stratum}", flush=True)
            return None, None
        # Transmit Timestamp at bytes 40-47: 64-bit fixed-point seconds-since-1900
        tx_sec, tx_frac = struct.unpack("!II", data[40:48])
        if tx_sec == 0:
            print(f"[upstream] {server_ip} rejected reply: zero timestamp", flush=True)
            return None, None
        unix_time = (tx_sec - NTP_EPOCH_OFFSET) + (tx_frac / (1 << 32))
        return unix_time, server_ip
    except Exception as e:
        print(f"[upstream] {UPSTREAM_HOST} query failed: {e}", flush=True)
        return None, None
    finally:
        s.close()


def refresh_offset_loop():
    """Background thread: resync from upstream every REFRESH_INTERVAL."""
    global _upstream_offset, _last_upstream_ok, _upstream_ip
    while True:
        try:
            upstream_unix, server_ip = query_upstream()
            if upstream_unix is not None:
                now = time.time()
                with _offset_lock:
                    _upstream_offset = upstream_unix - now
                    _last_upstream_ok = now
                    _upstream_ip = server_ip
                print(f"[upstream] synced to {server_ip}: offset={_upstream_offset:+.3f}s", flush=True)
        except Exception as e:
            print(f"[upstream] refresh error: {e}", flush=True)
        time.sleep(REFRESH_INTERVAL)


def dst_active():
    """True if the local timezone is currently in DST per the OS rules."""
    return time.localtime().tm_isdst > 0


def current_spoofed_unix(dst=None):
    """Wall-clock time we want clients to see, as Unix seconds (float)."""
    if dst is None:
        dst = dst_active()
    with _offset_lock:
        offset = _upstream_offset
    base = time.time() + offset
    return base + (DST_OFFSET_SECONDS if dst else 0)


def unix_to_ntp(unix_time):
    """Returns a (seconds, fractional-as-uint32) tuple suitable for an NTP
    64-bit fixed-point timestamp field."""
    seconds = int(unix_time) + NTP_EPOCH_OFFSET
    frac = int((unix_time - int(unix_time)) * (1 << 32)) & 0xFFFFFFFF
    return seconds & 0xFFFFFFFF, frac


def build_response(client_data, dst=None):
    """Construct a 48-byte stratum-2 NTP response that mirrors the client's
    version and embeds the spoofed timestamps."""
    if len(client_data) < 48:
        return None
    if dst is None:
        dst = dst_active()
    client_byte0 = client_data[0]
    client_vn = (client_byte0 >> 3) & 0x7
    if not 1 <= client_vn <= 4:
        client_vn = 4
    # Originate Timestamp echoes the client's transmit timestamp verbatim
    client_tx_sec, client_tx_frac = struct.unpack("!II", client_data[40:48])

    # Receive Timestamp = now (locally, the moment we got the packet — we
    # approximate as 'now' which is good enough for a clock-spoofing rig)
    recv_unix = current_spoofed_unix(dst)
    recv_sec, recv_frac = unix_to_ntp(recv_unix)

    # LI=0, VN=client's, Mode=4 (server)
    li_vn_mode = (0 << 6) | (client_vn << 3) | 4

    # Reference ID: in stratum 2+, IPv4 address of upstream as 4 bytes
    with _offset_lock:
        last_ok = _last_upstream_ok
        offset = _upstream_offset
        up_ip = _upstream_ip
    try:
        ref_id_packed = struct.unpack("!I", socket.inet_aton(up_ip))[0]
    except OSError:
        ref_id_packed = 0

    # Reference Timestamp: the moment we last synced upstream
    if last_ok:
        ref_unix = (last_ok + offset
                    + (DST_OFFSET_SECONDS if dst else 0))
    else:
        ref_unix = recv_unix
    ref_sec, ref_frac = unix_to_ntp(ref_unix)

    # Transmit Timestamp: just before sending
    tx_unix = current_spoofed_unix(dst)
    tx_sec, tx_frac = unix_to_ntp(tx_unix)

    # Stratum 2; Poll log2 (6 = 64s, conventional);
    # Precision: 2^-10 s ≈ 1 ms — a realistic claim for a Pi.
    # Root delay & dispersion: small non-zero values in NTP short format
    # (32-bit fixed-point seconds). 0x00010000 = 1.0s, plausible.
    return struct.pack(
        "!B B b b 11I",
        li_vn_mode,
        2,                # stratum
        6,                # poll interval (log2 seconds)
        -10,              # precision (log2 seconds)
        0x00010000,       # root delay (NTP short fixed-point ~ 1.0 s)
        0x00010000,       # root dispersion
        ref_id_packed,
        ref_sec, ref_frac,
        client_tx_sec, client_tx_frac,
        recv_sec, recv_frac,
        tx_sec, tx_frac,
    )


def handle_request(server_socket, client_data, client_addr):
    try:
        dst = dst_active()
        response = build_response(client_data, dst)
        if response is None:
            print(f"[server] short/malformed request from {client_addr} "
                  f"({len(client_data)} bytes)", flush=True)
            return
        server_socket.sendto(response, client_addr)
        # Log the exact timestamp placed in the reply (read back from the packet)
        tx_sec, tx_frac = struct.unpack("!II", response[40:48])
        sent_unix = tx_sec - NTP_EPOCH_OFFSET
        client_vn = (client_data[0] >> 3) & 0x7
        fmt = "%Y-%m-%d %H:%M:%S"
        print(f"[sync] SENT to {client_addr[0]}:{client_addr[1]} "
              f"ntpv{client_vn}: real_local={time.strftime(fmt)} "
              f"sent_utc={time.strftime(fmt, time.gmtime(sent_unix))} "
              f"dst={'on' if dst else 'off'} "
              f"offset_applied=+{DST_OFFSET_SECONDS if dst else 0}s", flush=True)
    except Exception as e:
        print(f"[server] response error for {client_addr}: {e}", flush=True)


def run_server():
    global _upstream_offset, _last_upstream_ok, _upstream_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", LISTEN_PORT))
    print(f"[server] listening on UDP/{LISTEN_PORT}, "
          f"upstream={UPSTREAM_HOST}:{UPSTREAM_PORT}, "
          f"dst_offset={DST_OFFSET_SECONDS}s, "
          f"dst_now={dst_active()}", flush=True)

    # Sync once immediately so the first request gets a good answer
    upstream_unix, server_ip = query_upstream()
    if upstream_unix is not None:
        with _offset_lock:
            _upstream_offset = upstream_unix - time.time()
            _last_upstream_ok = time.time()
            _upstream_ip = server_ip
        print(f"[server] initial sync to {server_ip}: offset={_upstream_offset:+.3f}s", flush=True)

    threading.Thread(target=refresh_offset_loop, daemon=True, name="refresh").start()

    while True:
        try:
            data, addr = s.recvfrom(1024)
        except Exception as e:
            print(f"[server] recv error: {e}", flush=True)
            time.sleep(1)
            continue
        threading.Thread(target=handle_request, args=(s, data, addr),
                         daemon=True).start()


if __name__ == "__main__":
    run_server()
