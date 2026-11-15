import base64
import csv
import json
import concurrent.futures
import os
import socket
import struct
import sys
import time
from datetime import datetime, timedelta, timezone

API_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]
DDNS_SUFFIX = ".opengw.net"
# Two files, because two kinds of app read this repository:
#  - servers.json    : short list for the old app versions (they rebuild the whole screen after every ping)
#  - servers_v2.json : the full list for the versions with the country screen
LEGACY_FILE = "servers.json"
OUTPUT_FILE = "servers_v2.json"
LEGACY_SIZE = 60

# The L2TP/IPsec list: only servers that answer an IKE message (UDP 500). VPN Gate's list does not say which
# servers offer L2TP, and many volunteer servers do not. The app pings again from the phone.
L2TP_FILE = "servers_l2tp.json"
IKE_PORT = 500
IKE_TIMEOUT = 2.5   # seconds to wait for each try
IKE_TRIES = 2
IKE_THREADS = 32

# The numbers VPN Gate publishes (speed, ping, sessions) are measured from Japan, so this script
# does not try to find the "best" server. It keeps every server that can work at all; the app groups
# them by country, measures the real ping from the phone, and shows a quality label.
POOL_SIZE = 400           # upper bound for the number of servers written to servers.json
MIN_SPEED_MBPS = 1        # almost nothing is dropped: the app pings every server before it is shown as working
MIN_UPTIME_HOURS = 0
DEFAULT_PORT = 443        # used when the OpenVPN config shows no TCP port (SoftEther servers listen on 443)
EXCLUDED_COUNTRIES = {"RU"}  # blocks too many sites (Instagram, ...): never listed
CARRY_HOURS = 24          # a server that left VPN Gate's list stays this long; the app's ping drops dead ones
SPEED_CAP_MBPS = 300      # only used to order the file: a measurement above this tells nothing more
LOAD_SESSIONS = 60        # only used to order the file: every LOAD_SESSIONS sessions halve the rank


def fetch_csv_text():
    import requests

    last_error = None
    for url in API_URLS:
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            return response.text
        except Exception as e:  # noqa: BLE001
            last_error = e
            print(f"Fetch failed for {url}: {e}")
    raise RuntimeError(f"Could not fetch VPN Gate list: {last_error}")


def ports_from_config(config_b64):
    """Read the OpenVPN config embedded in the CSV and return (tcp_port, udp_port); None when missing.

    On VPN Gate the TCP port advertised for a server is also the port to use for MS-SSTP and for the
    SoftEther protocol (443 means no ':port' suffix on the website).
    """
    try:
        text = base64.b64decode(config_b64).decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None, None

    proto = None
    entries = []  # (protocol or None, port)
    for raw in text.splitlines():
        parts = raw.strip().split()
        if not parts or parts[0].startswith(("#", ";")):
            continue
        key = parts[0].lower()
        if key == "proto" and len(parts) > 1:
            proto = parts[1].lower()
        elif key == "remote" and len(parts) >= 3 and parts[2].isdigit():
            remote_proto = parts[3].lower() if len(parts) >= 4 else None
            entries.append((remote_proto, int(parts[2])))

    tcp_port = None
    udp_port = None
    for remote_proto, port in entries:
        effective = remote_proto or proto
        if not effective:
            continue
        if effective.startswith("tcp") and tcp_port is None:
            tcp_port = port
        elif effective.startswith("udp") and udp_port is None:
            udp_port = port

    return tcp_port, udp_port


def to_int(value, default):
    return int(value) if value.isdigit() else default


def to_float(value):
    try:
        return float(value) if value else 0.0
    except ValueError:
        return 0.0


def quality(server):
    """Rough health of a server. The speed counts only up to a cap and a loaded server loses points."""
    capped = min(server["speed_mbps"], SPEED_CAP_MBPS)
    load = 1 + server["sessions"] / LOAD_SESSIONS
    return capped / load


def select_pool(servers):
    """Every usable server, best-looking first, without duplicates, up to POOL_SIZE."""
    seen = set()
    pool = []

    for server in sorted(servers, key=quality, reverse=True):
        if server["host"] in seen:
            continue
        seen.add(server["host"])
        pool.append(server)

        if len(pool) >= POOL_SIZE:
            break

    return pool


def parse_servers(csv_text):
    lines = csv_text.replace("\r", "").split("\n")
    rows_total = 0
    no_tcp_port = 0
    excluded = 0
    too_slow = 0
    too_young = 0
    servers = []

    reader = csv.reader(lines[2:])
    for row in reader:
        if len(row) < 15:
            continue
        host_name = row[0].strip()
        if not host_name or host_name.startswith(("#", "*")):
            continue
        rows_total += 1

        country_code = row[6].strip()
        if country_code in EXCLUDED_COUNTRIES:
            excluded += 1
            continue

        port, udp_port = ports_from_config(row[14])
        port_guessed = port is None
        if port_guessed:
            no_tcp_port += 1
            port = DEFAULT_PORT  # a guess: the app's ping test shows whether it answers

        speed_mbps = round(to_float(row[4]) / 1_000_000, 2)
        if speed_mbps < MIN_SPEED_MBPS:
            too_slow += 1
            continue

        uptime_hours = round(to_float(row[8]) / 3_600_000, 1)
        if uptime_hours < MIN_UPTIME_HOURS:
            too_young += 1
            continue

        servers.append({
            "host_name": host_name,
            "host": host_name + DDNS_SUFFIX,
            "ip": row[1].strip(),
            "port": port,
            "port_guessed": port_guessed,
            "udp_port": udp_port or 0,
            "country": country_code,
            "country_name": row[5].strip(),
            "speed_mbps": speed_mbps,   # measured from Japan: informational only
            "ping": to_int(row[3], 999),  # measured from Japan: informational only
            "sessions": to_int(row[7], 999),
            "score": to_int(row[2], 0),
            "uptime_hours": uptime_hours,
            "operator": row[12].strip() if len(row) > 12 else "",
        })

    pool = select_pool(servers)

    per_country = {}
    for s in pool:
        per_country[s["country"]] = per_country.get(s["country"], 0) + 1

    print(
        f"Rows parsed: {rows_total}; excluded country: {excluded}; no TCP port in config (port {DEFAULT_PORT} "
        f"assumed): {no_tcp_port}; dropped: {too_slow} slower than {MIN_SPEED_MBPS} Mbps, "
        f"{too_young} younger than {MIN_UPTIME_HOURS} h; "
        f"pool: {len(pool)} servers from {len(per_country)} countries"
    )
    print("Per country: " + ", ".join(f"{c} {n}" for c, n in sorted(per_country.items(), key=lambda x: -x[1])))
    return pool


def legacy_list(servers):
    """The old apps get a short list of the better-looking servers."""
    better = [s for s in servers if s["speed_mbps"] >= 50 and s["uptime_hours"] >= 3]
    return (better or servers)[:LEGACY_SIZE]


def load_previous(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:  # noqa: BLE001
        return []


def merge_with_previous(fresh, previous, now, label=None):
    """VPN Gate's list changes all the time. Servers that just left it are kept for CARRY_HOURS:
    the app pings every server, so the dead ones simply show as not answering.
    Their session count is old, so it is set to 0 and the app shows their quality as unknown."""
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    merged = {}

    for s in fresh:
        entry = dict(s)
        entry["last_seen"] = stamp
        entry["carried"] = False
        merged[entry["host"]] = entry

    carried = 0
    for old in previous:
        host = old.get("host")
        if not host or host in merged or old.get("country") in EXCLUDED_COUNTRIES:
            continue

        try:
            seen = datetime.strptime(old["last_seen"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001
            seen = now  # first run with this feature: it was listed one refresh ago

        if now - seen > timedelta(hours=CARRY_HOURS):
            continue

        entry = dict(old)
        entry["last_seen"] = seen.strftime("%Y-%m-%dT%H:%M:%SZ")
        entry["carried"] = True
        entry["sessions"] = 0
        merged[host] = entry
        carried += 1

    result = sorted(merged.values(), key=quality, reverse=True)[:POOL_SIZE]
    print(f"Carried over from earlier refreshes: {carried}; total in {label or OUTPUT_FILE}: {len(result)}")
    return result


def stage_in_git(path):
    """The workflow only adds servers.json by itself: stage the new file so the same commit carries it."""
    import subprocess

    try:
        subprocess.run(["git", "add", path], check=True, capture_output=True)
        print(f"Staged {path} for the commit")
    except Exception as e:  # noqa: BLE001
        print(f"Could not stage {path} (fine when not run by the workflow): {e}")


def write_json(path, servers):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(servers, f, ensure_ascii=False, indent=2)
    print(f"Saved {len(servers)} servers to {path}")


# ---- L2TP/IPsec list ------------------------------------------------------------------------

def _attribute(kind, value):
    return struct.pack(">HH", 0x8000 | kind, value)


def _transform(number, encryption, key_length, hash_id, group, last):
    attributes = (
        _attribute(1, encryption)
        + (_attribute(14, key_length) if key_length else b"")
        + _attribute(2, hash_id)
        + _attribute(4, group)
        + _attribute(3, 1)        # pre-shared key
        + _attribute(11, 1)       # life type: seconds
        + _attribute(12, 28800)   # life duration
    )
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attributes), number, 1, 0) + attributes


def build_ike_message(cookie):
    """IKEv1 Main Mode, first message: the SA proposals the app's tunnel uses. No key is exchanged."""
    transforms = (
        _transform(1, 7, 256, 2, 2, False)     # AES-256, SHA1, MODP-1024
        + _transform(2, 5, None, 2, 2, False)  # 3DES, SHA1, MODP-1024
        + _transform(3, 7, 256, 4, 14, True)   # AES-256, SHA-256, MODP-2048
    )
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3) + transforms
    sa = struct.pack(">BBHII", 0, 0, 4 + 8 + len(proposal), 1, 1) + proposal
    header = cookie + bytes(8) + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa))
    return header + sa


def ike_probe(ip, port=None):
    """Milliseconds until the server answers with an ISAKMP message, or None."""
    port = port or IKE_PORT
    cookie = os.urandom(8)
    message = build_ike_message(cookie)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect((ip, port))

        for _ in range(IKE_TRIES):
            started = time.monotonic()
            sock.send(message)

            while True:
                remaining = started + IKE_TIMEOUT - time.monotonic()
                if remaining <= 0:
                    break

                sock.settimeout(remaining)
                try:
                    data = sock.recv(2048)
                except socket.timeout:
                    break
                except OSError:
                    return None  # for example "port unreachable": nothing listens there

                if len(data) >= 28 and data[:8] == cookie:
                    return max(1, int((time.monotonic() - started) * 1000))
    except OSError:
        return None
    finally:
        sock.close()

    return None


def build_l2tp_list(fresh, previous, now):
    """Every candidate (this refresh's servers and the earlier L2TP list) is probed; the ones that answer stay."""
    candidates = merge_with_previous(fresh, previous, now, label=L2TP_FILE + " candidates")

    # Only servers whose TCP port is 443 ever answered L2TP: the others are not even probed.
    before = len(candidates)
    candidates = [s for s in candidates if s["port"] == 443]
    print(f"L2TP: {len(candidates)} of {before} candidates have TCP port 443")

    answers = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=IKE_THREADS) as pool:
        futures = {pool.submit(ike_probe, s["ip"]): s for s in candidates}
        for future in concurrent.futures.as_completed(futures):
            ms = future.result()
            if ms is not None:
                answers[futures[future]["host"]] = ms

    result = []
    for s in candidates:
        if s["host"] in answers:
            entry = dict(s)
            entry["ike_ms"] = answers[s["host"]]
            result.append(entry)

    per_country = {}
    for s in result:
        per_country[s["country"]] = per_country.get(s["country"], 0) + 1

    print(f"L2TP: probed {len(candidates)} servers, {len(result)} answered IKE")
    print("L2TP per country: " + ", ".join(f"{c} {n}" for c, n in sorted(per_country.items(), key=lambda x: -x[1])))
    return result


def main():
    fresh = parse_servers(fetch_csv_text())
    if not fresh:
        print("No usable servers found; keeping the old files")
        sys.exit(1)

    for s in fresh[:5]:
        print(f"  {s['host']}:{s['port']}  {s['country']}  {s['speed_mbps']} Mbps  sessions {s['sessions']}")

    full = merge_with_previous(fresh, load_previous(OUTPUT_FILE), datetime.now(timezone.utc))

    write_json(OUTPUT_FILE, full)
    write_json(LEGACY_FILE, legacy_list(fresh))
    stage_in_git(OUTPUT_FILE)

    now = datetime.now(timezone.utc)
    l2tp = build_l2tp_list(fresh, load_previous(L2TP_FILE), now)
    if l2tp:
        write_json(L2TP_FILE, l2tp)
        stage_in_git(L2TP_FILE)
    else:
        # Probably this machine cannot send UDP: do not wipe the list that is there.
        print(f"No server answered IKE: keeping the old {L2TP_FILE}")


if __name__ == "__main__":
    main()
