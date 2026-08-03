#!/usr/bin/env python3
"""
Active eD2k Server Directory & Harvester
=========================================
An automated Python scanner that probes eDonkey/eMule servers via UDP/TCP,
extracts extended server statistics (Max Users, Limits, LowID, Ping), updates
its seed list from remote peers & server.met URLs, and generates a modern web portal.

Author: Telemacore & Antigravity AI
License: MIT
"""

import os
import sys
import time
import json
import zlib
import socket
import struct
import random
import datetime
import urllib.request
import urllib.parse
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Any, Set

# ==============================================================================
# CONFIGURATION
# ==============================================================================
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")
JSON_FILE = os.path.join(OUTPUT_DIR, "servers.json")
TXT_FILE = os.path.join(OUTPUT_DIR, "servers.txt")

# Reconfigure stdout for UTF-8 compatibility on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Community server.met and list URLs to pull new servers from
REMOTE_MET_URLS = [
    "http://upd.emule-security.org/server.met",
    "http://edk.peerates.net/servers.met",
    "http://www.peerates.net/servers.met",
]

# UDP & TCP Connection Settings
UDP_TIMEOUT = 2.5
TCP_TIMEOUT = 5.0
MAX_THREADS = 25

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def ensure_dir(directory: str) -> None:
    """Ensure that a directory exists."""
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

def ip_to_int(ip: str) -> int:
    """Convert IPv4 string to 32-bit unsigned integer (little-endian for eD2k)."""
    packed = socket.inet_aton(ip)
    return struct.unpack("<I", packed)[0]

def int_to_ip(ip_int: int) -> str:
    """Convert 32-bit integer back to IPv4 string."""
    return socket.inet_ntoa(struct.pack("<I", ip_int))

def format_number(val: Optional[int]) -> str:
    """Format integers with commas/spaces for display."""
    if val is None:
        return "Unknown"
    return f"{val:,}".replace(",", " ")

# ==============================================================================
# ED2K PROTOCOL TAG PARSER
# ==============================================================================
def parse_ed2k_tags(payload: bytes, offset: int, num_tags: int) -> Dict[Any, Any]:
    """
    Parses eD2k protocol tags from binary packet payload with maximum robustness.
    Supports standard, eMule compressed, string-named, and integer-named tags.
    """
    tags = {}
    for _ in range(num_tags):
        if offset >= len(payload):
            break

        tag_type_full = payload[offset]
        tag_type = tag_type_full & 0x7F
        is_int_name = (tag_type_full & 0x80) != 0
        offset += 1

        name = None
        if is_int_name:
            if offset >= len(payload):
                break
            name = payload[offset]
            offset += 1
        else:
            if offset + 2 > len(payload):
                break
            name_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if offset + name_len > len(payload):
                break
            if name_len == 1:
                name = payload[offset]
            else:
                raw_name = payload[offset : offset + name_len]
                try:
                    name = raw_name.decode("utf-8", errors="ignore").lower()
                except Exception:
                    name = raw_name.decode("latin1", errors="ignore").lower()
            offset += name_len

        val = None
        if tag_type == 0x01:  # Hash (16 bytes)
            if offset + 16 > len(payload):
                break
            val = payload[offset : offset + 16]
            offset += 16
        elif tag_type == 0x02:  # String
            if offset + 2 > len(payload):
                break
            val_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if offset + val_len > len(payload):
                break
            raw_val = payload[offset : offset + val_len]
            try:
                val = raw_val.decode("utf-8", errors="ignore")
            except Exception:
                val = raw_val.decode("latin1", errors="ignore")
            offset += val_len
        elif tag_type == 0x03:  # Uint32
            if offset + 4 > len(payload):
                break
            val = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
        elif tag_type == 0x04:  # Float32
            if offset + 4 > len(payload):
                break
            val = struct.unpack_from("<f", payload, offset)[0]
            offset += 4
        elif tag_type == 0x07:  # Blob
            if offset + 4 > len(payload):
                break
            val_len = struct.unpack_from("<I", payload, offset)[0]
            offset += 4 + val_len
        elif tag_type == 0x08:  # Uint16
            if offset + 2 > len(payload):
                break
            val = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
        elif tag_type == 0x09:  # Uint8
            if offset + 1 > len(payload):
                break
            val = payload[offset]
            offset += 1
        elif tag_type == 0x0B:  # Uint64
            if offset + 8 > len(payload):
                break
            val = struct.unpack_from("<Q", payload, offset)[0]
            offset += 8
        elif 0x11 <= tag_type <= 0x26:  # eMule Optimized String (STR1..STR22)
            val_len = tag_type - 0x11 + 1
            if offset + val_len > len(payload):
                break
            raw_val = payload[offset : offset + val_len]
            try:
                val = raw_val.decode("utf-8", errors="ignore")
            except Exception:
                val = raw_val.decode("latin1", errors="ignore")
            offset += val_len
        else:
            break

        if name is not None and val is not None:
            tags[name] = val

    return tags

# ==============================================================================
# UDP SERVER HARVESTER & STATS PROBER
# ==============================================================================
def probe_server_udp(ip: str, tcp_port: int, timeout: float = UDP_TIMEOUT) -> Optional[Dict[str, Any]]:
    """
    Probes an eD2k server via UDP to gather live metrics (users, files, max users, limits, ping).
    UDP port is standard TCP_PORT + 4.
    """
    udp_port = tcp_port + 4
    info = {
        "ip": ip,
        "port": tcp_port,
        "udp_port": udp_port,
        "active": False,
        "name": "Unknown Server",
        "description": "No description available",
        "version": "Unknown",
        "users": 0,
        "files": 0,
        "max_users": None,
        "lowid_users": None,
        "soft_files": None,
        "hard_files": None,
        "ping_ms": None,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    start_time = time.time()
    # 1. OP_GLOBSERVSTATREQ (0x96) using eMule Magic Challenge
    challenge_stat = 0x55AA0000 | random.randint(0, 0xFFFF)
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0x96, challenge_stat), (ip, udp_port))
        data, _ = sock.recvfrom(1024)
        rtt = int((time.time() - start_time) * 1000)
        
        if len(data) >= 14 and data[0] == 0xE3 and data[1] == 0x97:
            resp_challenge, users, files = struct.unpack_from("<III", data, 2)
            if resp_challenge == challenge_stat:
                info["users"] = users
                info["files"] = files
                info["ping_ms"] = rtt
                info["active"] = True

                # Parse optional hidden stat fields appended at end of packet
                offset = 14
                if len(data) >= offset + 4:
                    info["max_users"] = struct.unpack_from("<I", data, offset)[0]
                    offset += 4
                if len(data) >= offset + 4:
                    info["soft_files"] = struct.unpack_from("<I", data, offset)[0]
                    offset += 4
                if len(data) >= offset + 4:
                    info["hard_files"] = struct.unpack_from("<I", data, offset)[0]
                    offset += 4
                if len(data) >= offset + 4:  # udp_flags (skipped)
                    offset += 4
                if len(data) >= offset + 4:
                    info["lowid_users"] = struct.unpack_from("<I", data, offset)[0]
    except Exception:
        pass

    # 2. OP_SERVER_DESC_REQ (0xA2) to get Name, Description & Version
    challenge_desc = (random.randint(0, 65535) << 16) | 0xF0FF
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0xA2, challenge_desc), (ip, udp_port))
        data, _ = sock.recvfrom(4096)
        if len(data) >= 10 and data[0] == 0xE3 and data[1] == 0xA3:
            resp_challenge = struct.unpack_from("<I", data, 2)[0]
            if resp_challenge == challenge_desc:
                tag_count = struct.unpack_from("<I", data, 6)[0]
                tags = parse_ed2k_tags(data, 10, tag_count)

                if 0x01 in tags:
                    info["name"] = str(tags[0x01]).strip()
                if 0x0B in tags:
                    info["description"] = str(tags[0x0B]).strip()
                if 0x91 in tags:
                    v = tags[0x91]
                    info["version"] = f"{v >> 16}.{v & 0xFFFF}" if isinstance(v, int) else str(v)
                info["active"] = True
    except Exception:
        pass
    finally:
        sock.close()

    # Consider active if it responded with users > 0 or a valid name
    if info["active"] and (info["users"] > 0 or info["name"] != "Unknown Server"):
        return info
    return None

# ==============================================================================
# TCP REMOTE SERVER LIST HARVESTER
# ==============================================================================
def get_remote_server_list_tcp(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> List[Tuple[str, int]]:
    """
    Connects to an active eD2k server via TCP, performs handshake,
    and requests its peer server list (OP_SERVERLIST opcode 0x14 -> 0x32).
    """
    discovered_servers = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    client_port = random.randint(10000, 60000)
    try:
        sock.connect((ip, port))
        
        # Build handshake tags
        username = b"http://www.emule-project.net"
        tag_user = struct.pack("<BHB", 0x02, 1, 0x01) + struct.pack("<H", len(username)) + username
        tags_data = (
            tag_user
            + struct.pack("<BHBI", 0x03, 1, 0x11, 0x3C)        # Version
            + struct.pack("<BHBI", 0x03, 1, 0x0F, client_port)  # Client Port
            + struct.pack("<BHBI", 0x03, 1, 0xFB, 0x003C0000)  # eMule Version
            + struct.pack("<BHBI", 0x03, 1, 0x20, 0x0119)      # C++ Flags
        )
        payload = struct.pack("<16sIHI", os.urandom(16), 0, client_port, 5) + tags_data
        sock.send(struct.pack("<BI", 0xE3, len(payload) + 1) + struct.pack("<B", 0x01) + payload)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                header = sock.recv(5)
            except socket.timeout:
                break
            if not header or len(header) < 5:
                break

            protocol, packet_len = struct.unpack("<BI", header)
            if packet_len == 0 or packet_len > 1024 * 1024:
                continue

            data = b""
            while len(data) < packet_len:
                chunk = sock.recv(min(packet_len - len(data), 4096))
                if not chunk:
                    break
                data += chunk

            if protocol == 0xD4:  # Compressed packet
                try:
                    data = zlib.decompress(data)
                except Exception:
                    continue

            if not data:
                continue
            opcode, payload_data = data[0], data[1:]

            if opcode == 0x40:  # OP_IDCHANGE -> Handshake Success!
                client_id = struct.unpack_from("<I", payload_data, 0)[0]
                if client_id != 0:
                    # Request Server List (OP_GETSERVERLIST 0x14)
                    sock.send(struct.pack("<BI", 0xE3, 1) + struct.pack("<B", 0x14))
            elif opcode == 0x32:  # OP_SERVERLIST Response
                if len(payload_data) >= 1:
                    count = payload_data[0]
                    offset = 1
                    for _ in range(count):
                        if offset + 6 > len(payload_data):
                            break
                        ip_bytes = payload_data[offset : offset + 4]
                        srv_port = struct.unpack_from("<H", payload_data, offset + 4)[0]
                        srv_ip = socket.inet_ntoa(ip_bytes)
                        discovered_servers.append((srv_ip, srv_port))
                        offset += 6
                break
            elif opcode == 0x05:  # OP_REJECT
                break
    except Exception:
        pass
    finally:
        sock.close()

    return discovered_servers

# ==============================================================================
# REMOTE SERVER.MET FETCHING & PARSING
# ==============================================================================
def parse_server_met_bytes(met_data: bytes) -> List[Tuple[str, int]]:
    """Parses binary server.met content and returns a list of (ip, port) tuples."""
    servers = []
    if len(met_data) < 5:
        return servers

    header = met_data[0]
    if header not in (0xE0, 0xE1):
        return servers

    count = struct.unpack_from("<I", met_data, 1)[0]
    offset = 5

    for _ in range(count):
        if offset + 6 > len(met_data):
            break
        ip_int = struct.unpack_from("<I", met_data, offset)[0]
        port = struct.unpack_from("<H", met_data, offset + 4)[0]
        offset += 6
        ip_str = int_to_ip(ip_int)
        servers.append((ip_str, port))

        if offset + 4 > len(met_data):
            break
        tag_count = struct.unpack_from("<I", met_data, offset)[0]
        offset += 4

        # Parse / Skip tags
        for _ in range(tag_count):
            if offset >= len(met_data):
                break
            tag_type = met_data[offset] & 0x7F
            offset += 1

            if offset + 2 > len(met_data):
                break
            name_len = struct.unpack_from("<H", met_data, offset)[0]
            offset += 2 + name_len

            if tag_type == 0x02:  # String
                if offset + 2 > len(met_data):
                    break
                v_len = struct.unpack_from("<H", met_data, offset)[0]
                offset += 2 + v_len
            elif tag_type in (0x03, 0x04):  # Int/Float
                offset += 4
            elif tag_type == 0x08:  # Uint16
                offset += 2
            elif tag_type == 0x09:  # Uint8
                offset += 1
            elif tag_type == 0x0B:  # Uint64
                offset += 8

    return servers

def fetch_remote_server_lists() -> Set[Tuple[str, int]]:
    """Downloads distant server.met files over HTTP/HTTPS to extract server IP:Port combinations."""
    discovered = set()
    print("--- Fetching remote server.met lists ---")

    headers = {"User-Agent": "eMule/0.50a (Windows NT 10.0; Win64; x64)"}
    for url in REMOTE_MET_URLS:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = resp.read()
                servers = parse_server_met_bytes(data)
                if servers:
                    print(f"  [+] Downloaded {len(servers)} servers from {url}")
                    discovered.update(servers)
        except Exception as e:
            print(f"  [-] Failed to fetch {url}: {e}")

    return discovered

# ==============================================================================
# GEOIP ENRICHMENT
# ==============================================================================
def enrich_with_geo(servers: List[Dict[str, Any]]) -> None:
    """Enriches active servers with country code, country name, and flag graphics via batch API."""
    if not servers:
        return

    print("--- Resolving GeoIP location data ---")
    chunk_size = 100
    for i in range(0, len(servers), chunk_size):
        chunk = servers[i : i + chunk_size]
        queries = [{"query": s["ip"], "fields": "countryCode,country"} for s in chunk]

        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=json.dumps(queries).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                results = json.loads(resp.read().decode())
                for s, res in zip(chunk, results):
                    code = res.get("countryCode", "XX")
                    country = res.get("country", "Unknown Location")
                    s["country_code"] = code
                    s["country_name"] = country
                    if code != "XX":
                        s["flag"] = f'<img src="https://flagcdn.io/{code.lower()}.svg" width="22" height="15" alt="{code}" class="flag-icon" title="{country}">'
                    else:
                        s["flag"] = "🌐"
        except Exception as e:
            print(f"  [-] GeoIP batch failed ({e}), setting default values.")
            for s in chunk:
                s["country_code"] = "XX"
                s["country_name"] = "Unknown Location"
                s["flag"] = "🌐"

# ==============================================================================
# GENERATORS (BINARY SERVER.MET, JSON, TXT, HTML)
# ==============================================================================
def write_tag_string_id(tag_id: int, value: str) -> bytes:
    """Encodes string tag with integer ID (Type 0x02, NameLen = 1, Name = ID)."""
    val_bytes = str(value).encode("utf-8", errors="ignore")
    return struct.pack("<B H B H", 2, 1, tag_id, len(val_bytes)) + val_bytes

def write_tag_uint32_name(name_str: str, value: int) -> bytes:
    """Encodes Uint32 tag with string name (Type 0x03, NameLen, Name, Uint32)."""
    name_bytes = name_str.encode("ascii")
    return struct.pack("<B H", 3, len(name_bytes)) + name_bytes + struct.pack("<I", int(value))

def generate_server_met(filepath: str, servers: List[Dict[str, Any]]) -> None:
    """Generates a binary eMule server.met file."""
    with open(filepath, "wb") as f:
        f.write(struct.pack("<B", 0xE0))  # eD2k Header
        f.write(struct.pack("<I", len(servers)))  # Server count

        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s["ip"])))
            f.write(struct.pack("<H", s["port"]))

            tags = []
            if s.get("name"):
                tags.append(write_tag_string_id(1, s["name"]))  # ST_SERVERNAME
            if s.get("description"):
                tags.append(write_tag_string_id(11, s["description"]))  # ST_DESCRIPTION
            if s.get("version") and s["version"] != "Unknown":
                tags.append(write_tag_string_id(17, s["version"]))  # ST_VERSION

            if s.get("users") is not None:
                tags.append(write_tag_uint32_name("users", s["users"]))
            if s.get("files") is not None:
                tags.append(write_tag_uint32_name("files", s["files"]))

            f.write(struct.pack("<I", len(tags)))
            for tag in tags:
                f.write(tag)

def generate_json(filepath: str, servers: List[Dict[str, Any]], stats: Dict[str, Any]) -> None:
    """Exports active server directory to a clean JSON API."""
    data = {
        "metadata": stats,
        "server_count": len(servers),
        "servers": servers,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_txt(filepath: str, servers: List[Dict[str, Any]]) -> None:
    """Exports raw server list (IP:Port) to text file."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# eD2k Active Server List - Updated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        for s in servers:
            f.write(f"{s['ip']}:{s['port']}\n")

def generate_html(filepath: str, servers: List[Dict[str, Any]], stats: Dict[str, Any]) -> None:
    """Generates a responsive, ultra-modern Glassmorphism web portal."""
    now_utc = stats["last_updated_utc"]

    # Calculate summary metrics
    total_users = sum(s.get("users", 0) for s in servers)
    total_files = sum(s.get("files", 0) for s in servers)
    valid_pings = [s["ping_ms"] for s in servers if s.get("ping_ms") is not None]
    avg_ping = int(sum(valid_pings) / len(valid_pings)) if valid_pings else 0

    servers_json_escaped = json.dumps(servers, ensure_ascii=False).replace("</script>", "<\\/script>")

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active eD2k Server List • eMule Server Directory</title>
    <meta name="description" content="Verified active eD2k (eMule / aMule) server list with real-time stats, ping metrics, limits, and automated server.met updates.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="icon" type="image/svg+xml" href="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg">
    
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: rgba(18, 26, 43, 0.75);
            --bg-card-hover: rgba(28, 40, 64, 0.85);
            --border-card: rgba(255, 255, 255, 0.08);
            --border-focus: #6366f1;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --accent-cyan: #06b6d4;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            --radius-lg: 16px;
            --radius-md: 10px;
            --radius-sm: 6px;
        }}

        [data-theme="light"] {{
            --bg-body: #f1f5f9;
            --bg-card: rgba(255, 255, 255, 0.85);
            --bg-card-hover: rgba(248, 250, 252, 0.95);
            --border-card: rgba(0, 0, 0, 0.08);
            --text-main: #0f172a;
            --text-muted: #475569;
            --text-dim: #94a3b8;
            --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.06);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px 16px;
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}

        /* --- HEADER & NAVBAR --- */
        .navbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 28px;
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-lg);
            box-shadow: var(--glass-shadow);
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 14px;
        }}
        .brand img {{
            width: 44px;
            height: 44px;
            filter: drop-shadow(0 4px 6px rgba(99, 102, 241, 0.3));
        }}
        .brand-text h1 {{
            font-size: 22px;
            font-weight: 800;
            background: linear-gradient(135deg, var(--text-main) 0%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }}
        .brand-text p {{
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
        }}

        .nav-controls {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .btn-icon {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-card);
            color: var(--text-main);
            padding: 8px 12px;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }}
        .btn-icon:hover {{
            background: rgba(255, 255, 255, 0.12);
            border-color: var(--primary);
            transform: translateY(-1px);
        }}

        /* --- DASHBOARD STATS CARDS --- */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-lg);
            padding: 20px;
            box-shadow: var(--glass-shadow);
            position: relative;
            overflow: hidden;
        }}
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
        }}
        .stat-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .stat-value {{
            font-size: 26px;
            font-weight: 800;
            color: var(--text-main);
            font-family: 'JetBrains Mono', monospace;
        }}
        .stat-sub {{
            font-size: 11px;
            color: var(--success);
            margin-top: 4px;
            font-weight: 500;
        }}

        /* --- HERO BANNER & DOWNLOAD BAR --- */
        .hero-bar {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            box-shadow: var(--glass-shadow);
        }}
        .hero-info h2 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 6px;
        }}
        .hero-info p {{
            font-size: 13px;
            color: var(--text-muted);
        }}

        .btn-group {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent-cyan) 100%);
            color: #ffffff;
            font-weight: 700;
            padding: 12px 22px;
            border-radius: var(--radius-md);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
            transition: all 0.2s ease;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }}
        .btn-primary:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5);
        }}
        .btn-secondary {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-main);
            font-weight: 600;
            padding: 12px 18px;
            border-radius: var(--radius-md);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid var(--border-card);
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 14px;
        }}
        .btn-secondary:hover {{
            background: rgba(255, 255, 255, 0.15);
            border-color: var(--primary);
        }}

        /* --- TOOLBAR & SEARCH --- */
        .toolbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .search-box {{
            position: relative;
            flex-grow: 1;
            max-width: 420px;
        }}
        .search-box input {{
            width: 100%;
            padding: 12px 16px 12px 42px;
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-md);
            color: var(--text-main);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s ease;
        }}
        .search-box input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }}
        .search-box svg {{
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            width: 18px;
            height: 18px;
            fill: var(--text-muted);
        }}

        /* --- TABLE CONTAINER --- */
        .table-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--glass-shadow);
        }}

        .table-responsive {{
            width: 100%;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13.5px;
        }}

        th {{
            background: rgba(0, 0, 0, 0.2);
            color: var(--text-muted);
            font-weight: 700;
            padding: 16px;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.06em;
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
            transition: color 0.2s ease;
        }}
        th:hover {{
            color: var(--text-main);
        }}

        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-card);
            vertical-align: middle;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover td {{
            background: var(--bg-card-hover);
        }}

        .server-name-cell {{
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            flex-direction: column;
        }}
        .server-desc {{
            font-size: 11.5px;
            color: var(--text-muted);
            font-weight: 400;
            margin-top: 3px;
            max-width: 280px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: var(--radius-sm);
            font-size: 11px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-ping-good {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-ping-medium {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-ping-high {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}

        .badge-version {{ background: rgba(99, 102, 241, 0.15); color: var(--primary); border: 1px solid rgba(99, 102, 241, 0.3); }}

        .num-font {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }}

        .flag-icon {{
            border-radius: 2px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            vertical-align: middle;
        }}

        .capacity-bar {{
            width: 100px;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 4px;
        }}
        .capacity-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--success), var(--warning));
            border-radius: 3px;
        }}

        /* --- TOAST NOTIFICATIONS --- */
        #toast {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #1e293b;
            color: #ffffff;
            padding: 14px 22px;
            border-radius: var(--radius-md);
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid var(--primary);
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            z-index: 1000;
        }}
        #toast.show {{
            transform: translateY(0);
            opacity: 1;
        }}

        /* --- INSTRUCTION CARDS --- */
        .instructions-card {{
            margin-top: 32px;
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--glass-shadow);
        }}
        .instructions-card h3 {{
            font-size: 16px;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .instructions-card ol {{
            margin-left: 20px;
            color: var(--text-muted);
            font-size: 13.5px;
            line-height: 1.7;
        }}
        .code-snippet {{
            background: rgba(0,0,0,0.3);
            padding: 8px 12px;
            border-radius: var(--radius-sm);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--accent-cyan);
            word-break: break-all;
            margin: 6px 0;
            display: inline-block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- NAVBAR -->
        <header class="navbar">
            <div class="brand">
                <img src="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg" alt="eMule Logo">
                <div class="brand-text">
                    <h1 id="txt-title">eD2k Active Server Directory</h1>
                    <p id="txt-subtitle">Live Automated Scanner • High-ID Verified Servers</p>
                </div>
            </div>
            <div class="nav-controls">
                <select id="lang-select" class="btn-icon" onchange="changeLanguage(this.value)">
                    <option value="en">🇬🇧 English</option>
                    <option value="fr">🇫🇷 Français</option>
                    <option value="es">🇪🇸 Español</option>
                    <option value="de">🇩🇪 Deutsch</option>
                    <option value="it">🇮🇹 Italiano</option>
                </select>
                <button class="btn-icon" onclick="toggleTheme()">
                    <span id="theme-icon">🌙</span> <span id="theme-txt">Dark</span>
                </button>
            </div>
        </header>

        <!-- KPI STATS CARDS -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label" id="lbl-servers">Active Servers</div>
                <div class="stat-value">{len(servers)}</div>
                <div class="stat-sub">🟢 100% Operational</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-users">Online Users</div>
                <div class="stat-value">{format_number(total_users)}</div>
                <div class="stat-sub">⚡ Connected Network</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-files">Shared Files</div>
                <div class="stat-value">{format_number(total_files)}</div>
                <div class="stat-sub">📂 Indexed Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-ping">Avg Latency</div>
                <div class="stat-value">{avg_ping} ms</div>
                <div class="stat-sub">🚀 Fast Response</div>
            </div>
        </div>

        <!-- HERO / ACTION BAR -->
        <div class="hero-bar">
            <div class="hero-info">
                <h2 id="txt-hero-title">Auto-Updating eMule server.met</h2>
                <p><span id="txt-updated">Last scan:</span> <strong>{now_utc} UTC</strong> • Next scan in ~6 hours</p>
            </div>
            <div class="btn-group">
                <a href="server.met" class="btn-primary" id="btn-download">
                    <span>⬇️</span> <span id="txt-btn-download">Download server.met</span>
                </a>
                <button class="btn-secondary" onclick="copyMetURL()" id="btn-copy-url">
                    <span>📋</span> <span id="txt-btn-copy-url">Copy server.met URL</span>
                </button>
                <button class="btn-secondary" onclick="copyAllEd2k()" id="btn-copy-ed2k">
                    <span>🔗</span> <span id="txt-btn-copy-ed2k">Copy All eD2k Links</span>
                </button>
            </div>
        </div>

        <!-- TOOLBAR & SEARCH -->
        <div class="toolbar">
            <div class="search-box">
                <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                <input type="text" id="search-input" placeholder="Search servers by name, IP, country..." onkeyup="filterServers()">
            </div>
        </div>

        <!-- MAIN SERVER TABLE -->
        <div class="table-card">
            <div class="table-responsive">
                <table id="server-table">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)" id="th-geo">Geo ↕</th>
                            <th onclick="sortTable(1)" id="th-name">Server Name & Description ↕</th>
                            <th onclick="sortTable(2)" id="th-ip">IP:Port ↕</th>
                            <th onclick="sortTable(3)" id="th-ping">Ping ↕</th>
                            <th onclick="sortTable(4)" style="text-align:right" id="th-users">Users / Capacity ↕</th>
                            <th onclick="sortTable(5)" style="text-align:right" id="th-files">Files ↕</th>
                            <th onclick="sortTable(6)" id="th-limits">Limits ↕</th>
                            <th onclick="sortTable(7)" id="th-ver">Version ↕</th>
                            <th style="text-align:center" id="th-action">Connect</th>
                        </tr>
                    </thead>
                    <tbody id="table-body">
                        <!-- Dynamically populated -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- INSTRUCTIONS CARD -->
        <div class="instructions-card">
            <h3 id="txt-inst-title">💡 How to use this list in eMule / aMule</h3>
            <ol>
                <li id="txt-inst-1">Copy the direct <strong>server.met URL</strong>: <span class="code-snippet" id="met-url-display"></span></li>
                <li id="txt-inst-2">Open your <strong>eMule</strong> preferences → <strong>Server</strong> section.</li>
                <li id="txt-inst-3">Paste the URL under <em>"Auto-update server list at startup"</em> or click <em>"Update server.met from URL"</em>.</li>
                <li id="txt-inst-4">Alternatively, click any <strong>"Add to eMule"</strong> link above to add an individual server immediately.</li>
            </ol>
        </div>
    </div>

    <!-- TOAST -->
    <div id="toast">✅ Copied to clipboard!</div>

    <script>
        const SERVERS_DATA = {servers_json_escaped};

        const TRANSLATIONS = {{
            en: {{
                title: "eD2k Active Server Directory", subtitle: "Live Automated Scanner • High-ID Verified Servers",
                servers: "Active Servers", users: "Online Users", files: "Shared Files", ping: "Avg Latency",
                heroTitle: "Auto-Updating eMule server.met", updated: "Last scan:",
                btnDownload: "Download server.met", btnCopyUrl: "Copy server.met URL", btnCopyEd2k: "Copy All eD2k Links",
                thGeo: "Geo ↕", thName: "Server Name & Description ↕", thIp: "IP:Port ↕", thPing: "Ping ↕",
                thUsers: "Users / Capacity ↕", thFiles: "Files ↕", thLimits: "Limits ↕", thVer: "Version ↕", thAction: "Connect",
                instTitle: "💡 How to use this list in eMule / aMule",
                inst1: "Copy the direct server.met URL:", inst2: "Open your eMule preferences → Server section.",
                inst3: "Paste the URL into 'Update server.met from URL'.", inst4: "Click any 'Add to eMule' link above to add servers instantly."
            }},
            fr: {{
                title: "Annuaire des Serveurs eD2k Actifs", subtitle: "Scanner Automatique En Direct • Serveurs High-ID Vérifiés",
                servers: "Serveurs Actifs", users: "Utilisateurs En Ligne", files: "Fichiers Partagés", ping: "Latence Moyenne",
                heroTitle: "Fichier server.met eMule Auto-Mise à Jour", updated: "Dernier scan :",
                btnDownload: "Télécharger server.met", btnCopyUrl: "Copier l'URL server.met", btnCopyEd2k: "Copier Tous les Liens eD2k",
                thGeo: "Géo ↕", thName: "Nom du Serveur & Description ↕", thIp: "IP:Port ↕", thPing: "Ping ↕",
                thUsers: "Utilisateurs / Capacité ↕", thFiles: "Fichiers ↕", thLimits: "Limites ↕", thVer: "Version ↕", thAction: "Connexion",
                instTitle: "💡 Comment utiliser cette liste dans eMule / aMule",
                inst1: "Copiez l'URL directe du fichier server.met :", inst2: "Ouvrez les préférences eMule → Section Serveur.",
                inst3: "Collez l'URL dans 'Mettre à jour server.met depuis l'URL'.", inst4: "Cliquez sur 'Ajouter à eMule' pour ajouter un serveur directement."
            }},
            es: {{
                title: "Directorio de Servidores eD2k Activos", subtitle: "Escáner Automático En Vivo • Servidores Verificados",
                servers: "Servidores Activos", users: "Usuarios En Línea", files: "Archivos Compartidos", ping: "Latencia Media",
                heroTitle: "Archivo server.met con Actualización Automática", updated: "Última exploración:",
                btnDownload: "Descargar server.met", btnCopyUrl: "Copiar URL server.met", btnCopyEd2k: "Copiar Todos los Enlaces eD2k",
                thGeo: "Geo ↕", thName: "Nombre y Descripción ↕", thIp: "IP:Puerto ↕", thPing: "Ping ↕",
                thUsers: "Usuarios / Capacidad ↕", thFiles: "Archivos ↕", thLimits: "Límites ↕", thVer: "Versión ↕", thAction: "Conectar",
                instTitle: "💡 Cómo usar esta lista en eMule / aMule",
                inst1: "Copie la URL directa de server.met:", inst2: "Abra las preferencias de eMule → Sección Servidor.",
                inst3: "Pegue la URL en 'Actualizar server.met desde URL'.", inst4: "Haga clic en 'Añadir a eMule' para agregar un servidor."
            }},
            de: {{
                title: "Aktive eD2k Serverliste", subtitle: "Live Automatische Überprüfung • Verifizierte High-ID Server",
                servers: "Aktive Server", users: "Online Benutzer", files: "Freigegebene Dateien", ping: "Avg Latenz",
                heroTitle: "Auto-Update eMule server.met Datei", updated: "Letzter Scan:",
                btnDownload: "server.met Herunterladen", btnCopyUrl: "server.met URL Kopieren", btnCopyEd2k: "Alle eD2k-Links Kopieren",
                thGeo: "Geo ↕", thName: "Servername & Beschreibung ↕", thIp: "IP:Port ↕", thPing: "Ping ↕",
                thUsers: "Benutzer / Kapazität ↕", thFiles: "Dateien ↕", thLimits: "Limits ↕", thVer: "Version ↕", thAction: "Verbinden",
                instTitle: "💡 Verwendung dieser Liste in eMule / aMule",
                inst1: "Kopieren Sie die direkte server.met URL:", inst2: "Öffnen Sie eMule Einstellungen → Server.",
                inst3: "Fügen Sie die URL bei 'server.met von URL aktualisieren' ein.", inst4: "Klicken Sie auf 'Zu eMule hinzufügen' für direkten Import."
            }},
            it: {{
                title: "Elenco Server eD2k Attivi", subtitle: "Scansione Automatica Live • Server Verificati High-ID",
                servers: "Server Attivi", users: "Utenti Online", files: "File Condivisi", ping: "Latenza Media",
                heroTitle: "File server.met Auto-Aggiornante per eMule", updated: "Ultima scansione:",
                btnDownload: "Scarica server.met", btnCopyUrl: "Copia URL server.met", btnCopyEd2k: "Copia Tutti i Link eD2k",
                thGeo: "Geo ↕", thName: "Nome Server e Descrizione ↕", thIp: "IP:Porta ↕", thPing: "Ping ↕",
                thUsers: "Utenti / Capacità ↕", thFiles: "File ↕", thLimits: "Limiti ↕", thVer: "Versione ↕", thAction: "Connetti",
                instTitle: "💡 Come usare questo elenco in eMule / aMule",
                inst1: "Copia l'URL diretto di server.met:", inst2: "Apri Preferenze eMule → Sezione Server.",
                inst3: "Incolla l'URL in 'Aggiorna server.met da URL'.", inst4: "Clicca 'Aggiungi a eMule' per aggiungere direttamente un server."
            }}
        }};

        let currentServers = [...SERVERS_DATA];
        let currentSortCol = 4; // Default sort by Users descending
        let sortAsc = false;

        function initPage() {{
            const origin = window.location.href.split('?')[0].split('#')[0];
            const metUrl = origin.substring(0, origin.lastIndexOf('/') + 1) + 'server.met';
            document.getElementById('met-url-display').innerText = metUrl;
            renderTable();
        }}

        function formatNum(n) {{
            return n !== null && n !== undefined ? n.toLocaleString() : 'N/A';
        }}

        function getPingBadge(ping) {{
            if (!ping) return '<span class="badge badge-ping-medium">N/A</span>';
            if (ping < 60) return `<span class="badge badge-ping-good">${{ping}} ms</span>`;
            if (ping < 140) return `<span class="badge badge-ping-medium">${{ping}} ms</span>`;
            return `<span class="badge badge-ping-high">${{ping}} ms</span>`;
        }}

        function renderTable() {{
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';

            currentServers.forEach(s => {{
                const ed2kLink = `ed2k://|server|${{s.ip}}|${{s.port}}|/`;
                const maxUsers = s.max_users ? formatNum(s.max_users) : '∞';
                const capacityPct = s.max_users && s.max_users > 0 ? Math.min(100, Math.round((s.users / s.max_users) * 100)) : 0;
                
                let limitsText = 'Standard';
                if (s.soft_files || s.hard_files) {{
                    limitsText = `Soft: ${{s.soft_files ? formatNum(s.soft_files) : '∞'}} / Hard: ${{s.hard_files ? formatNum(s.hard_files) : '∞'}}`;
                }}

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${{s.flag}}</td>
                    <td>
                        <div class="server-name-cell">
                            <span>${{escapeHtml(s.name)}}</span>
                            <span class="server-desc" title="${{escapeHtml(s.description)}}">${{escapeHtml(s.description)}}</span>
                        </div>
                    </td>
                    <td class="num-font">${{s.ip}}:${{s.port}}</td>
                    <td>${{getPingBadge(s.ping_ms)}}</td>
                    <td style="text-align:right">
                        <div class="num-font" style="font-weight:700">${{formatNum(s.users)}} <span style="font-size:11px;color:var(--text-muted)">/ ${{maxUsers}}</span></div>
                        ${{s.max_users ? `<div class="capacity-bar"><div class="capacity-fill" style="width:${{capacityPct}}%"></div></div>` : ''}}
                    </td>
                    <td class="num-font" style="text-align:right;font-weight:600">${{formatNum(s.files)}}</td>
                    <td><span class="badge" style="background:rgba(255,255,255,0.05);color:var(--text-muted);font-size:10.5px">${{limitsText}}</span></td>
                    <td><span class="badge badge-version">${{escapeHtml(s.version)}}</span></td>
                    <td style="text-align:center">
                        <a href="${{ed2kLink}}" class="btn-icon" style="padding:4px 8px;font-size:11px;display:inline-flex" title="Add directly to eMule client">
                            ⚡ Connect
                        </a>
                    </td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterServers() {{
            const q = document.getElementById('search-input').value.toLowerCase().trim();
            if (!q) {{
                currentServers = [...SERVERS_DATA];
            }} else {{
                currentServers = SERVERS_DATA.filter(s => 
                    s.name.toLowerCase().includes(q) ||
                    s.ip.includes(q) ||
                    s.description.toLowerCase().includes(q) ||
                    (s.country_name && s.country_name.toLowerCase().includes(q)) ||
                    (s.version && s.version.toLowerCase().includes(q))
                );
            }}
            sortTable(currentSortCol, false);
        }}

        function sortTable(colIndex, toggle = true) {{
            if (toggle) {{
                if (currentSortCol === colIndex) sortAsc = !sortAsc;
                else {{ currentSortCol = colIndex; sortAsc = false; }}
            }}

            currentServers.sort((a, b) => {{
                let valA, valB;
                switch(colIndex) {{
                    case 0: valA = a.country_name || ''; valB = b.country_name || ''; break;
                    case 1: valA = a.name.toLowerCase(); valB = b.name.toLowerCase(); break;
                    case 2: valA = a.ip; valB = b.ip; break;
                    case 3: valA = a.ping_ms || 9999; valB = b.ping_ms || 9999; break;
                    case 4: valA = a.users || 0; valB = b.users || 0; break;
                    case 5: valA = a.files || 0; valB = b.files || 0; break;
                    case 6: valA = a.hard_files || 0; valB = b.hard_files || 0; break;
                    case 7: valA = a.version || ''; valB = b.version || ''; break;
                    default: valA = a.users || 0; valB = b.users || 0;
                }}
                if (valA < valB) return sortAsc ? -1 : 1;
                if (valA > valB) return sortAsc ? 1 : -1;
                return 0;
            }});

            renderTable();
        }}

        function changeLanguage(lang) {{
            const t = TRANSLATIONS[lang] || TRANSLATIONS.en;
            document.getElementById('txt-title').innerText = t.title;
            document.getElementById('txt-subtitle').innerText = t.subtitle;
            document.getElementById('lbl-servers').innerText = t.servers;
            document.getElementById('lbl-users').innerText = t.users;
            document.getElementById('lbl-files').innerText = t.files;
            document.getElementById('lbl-ping').innerText = t.ping;
            document.getElementById('txt-hero-title').innerText = t.heroTitle;
            document.getElementById('txt-updated').innerText = t.updated;
            document.getElementById('txt-btn-download').innerText = t.btnDownload;
            document.getElementById('txt-btn-copy-url').innerText = t.btnCopyUrl;
            document.getElementById('txt-btn-copy-ed2k').innerText = t.btnCopyEd2k;
            document.getElementById('th-geo').innerText = t.thGeo;
            document.getElementById('th-name').innerText = t.thName;
            document.getElementById('th-ip').innerText = t.thIp;
            document.getElementById('th-ping').innerText = t.thPing;
            document.getElementById('th-users').innerText = t.thUsers;
            document.getElementById('th-files').innerText = t.thFiles;
            document.getElementById('th-limits').innerText = t.thLimits;
            document.getElementById('th-ver').innerText = t.thVer;
            document.getElementById('th-action').innerText = t.thAction;
            document.getElementById('txt-inst-title').innerText = t.instTitle;
            document.getElementById('txt-inst-1').childNodes[0].nodeValue = t.inst1 + " ";
            document.getElementById('txt-inst-2').innerText = t.inst2;
            document.getElementById('txt-inst-3').innerText = t.inst3;
            document.getElementById('txt-inst-4').innerText = t.inst4;
        }}

        function toggleTheme() {{
            const html = document.documentElement;
            const isDark = html.getAttribute('data-theme') === 'dark';
            const next = isDark ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            document.getElementById('theme-icon').innerText = isDark ? '☀️' : '🌙';
            document.getElementById('theme-txt').innerText = isDark ? 'Light' : 'Dark';
        }}

        function showToast(msg) {{
            const toast = document.getElementById('toast');
            toast.innerText = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2500);
        }}

        function copyMetURL() {{
            const metUrl = document.getElementById('met-url-display').innerText;
            navigator.clipboard.writeText(metUrl).then(() => showToast('📋 server.met URL copied!'));
        }}

        function copyAllEd2k() {{
            const links = SERVERS_DATA.map(s => `ed2k://|server|${{s.ip}}|${{s.port}}|/`).join('\\n');
            navigator.clipboard.writeText(links).then(() => showToast(`🔗 Copied ${{SERVERS_DATA.length}} eD2k server links!`));
        }}

        function escapeHtml(str) {{
            if (!str) return '';
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }}

        window.onload = initPage;
    </script>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

# ==============================================================================
# DATABASE MAINTENANCE & SEED LIST EXPANSION
# ==============================================================================
def load_seed_servers(filepath: str) -> Set[Tuple[str, int]]:
    """Reads seed list of IP:Port entries from file."""
    servers = set()
    if not os.path.exists(filepath):
        return servers

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = line.split(":")
                if len(parts) == 2:
                    ip = parts[0].strip()
                    port = int(parts[1].strip())
                    servers.add((ip, port))
            except Exception:
                pass
    return servers

def update_servers_txt(filepath: str, known_servers: Set[Tuple[str, int]]) -> None:
    """Updates servers.txt with deduplicated and validated IP:Port entries."""
    sorted_servers = sorted(list(known_servers), key=lambda x: (x[0], x[1]))
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Known eD2k Seed Servers (IP:PORT)\n")
        f.write(f"# Total Candidates: {len(sorted_servers)}\n")
        for ip, port in sorted_servers:
            f.write(f"{ip}:{port}\n")
    print(f"  [+] Saved {len(sorted_servers)} unique servers to {filepath}")

# ==============================================================================
# MAIN ENGINE ENTRYPOINT
# ==============================================================================
def main() -> None:
    print("==========================================================================")
    print("       Active eD2k Server Harvester & Directory Generator                ")
    print("==========================================================================")
    
    ensure_dir(OUTPUT_DIR)

    # 1. Load seed servers from input file
    candidate_servers = load_seed_servers(INPUT_FILE)
    print(f"[*] Loaded {len(candidate_servers)} seed servers from {INPUT_FILE}")

    # 2. Fetch remote server.met files to expand candidates
    remote_servers = fetch_remote_server_lists()
    before_count = len(candidate_servers)
    candidate_servers.update(remote_servers)
    print(f"[*] Total server candidates after remote fetch: {len(candidate_servers)} (+{len(candidate_servers) - before_count} new)")

    # 3. Probe all candidates concurrently via UDP
    print(f"\n--- Interrogating {len(candidate_servers)} servers via UDP (Threads: {MAX_THREADS}) ---")
    active_servers: List[Dict[str, Any]] = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_server = {
            executor.submit(probe_server_udp, ip, port): (ip, port)
            for ip, port in candidate_servers
        }
        for future in concurrent.futures.as_completed(future_to_server):
            ip, port = future_to_server[future]
            try:
                res = future.result()
                if res and res["active"]:
                    print(f"  [ONLINE] {ip}:{port} | {res['name']} | {res['users']:,} users | {res['files']:,} files | {res['ping_ms']} ms")
                    active_servers.append(res)
                else:
                    print(f"  [OFFLINE] {ip}:{port}")
            except Exception as e:
                print(f"  [ERROR] {ip}:{port} - {e}")

    print(f"\n[*] Scan Complete! {len(active_servers)} active servers verified.")

    if not active_servers:
        print("[-] Warning: No active servers found! Check firewall or network connectivity.")
        sys.exit(1)

    # 4. Peer discovery via TCP OP_SERVERLIST from active servers
    print("\n--- Harvesting peer lists from active servers via TCP ---")
    newly_discovered_peers = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_peer = {
            executor.submit(get_remote_server_list_tcp, s["ip"], s["port"]): s
            for s in active_servers
        }
        for future in concurrent.futures.as_completed(future_to_peer):
            try:
                peers = future.result()
                if peers:
                    print(f"  [+] Server {future_to_peer[future]['ip']} shared {len(peers)} peer servers.")
                    newly_discovered_peers.update(peers)
            except Exception:
                pass

    # Save all accumulated candidates back to servers.txt for auto-growth
    candidate_servers.update(newly_discovered_peers)
    update_servers_txt(INPUT_FILE, candidate_servers)

    # 5. Enrich active servers with GeoIP location data
    enrich_with_geo(active_servers)

    # 6. Sort active servers by Users descending (and Files secondarily)
    active_servers.sort(key=lambda s: (s.get("users", 0), s.get("files", 0)), reverse=True)

    # 7. Generate Output Files
    print("\n--- Generating Directory Artefacts ---")
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    stats_meta = {
        "last_updated_utc": now_utc,
        "total_active_servers": len(active_servers),
        "total_users": sum(s.get("users", 0) for s in active_servers),
        "total_files": sum(s.get("files", 0) for s in active_servers),
    }

    generate_server_met(MET_FILE, active_servers)
    print(f"  [+] Generated eMule binary file: {MET_FILE}")

    generate_json(JSON_FILE, active_servers, stats_meta)
    print(f"  [+] Generated REST JSON API: {JSON_FILE}")

    generate_txt(TXT_FILE, active_servers)
    print(f"  [+] Generated plain text list: {TXT_FILE}")

    generate_html(HTML_FILE, active_servers, stats_meta)
    print(f"  [+] Generated Glassmorphism HTML Portal: {HTML_FILE}")

    print("\n==========================================================================")
    print(f"   SUCCESS! Directory updated with {len(active_servers)} active eD2k servers.")
    print("==========================================================================")

if __name__ == "__main__":
    main()
