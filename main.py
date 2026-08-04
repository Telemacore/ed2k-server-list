#!/usr/bin/env python3
"""
Active eD2k Server Directory, Harvester & Historical Analytics
================================================================
An automated Python scanner that probes eDonkey/eMule servers via UDP/TCP,
extracts extended server statistics (Max Users, Limits, LowID), tracks
historical changes (Users, Files, Name/Description audit logs), updates
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

# Reconfigure stdout for UTF-8 compatibility on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ==============================================================================
# CONFIGURATION
# ==============================================================================
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
HISTORY_FILE = "history.json"
PUBLIC_HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")
JSON_FILE = os.path.join(OUTPUT_DIR, "servers.json")
TXT_FILE = os.path.join(OUTPUT_DIR, "servers.txt")

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
MAX_HISTORY_POINTS = 180  # Keep last 180 metric points (~45 days at 6h intervals)

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
    """Format integers with commas/spaces for display or return N/A."""
    if val is None or val == 0:
        return "N/A"
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
    udp_port = tcp_port + 4
    info = {
        "ip": ip,
        "port": tcp_port,
        "udp_port": udp_port,
        "active": False,
        "name": "N/A",
        "description": "N/A",
        "version": "N/A",
        "users": 0,
        "files": 0,
        "max_users": None,
        "lowid_users": None,
        "soft_files": None,
        "hard_files": None,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    challenge_stat = 0x55AA0000 | random.randint(0, 0xFFFF)
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0x96, challenge_stat), (ip, udp_port))
        data, _ = sock.recvfrom(1024)

        if len(data) >= 14 and data[0] == 0xE3 and data[1] == 0x97:
            resp_challenge, users, files = struct.unpack_from("<III", data, 2)
            if resp_challenge == challenge_stat:
                info["users"] = users
                info["files"] = files
                info["active"] = True

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
                if len(data) >= offset + 4:
                    offset += 4
                if len(data) >= offset + 4:
                    info["lowid_users"] = struct.unpack_from("<I", data, offset)[0]
    except Exception:
        pass

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
                    name_str = str(tags[0x01]).strip()
                    if name_str:
                        info["name"] = name_str
                if 0x0B in tags:
                    desc_str = str(tags[0x0B]).strip()
                    if desc_str:
                        info["description"] = desc_str
                if 0x91 in tags:
                    v = tags[0x91]
                    info["version"] = f"{v >> 16}.{v & 0xFFFF}" if isinstance(v, int) else str(v)
                info["active"] = True
    except Exception:
        pass
    finally:
        sock.close()

    if info["active"] and (info["users"] > 0 or info["name"] != "N/A"):
        return info
    return None

# ==============================================================================
# TCP REMOTE SERVER LIST HARVESTER
# ==============================================================================
def get_remote_server_list_tcp(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> List[Tuple[str, int]]:
    discovered_servers = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    client_port = random.randint(10000, 60000)
    try:
        sock.connect((ip, port))
        
        username = b"http://www.emule-project.net"
        tag_user = struct.pack("<BHB", 0x02, 1, 0x01) + struct.pack("<H", len(username)) + username
        tags_data = (
            tag_user
            + struct.pack("<BHBI", 0x03, 1, 0x11, 0x3C)
            + struct.pack("<BHBI", 0x03, 1, 0x0F, client_port)
            + struct.pack("<BHBI", 0x03, 1, 0xFB, 0x003C0000)
            + struct.pack("<BHBI", 0x03, 1, 0x20, 0x0119)
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

            if protocol == 0xD4:
                try:
                    data = zlib.decompress(data)
                except Exception:
                    continue

            if not data:
                continue
            opcode, payload_data = data[0], data[1:]

            if opcode == 0x40:
                client_id = struct.unpack_from("<I", payload_data, 0)[0]
                if client_id != 0:
                    sock.send(struct.pack("<BI", 0xE3, 1) + struct.pack("<B", 0x14))
            elif opcode == 0x32:
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
            elif opcode == 0x05:
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

        for _ in range(tag_count):
            if offset >= len(met_data):
                break
            tag_type = met_data[offset] & 0x7F
            offset += 1

            if offset + 2 > len(met_data):
                break
            name_len = struct.unpack_from("<H", met_data, offset)[0]
            offset += 2 + name_len

            if tag_type == 0x02:
                if offset + 2 > len(met_data):
                    break
                v_len = struct.unpack_from("<H", met_data, offset)[0]
                offset += 2 + v_len
            elif tag_type in (0x03, 0x04):
                offset += 4
            elif tag_type == 0x08:
                offset += 2
            elif tag_type == 0x09:
                offset += 1
            elif tag_type == 0x0B:
                offset += 8

    return servers

def fetch_remote_server_lists() -> Set[Tuple[str, int]]:
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
                    country = res.get("country", "N/A")
                    s["country_code"] = code if code != "XX" else "N/A"
                    s["country_name"] = country if country != "N/A" else "N/A"
                    if code != "XX" and code != "N/A":
                        s["flag"] = f'<img src="https://flagcdn.io/{code.lower()}.svg" width="22" height="15" alt="{code}" class="flag-icon" title="{country}">'
                    else:
                        s["flag"] = "🌐"
        except Exception as e:
            print(f"  [-] GeoIP batch failed ({e}), setting default values.")
            for s in chunk:
                s["country_code"] = "N/A"
                s["country_name"] = "N/A"
                s["flag"] = "🌐"

# ==============================================================================
# HISTORICAL TRACKING & ANALYTICS MANAGER
# ==============================================================================
class HistoryManager:
    def __init__(self, filepath: str = HISTORY_FILE):
        self.filepath = filepath
        self.data: Dict[str, Any] = {
            "last_updated": "",
            "global_history": [],
            "servers": {}
        }
        self.load()

    def load(self) -> None:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception as e:
                print(f"  [-] Warning: Failed to load history database ({e}). Initializing new structure.")

    def update(self, active_servers: List[Dict[str, Any]], all_candidates: Set[Tuple[str, int]], timestamp: str) -> None:
        self.data["last_updated"] = timestamp
        active_keys = set()

        for s in active_servers:
            key = f"{s['ip']}:{s['port']}"
            active_keys.add(key)

            if key not in self.data["servers"]:
                srv_data = {
                    "ip": s["ip"],
                    "port": s["port"],
                    "key": key,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "status": "online",
                    "name": s["name"] if s["name"] else "N/A",
                    "description": s["description"] if s["description"] else "N/A",
                    "version": s.get("version", "N/A"),
                    "country_code": s.get("country_code", "N/A"),
                    "country_name": s.get("country_name", "N/A"),
                    "flag": s.get("flag", "🌐"),
                    "users": s.get("users", 0),
                    "files": s.get("files", 0),
                    "max_users": s.get("max_users"),
                    "soft_files": s.get("soft_files"),
                    "hard_files": s.get("hard_files"),
                    "name_history": [{"timestamp": timestamp, "name": s["name"]}] if s["name"] and s["name"] != "N/A" else [],
                    "desc_history": [{"timestamp": timestamp, "description": s["description"]}] if s["description"] and s["description"] != "N/A" else [],
                    "metrics": []
                }
                self.data["servers"][key] = srv_data
            else:
                srv_data = self.data["servers"][key]
                srv_data["last_seen"] = timestamp
                srv_data["status"] = "online"

                if s["name"] and s["name"] != "N/A" and s["name"] != srv_data.get("name"):
                    srv_data.setdefault("name_history", []).append({"timestamp": timestamp, "name": s["name"]})
                    srv_data["name"] = s["name"]

                if s["description"] and s["description"] != "N/A" and s["description"] != srv_data.get("description"):
                    srv_data.setdefault("desc_history", []).append({"timestamp": timestamp, "description": s["description"]})
                    srv_data["description"] = s["description"]

                srv_data["version"] = s.get("version", srv_data.get("version", "N/A"))
                srv_data["users"] = s.get("users", 0)
                srv_data["files"] = s.get("files", 0)
                srv_data["max_users"] = s.get("max_users", srv_data.get("max_users"))
                srv_data["soft_files"] = s.get("soft_files", srv_data.get("soft_files"))
                srv_data["hard_files"] = s.get("hard_files", srv_data.get("hard_files"))
                srv_data["country_code"] = s.get("country_code", srv_data.get("country_code", "N/A"))
                srv_data["country_name"] = s.get("country_name", srv_data.get("country_name", "N/A"))
                srv_data["flag"] = s.get("flag", srv_data.get("flag", "🌐"))

            srv_data["metrics"].append({
                "timestamp": timestamp,
                "users": s.get("users", 0),
                "files": s.get("files", 0),
                "status": "online"
            })
            if len(srv_data["metrics"]) > MAX_HISTORY_POINTS:
                srv_data["metrics"] = srv_data["metrics"][-MAX_HISTORY_POINTS:]

        keys_to_purge = []
        for key, srv_data in list(self.data["servers"].items()):
            if key not in active_keys:
                has_been_online = any(m.get("status") == "online" or m.get("users", 0) > 0 for m in srv_data.get("metrics", []))
                if not has_been_online and srv_data.get("name") == "N/A":
                    keys_to_purge.append(key)
                else:
                    srv_data["status"] = "offline"
                    srv_data["metrics"].append({
                        "timestamp": timestamp,
                        "users": 0,
                        "files": 0,
                        "status": "offline"
                    })
                    if len(srv_data["metrics"]) > MAX_HISTORY_POINTS:
                        srv_data["metrics"] = srv_data["metrics"][-MAX_HISTORY_POINTS:]

        for k in keys_to_purge:
            del self.data["servers"][k]

        total_users = sum(s.get("users", 0) for s in active_servers)
        total_files = sum(s.get("files", 0) for s in active_servers)
        self.data["global_history"].append({
            "timestamp": timestamp,
            "active_servers": len(active_servers),
            "total_users": total_users,
            "total_files": total_files
        })
        if len(self.data["global_history"]) > MAX_HISTORY_POINTS:
            self.data["global_history"] = self.data["global_history"][-MAX_HISTORY_POINTS:]

    def save(self) -> None:
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        with open(PUBLIC_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        print(f"  [+] History database saved ({len(self.data['servers'])} verified active/formerly active servers).")

# ==============================================================================
# GENERATORS (BINARY SERVER.MET, JSON, TXT, HTML)
# ==============================================================================
def write_tag_string_id(tag_id: int, value: str) -> bytes:
    val_bytes = str(value).encode("utf-8", errors="ignore")
    return struct.pack("<B H B H", 2, 1, tag_id, len(val_bytes)) + val_bytes

def write_tag_uint32_name(name_str: str, value: int) -> bytes:
    name_bytes = name_str.encode("ascii")
    return struct.pack("<B H", 3, len(name_bytes)) + name_bytes + struct.pack("<I", int(value))

def generate_server_met(filepath: str, servers: List[Dict[str, Any]]) -> None:
    with open(filepath, "wb") as f:
        f.write(struct.pack("<B", 0xE0))
        f.write(struct.pack("<I", len(servers)))

        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s["ip"])))
            f.write(struct.pack("<H", s["port"]))

            tags = []
            if s.get("name") and s["name"] != "N/A":
                tags.append(write_tag_string_id(1, s["name"]))
            if s.get("description") and s["description"] != "N/A":
                tags.append(write_tag_string_id(11, s["description"]))
            if s.get("version") and s["version"] != "N/A":
                tags.append(write_tag_string_id(17, s["version"]))

            if s.get("users") is not None:
                tags.append(write_tag_uint32_name("users", s["users"]))
            if s.get("files") is not None:
                tags.append(write_tag_uint32_name("files", s["files"]))

            f.write(struct.pack("<I", len(tags)))
            for tag in tags:
                f.write(tag)

def generate_json(filepath: str, servers: List[Dict[str, Any]], stats: Dict[str, Any]) -> None:
    data = {
        "metadata": stats,
        "server_count": len(servers),
        "servers": servers,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_txt(filepath: str, servers: List[Dict[str, Any]]) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# eD2k Active Server List - Updated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        for s in servers:
            f.write(f"{s['ip']}:{s['port']}\n")

def generate_html(filepath: str, active_servers: List[Dict[str, Any]], history_data: Dict[str, Any], stats: Dict[str, Any]) -> None:
    """Generates web portal with default sort by indexed files and 2-line hard/soft limits."""
    now_utc = stats["last_updated_utc"]

    total_users = sum(s.get("users", 0) for s in active_servers)
    total_files = sum(s.get("files", 0) for s in active_servers)
    total_max_capacity = sum(s.get("max_users", 0) for s in active_servers if s.get("max_users"))

    history_json_escaped = json.dumps(history_data, ensure_ascii=False).replace("</script>", "<\\/script>")

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active eD2k Server List & Trend Analytics • eMule & eDonkey</title>
    <meta name="description" content="Verified active eD2k server list with real-time user statistics, trend charts, audit history logs, and automated server.met updates.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="icon" type="image/svg+xml" href="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    
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

        .container {{ max-width: 1280px; margin: 0 auto; }}

        /* --- NAVBAR WITH HIGH Z-INDEX --- */
        .navbar {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 20px 28px; background: var(--bg-card); backdrop-filter: blur(16px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg);
            box-shadow: var(--glass-shadow); margin-bottom: 24px; flex-wrap: wrap; gap: 16px;
            position: relative; z-index: 50;
        }}
        .brand {{ display: flex; align-items: center; gap: 14px; }}
        .brand img {{ width: 44px; height: 44px; filter: drop-shadow(0 4px 6px rgba(99, 102, 241, 0.3)); }}
        .brand-text h1 {{
            font-size: 22px; font-weight: 800;
            background: linear-gradient(135deg, var(--text-main) 0%, var(--primary) 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}
        .brand-text p {{ font-size: 12px; color: var(--text-muted); font-weight: 500; }}

        .nav-controls {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; position: relative; z-index: 60; }}

        /* --- LANGUAGE PICKER IN TOP NAVBAR WITH MAXIMUM Z-INDEX --- */
        .lang-picker {{ position: relative; display: inline-block; z-index: 100; }}
        .lang-btn-current {{
            background: rgba(255, 255, 255, 0.06); border: 1px solid var(--border-card);
            color: var(--text-main); padding: 7px 12px; border-radius: var(--radius-md);
            cursor: pointer; font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px;
            transition: all 0.2s ease;
        }}
        .lang-btn-current:hover {{ background: rgba(255, 255, 255, 0.12); border-color: var(--primary); }}
        .lang-btn-current img {{ width: 20px; height: 14px; border-radius: 2px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }}

        .lang-dropdown {{
            position: absolute; top: calc(100% + 6px); right: 0;
            background: #1e293b; backdrop-filter: blur(20px);
            border: 1px solid var(--border-card); border-radius: var(--radius-md);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6); display: none; flex-direction: column;
            min-width: 150px; z-index: 1000; overflow: hidden;
        }}
        .lang-dropdown.show {{ display: flex; }}
        .lang-option {{
            display: flex; align-items: center; gap: 10px; padding: 10px 14px;
            color: var(--text-main); font-size: 13px; cursor: pointer; transition: background 0.15s ease;
        }}
        .lang-option:hover {{ background: rgba(99, 102, 241, 0.2); color: var(--primary); }}
        .lang-option img {{ width: 20px; height: 14px; border-radius: 2px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }}

        .btn-icon {{
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-card);
            color: var(--text-main); padding: 8px 12px; border-radius: var(--radius-md);
            cursor: pointer; font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 6px;
        }}
        .btn-icon:hover {{ background: rgba(255, 255, 255, 0.12); border-color: var(--primary); }}

        /* --- DASHBOARD STATS CARDS --- */
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px; margin-bottom: 24px; position: relative; z-index: 1;
        }}
        .stat-card {{
            background: var(--bg-card); backdrop-filter: blur(12px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg);
            padding: 20px; box-shadow: var(--glass-shadow); position: relative; overflow: hidden;
        }}
        .stat-card::before {{
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
        }}
        .stat-label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; }}
        .stat-value {{ font-size: 26px; font-weight: 800; color: var(--text-main); font-family: 'JetBrains Mono', monospace; }}
        .stat-sub {{ font-size: 11px; color: var(--success); margin-top: 4px; font-weight: 500; }}

        /* --- HERO BANNER & DOWNLOAD BAR --- */
        .hero-bar {{
            background: var(--bg-card); backdrop-filter: blur(12px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg);
            padding: 24px; margin-bottom: 24px; display: flex;
            justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px;
            box-shadow: var(--glass-shadow);
        }}
        .hero-info h2 {{ font-size: 18px; font-weight: 700; margin-bottom: 6px; }}
        .hero-info p {{ font-size: 13px; color: var(--text-muted); }}

        .btn-group {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .btn-primary {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent-cyan) 100%);
            color: #ffffff; font-weight: 700; padding: 12px 22px; border-radius: var(--radius-md);
            text-decoration: none; display: inline-flex; align-items: center; gap: 8px;
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35); border: none; cursor: pointer; font-size: 14px;
        }}
        .btn-primary:hover {{ transform: translateY(-2px); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5); }}
        .btn-secondary {{
            background: rgba(255, 255, 255, 0.08); color: var(--text-main); font-weight: 600;
            padding: 12px 18px; border-radius: var(--radius-md); text-decoration: none;
            display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--border-card);
            cursor: pointer; font-size: 14px;
        }}
        .btn-secondary:hover {{ background: rgba(255, 255, 255, 0.15); border-color: var(--primary); }}

        /* --- GLOBAL TREND CHARTS PANEL --- */
        .trends-panel {{
            background: var(--bg-card); backdrop-filter: blur(12px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg);
            padding: 24px; margin-bottom: 24px; box-shadow: var(--glass-shadow); display: none;
        }}
        .trends-panel.show {{ display: block; }}
        .trends-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
        .trends-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; }}
        .chart-container {{ background: rgba(0,0,0,0.2); border-radius: var(--radius-md); padding: 16px; border: 1px solid var(--border-card); }}

        /* --- CATEGORY TAB FILTERS & SEARCH --- */
        .tab-bar {{ display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }}
        .tab-btn {{
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-card);
            color: var(--text-muted); padding: 8px 16px; border-radius: var(--radius-md);
            cursor: pointer; font-weight: 600; font-size: 13px; transition: all 0.2s ease;
        }}
        .tab-btn.active {{
            background: var(--primary); color: #ffffff; border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }}

        .toolbar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 16px; }}
        .search-box {{ position: relative; flex-grow: 1; max-width: 420px; }}
        .search-box input {{
            width: 100%; padding: 12px 16px 12px 42px; background: var(--bg-card);
            border: 1px solid var(--border-card); border-radius: var(--radius-md);
            color: var(--text-main); font-size: 14px; outline: none;
        }}
        .search-box input:focus {{ border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }}
        .search-box svg {{ position: absolute; left: 14px; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; fill: var(--text-muted); }}

        /* --- TABLE --- */
        .table-card {{
            background: var(--bg-card); backdrop-filter: blur(12px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg);
            overflow: hidden; box-shadow: var(--glass-shadow);
        }}
        .table-responsive {{ width: 100%; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13.5px; }}
        th {{
            background: rgba(0, 0, 0, 0.2); color: var(--text-muted); font-weight: 700;
            padding: 16px; text-transform: uppercase; font-size: 11px; letter-spacing: 0.06em;
            cursor: pointer; user-select: none; white-space: nowrap;
        }}
        th:hover {{ color: var(--text-main); }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border-card); vertical-align: middle; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: var(--bg-card-hover); }}

        .tr-offline td {{ opacity: 0.65; background: rgba(0,0,0,0.1); }}

        .server-name-cell {{ font-weight: 700; color: var(--text-main); display: flex; flex-direction: column; }}
        .server-desc {{ font-size: 11.5px; color: var(--text-muted); font-weight: 400; margin-top: 3px; max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}

        .badge {{ display: inline-block; padding: 4px 8px; border-radius: var(--radius-sm); font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
        .badge-version {{ background: rgba(99, 102, 241, 0.15); color: var(--primary); border: 1px solid rgba(99, 102, 241, 0.3); }}
        .badge-status-online {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-status-offline {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}
        
        /* 2-LINE LIMITS BADGES STACKED VERTICALLY */
        .limits-stack {{
            display: flex; flex-direction: column; gap: 3px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px;
        }}
        .badge-limit-line {{
            background: rgba(255, 255, 255, 0.05); color: var(--text-main);
            border: 1px solid var(--border-card); padding: 2px 6px; border-radius: var(--radius-sm); width: fit-content;
        }}

        .num-font {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
        .flag-icon {{ border-radius: 2px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); vertical-align: middle; }}

        /* --- ACTION BUTTONS --- */
        .action-cell {{ display: flex; align-items: center; justify-content: center; gap: 6px; }}
        .btn-action-add {{
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(6, 182, 212, 0.2) 100%);
            border: 1px solid rgba(99, 102, 241, 0.4); color: var(--text-main);
            padding: 6px 10px; border-radius: var(--radius-md); font-size: 12px; font-weight: 600;
            text-decoration: none; display: inline-flex; align-items: center; gap: 4px;
        }}
        .btn-action-add:hover {{ background: linear-gradient(135deg, var(--primary) 0%, var(--accent-cyan) 100%); color: #ffffff; }}
        .btn-action-history {{
            background: rgba(255, 255, 255, 0.06); border: 1px solid var(--border-card);
            color: var(--accent-cyan); padding: 6px 8px; border-radius: var(--radius-md);
            cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;
        }}
        .btn-action-history:hover {{ background: rgba(6, 182, 212, 0.2); border-color: var(--accent-cyan); }}

        /* --- INSTRUCTIONS --- */
        .instructions-card {{
            margin-top: 32px; background: var(--bg-card); backdrop-filter: blur(12px);
            border: 1px solid var(--border-card); border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--glass-shadow);
        }}
        .instructions-card h3 {{ font-size: 16px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }}
        .instructions-card ol {{ margin-left: 20px; color: var(--text-muted); font-size: 13.5px; line-height: 1.7; }}
        .code-snippet {{ background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: var(--radius-sm); font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent-cyan); word-break: break-all; margin: 6px 0; display: inline-block; }}

        /* --- MODAL DIALOG --- */
        .modal-overlay {{
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(8px);
            display: none; justify-content: center; align-items: center; z-index: 10000; padding: 16px;
        }}
        .modal-overlay.show {{ display: flex; }}
        .modal-card {{
            background: var(--bg-card); border: 1px solid var(--border-card);
            border-radius: var(--radius-lg); width: 100%; max-width: 820px;
            max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: var(--glass-shadow);
        }}
        .modal-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border-card); padding-bottom: 16px; }}
        .modal-close {{ background: none; border: none; color: var(--text-muted); font-size: 24px; cursor: pointer; }}
        .modal-close:hover {{ color: var(--text-main); }}

        .audit-list {{ list-style: none; margin-top: 12px; }}
        .audit-item {{ background: rgba(0,0,0,0.2); border-left: 3px solid var(--primary); padding: 10px 14px; border-radius: var(--radius-sm); margin-bottom: 8px; font-size: 12.5px; }}
        .audit-date {{ font-size: 11px; color: var(--text-muted); margin-bottom: 2px; }}

        /* --- TOAST --- */
        #toast {{
            position: fixed; bottom: 24px; right: 24px; background: #1e293b; color: #ffffff;
            padding: 14px 22px; border-radius: var(--radius-md); box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid var(--primary); font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 10px;
            transform: translateY(100px); opacity: 0; transition: all 0.3s ease; z-index: 20000;
        }}
        #toast.show {{ transform: translateY(0); opacity: 1; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- NAVBAR WITH TOP RIGHT LANGUAGE SELECTOR (Z-INDEX FIX) -->
        <header class="navbar">
            <div class="brand">
                <img src="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg" alt="eMule Logo">
                <div class="brand-text">
                    <h1 id="txt-title">eD2k Active Server Directory & Trends</h1>
                    <p id="txt-subtitle">Automated Real-Time Scanner & Historical Analytics • eMule & eDonkey</p>
                </div>
            </div>
            <div class="nav-controls">
                <button class="btn-icon" onclick="toggleGlobalTrends()" id="btn-toggle-trends">
                    <span>📊</span> <span id="txt-btn-trends">Network Trends</span>
                </button>

                <!-- TOP NAVBAR LANGUAGE PICKER WITH HIGH Z-INDEX -->
                <div class="lang-picker">
                    <button class="lang-btn-current" onclick="toggleLangDropdown(event)">
                        <img id="current-flag" src="https://flagcdn.io/gb.svg" alt="EN">
                        <span id="current-lang-text">English</span>
                        <span style="font-size:10px">▼</span>
                    </button>
                    <div class="lang-dropdown" id="lang-dropdown">
                        <div class="lang-option" onclick="selectLang('en', 'English', 'gb')">
                            <img src="https://flagcdn.io/gb.svg" alt="EN"> English
                        </div>
                        <div class="lang-option" onclick="selectLang('fr', 'Français', 'fr')">
                            <img src="https://flagcdn.io/fr.svg" alt="FR"> Français
                        </div>
                        <div class="lang-option" onclick="selectLang('es', 'Español', 'es')">
                            <img src="https://flagcdn.io/es.svg" alt="ES"> Español
                        </div>
                        <div class="lang-option" onclick="selectLang('de', 'Deutsch', 'de')">
                            <img src="https://flagcdn.io/de.svg" alt="DE"> Deutsch
                        </div>
                        <div class="lang-option" onclick="selectLang('it', 'Italiano', 'it')">
                            <img src="https://flagcdn.io/it.svg" alt="IT"> Italiano
                        </div>
                    </div>
                </div>

                <button class="btn-icon" onclick="toggleTheme()">
                    <span id="theme-icon">🌙</span> <span id="theme-txt">Dark</span>
                </button>
            </div>
        </header>

        <!-- KPI STATS CARDS -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label" id="lbl-servers">Active Servers</div>
                <div class="stat-value">{len(active_servers)}</div>
                <div class="stat-sub">🟢 Operational</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-users">Connected Users</div>
                <div class="stat-value">{format_number(total_users)}</div>
                <div class="stat-sub">⚡ Network Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-files">Indexed Files</div>
                <div class="stat-value">{format_number(total_files)}</div>
                <div class="stat-sub">📂 Searchable Index</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-monitored">Total Monitored</div>
                <div class="stat-value">{len(history_data.get('servers', {}))}</div>
                <div class="stat-sub">🌐 Active & Formerly Active</div>
            </div>
        </div>

        <!-- GLOBAL NETWORK TRENDS PANEL -->
        <div class="trends-panel" id="global-trends-panel">
            <div class="trends-header">
                <h3>📈 Network Historical Growth Trends</h3>
                <button class="btn-icon" onclick="toggleGlobalTrends()">✕ Close</button>
            </div>
            <div class="trends-grid">
                <div class="chart-container">
                    <h4 style="font-size:13px;margin-bottom:10px;color:var(--text-muted)">Total Connected Users Over Time</h4>
                    <canvas id="chart-global-users" height="200"></canvas>
                </div>
                <div class="chart-container">
                    <h4 style="font-size:13px;margin-bottom:10px;color:var(--text-muted)">Total Indexed Files Over Time</h4>
                    <canvas id="chart-global-files" height="200"></canvas>
                </div>
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

        <!-- TAB FILTERS & SEARCH -->
        <div class="toolbar">
            <div class="tab-bar">
                <button class="tab-btn active" id="tab-active" onclick="setCategoryTab('active')">🟢 Active ({len(active_servers)})</button>
                <button class="tab-btn" id="tab-inactive" onclick="setCategoryTab('inactive')">🔴 Formerly Monitored ({len(history_data.get('servers', {})) - len(active_servers)})</button>
                <button class="tab-btn" id="tab-all" onclick="setCategoryTab('all')">🌐 All ({len(history_data.get('servers', {}))})</button>
            </div>
            <div class="search-box">
                <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 14z"/></svg>
                <input type="text" id="search-input" placeholder="Search by name, IP, country..." onkeyup="filterServers()">
            </div>
        </div>

        <!-- MAIN SERVER TABLE (DEFAULT SORT BY INDEXED FILES) -->
        <div class="table-card">
            <div class="table-responsive">
                <table id="server-table">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)" id="th-geo">Geo ↕</th>
                            <th onclick="sortTable(1)" id="th-name">Server Name & Description ↕</th>
                            <th onclick="sortTable(2)" id="th-ip">IP:Port ↕</th>
                            <th onclick="sortTable(3)" style="text-align:right" id="th-users">Users / Capacity ↕</th>
                            <th onclick="sortTable(4)" style="text-align:right" id="th-files">Indexed Files ↕</th>
                            <th onclick="sortTable(5)" id="th-limits">File Limits / User ↕</th>
                            <th onclick="sortTable(6)" id="th-ver">Version ↕</th>
                            <th style="text-align:center" id="th-action">Actions</th>
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
            <h3 id="txt-inst-title">💡 How to use this server list in eMule / aMule</h3>
            <ol>
                <li id="txt-inst-1">Copy the direct <strong>server.met URL</strong>: <span class="code-snippet" id="met-url-display"></span></li>
                <li id="txt-inst-2">Open your <strong>eMule</strong> preferences → <strong>Server</strong> tab.</li>
                <li id="txt-inst-3">Paste the URL into <em>"Update server.met from URL"</em> or set it to auto-update on startup.</li>
                <li id="txt-inst-4">Click <strong>"📈 Analytics"</strong> on any server to view historical user trends and audit logs.</li>
            </ol>
        </div>
    </div>

    <!-- SERVER DETAILS & HISTORY MODAL -->
    <div class="modal-overlay" id="history-modal" onclick="closeModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div>
                    <h3 id="modal-server-title" style="font-size:18px;margin-bottom:4px">Server History & Analytics</h3>
                    <p id="modal-server-sub" style="font-size:12px;color:var(--text-muted)"></p>
                </div>
                <button class="modal-close" onclick="closeModalDirect()">✕</button>
            </div>

            <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">
                <span class="badge" id="modal-badge-status"></span>
                <span class="badge badge-version" id="modal-badge-ver"></span>
                <span class="badge badge-limit" id="modal-badge-seen"></span>
            </div>

            <!-- TREND CHARTS -->
            <div class="trends-grid" style="margin-bottom:20px">
                <div class="chart-container">
                    <h4 style="font-size:12px;margin-bottom:8px;color:var(--text-muted)">User Count Trend</h4>
                    <canvas id="chart-server-users" height="180"></canvas>
                </div>
                <div class="chart-container">
                    <h4 style="font-size:12px;margin-bottom:8px;color:var(--text-muted)">File Index Trend</h4>
                    <canvas id="chart-server-files" height="180"></canvas>
                </div>
            </div>

            <!-- AUDIT HISTORY LOGS -->
            <div style="margin-top:20px">
                <h4 style="font-size:14px;margin-bottom:10px;color:var(--text-main)">📜 Name & Description Change Audit Logs</h4>
                <div id="modal-audit-content"></div>
            </div>
        </div>
    </div>

    <!-- TOAST -->
    <div id="toast">✅ Copied to clipboard!</div>

    <script>
        const HISTORY_DATA = {history_json_escaped};
        const ALL_SERVERS_MAP = HISTORY_DATA.servers || {{}};

        const TRANSLATIONS = {{
            en: {{
                title: "eD2k Active Server Directory & Trends", subtitle: "Automated Real-Time Scanner & Historical Analytics • eMule & eDonkey",
                servers: "Active Servers", users: "Connected Users", files: "Indexed Files", monitored: "Total Monitored",
                heroTitle: "Auto-Updating eMule server.met", updated: "Last scan:",
                btnDownload: "Download server.met", btnCopyUrl: "Copy server.met URL", btnCopyEd2k: "Copy All eD2k Links", btnTrends: "Network Trends",
                thGeo: "Geo ↕", thName: "Server Name & Description ↕", thIp: "IP:Port ↕",
                thUsers: "Users / Capacity ↕", thFiles: "Indexed Files ↕", thLimits: "File Limits / User ↕", thVer: "Version ↕", thAction: "Actions",
                instTitle: "💡 How to use this server list in eMule / aMule",
                inst1: "Copy the direct server.met URL:", inst2: "Open your eMule preferences → Server tab.",
                inst3: "Paste the URL into 'Update server.met from URL'.", inst4: "Click '📈 Analytics' on any server to view historical user trends and audit logs.",
                btnAdd: "Add to eMule", btnAnalytics: "📈 Trends", toastCopiedLink: "📋 Server eD2k link copied!", toastCopiedMet: "📋 server.met URL copied!", toastCopiedAll: "🔗 Copied all eD2k server links!"
            }},
            fr: {{
                title: "Annuaire & Tendances des Serveurs eD2k", subtitle: "Scanner Automatique & Analyse Historique • eMule & eDonkey",
                servers: "Serveurs Actifs", users: "Utilisateurs Connectés", files: "Fichiers Indexés", monitored: "Total Surveillés",
                heroTitle: "Fichier server.met eMule Auto-Mise à Jour", updated: "Dernier scan :",
                btnDownload: "Télécharger server.met", btnCopyUrl: "Copier l'URL server.met", btnCopyEd2k: "Copier Liens eD2k", btnTrends: "Tendances Réseau",
                thGeo: "Géo ↕", thName: "Nom du Serveur & Description ↕", thIp: "IP:Port ↕",
                thUsers: "Utilisateurs / Capacité ↕", thFiles: "Fichiers Indexés ↕", thLimits: "Limites Fichiers / Client ↕", thVer: "Version ↕", thAction: "Actions",
                instTitle: "💡 Comment utiliser cette liste dans eMule / aMule",
                inst1: "Copiez l'URL directe du fichier server.met :", inst2: "Ouvrez les préférences d'eMule → Onglet Serveur.",
                inst3: "Collez l'URL dans 'Mettre à jour server.met depuis l'URL'.", inst4: "Cliquez sur '📈 Tendances' pour consulter les graphiques d'historique.",
                btnAdd: "Ajouter", btnAnalytics: "📈 Tendances", toastCopiedLink: "📋 Lien eD2k copié !", toastCopiedMet: "📋 URL server.met copiée !", toastCopiedAll: "🔗 Tous les liens eD2k copiés !"
            }},
            es: {{
                title: "Directorio y Tendencias de Servidores eD2k", subtitle: "Escáner Automático y Análisis Histórico • eMule & eDonkey",
                servers: "Servidores Activos", users: "Usuarios Conectados", files: "Archivos Indizados", monitored: "Total Monitoreados",
                heroTitle: "Archivo server.met de Actualización Automática", updated: "Última exploración:",
                btnDownload: "Descargar server.met", btnCopyUrl: "Copiar URL server.met", btnCopyEd2k: "Copiar Enlaces eD2k", btnTrends: "Tendencias Red",
                thGeo: "Geo ↕", thName: "Nombre del Servidor y Descripción ↕", thIp: "IP:Puerto ↕",
                thUsers: "Usuarios / Capacidad ↕", thFiles: "Archivos Indizados ↕", thLimits: "Límite de Archivos / Usuario ↕", thVer: "Versión ↕", thAction: "Acciones",
                instTitle: "💡 Cómo usar esta lista en eMule / aMule",
                inst1: "Copie la URL directa de server.met:", inst2: "Abra las preferencias de eMule → Pestaña Servidor.",
                inst3: "Pegue la URL en 'Actualizar server.met desde URL'.", inst4: "Haga clic en '📈 Tendencias' para ver gráficos e historial.",
                btnAdd: "Añadir", btnAnalytics: "📈 Tendencias", toastCopiedLink: "📋 ¡Enlace eD2k copiado!", toastCopiedMet: "📋 ¡URL server.met copiada!", toastCopiedAll: "🔗 ¡Todos los enlaces eD2k copiados!"
            }},
            de: {{
                title: "Aktive eD2k Serverliste & Trends", subtitle: "Automatische Echtzeit-Überprüfung & Historische Analysen • eMule",
                servers: "Aktive Server", users: "Verbundene Benutzer", files: "Indizierte Dateien", monitored: "Überwacht Gesamt",
                heroTitle: "Auto-Update eMule server.met Datei", updated: "Letzter Scan:",
                btnDownload: "server.met Herunterladen", btnCopyUrl: "server.met URL Kopieren", btnCopyEd2k: "Alle eD2k-Links Kopieren", btnTrends: "Netzwerk-Trends",
                thGeo: "Geo ↕", thName: "Servername & Beschreibung ↕", thIp: "IP:Port ↕",
                thUsers: "Benutzer / Kapazität ↕", thFiles: "Indizierte Dateien ↕", thLimits: "Dateilimits / Benutzer ↕", thVer: "Version ↕", thAction: "Aktionen",
                instTitle: "💡 Verwendung dieser Liste in eMule / aMule",
                inst1: "Kopieren Sie die direkte server.met URL:", inst2: "Öffnen Sie eMule Einstellungen → Option Server.",
                inst3: "Fügen Sie die URL bei 'server.met von URL aktualisieren' ein.", inst4: "Klicken Sie auf '📈 Trends' für historische Benutzer- und Dateidiagramme.",
                btnAdd: "Hinzufügen", btnAnalytics: "📈 Trends", toastCopiedLink: "📋 eD2k-Link kopiert!", toastCopiedMet: "📋 server.met URL kopiert!", toastCopiedAll: "🔗 Alle eD2k-Links kopiert!"
            }},
            it: {{
                title: "Elenco & Analisi Server eD2k Attivi", subtitle: "Scansione Automatica e Analisi Storica • eMule & eDonkey",
                servers: "Server Attivi", users: "Utenti Connessi", files: "File Indicizzati", monitored: "Monitorati Totali",
                heroTitle: "File server.met Auto-Aggiornante per eMule", updated: "Ultima scansione:",
                btnDownload: "Scarica server.met", btnCopyUrl: "Copia URL server.met", btnCopyEd2k: "Copia Link eD2k", btnTrends: "Tendenze Rete",
                thGeo: "Geo ↕", thName: "Nome Server e Descrizione ↕", thIp: "IP:Porta ↕",
                thUsers: "Utenti / Capacità ↕", thFiles: "File Indicizzati ↕", thLimits: "Limiti File per Utente ↕", thVer: "Versione ↕", thAction: "Azioni",
                instTitle: "💡 Come usare questo elenco in eMule / aMule",
                inst1: "Copia l'URL diretto di server.met:", inst2: "Apri le preferenze di eMule → Scheda Server.",
                inst3: "Incolla l'URL in 'Aggiorna server.met da URL'.", inst4: "Clicca su '📈 Tendenze' per visualizzare i grafici storici.",
                btnAdd: "Aggiungi", btnAnalytics: "📈 Tendenze", toastCopiedLink: "📋 Link eD2k copiato!", toastCopiedMet: "📋 URL server.met copiato!", toastCopiedAll: "🔗 Tutti i link eD2k copiati!"
            }}
        }};

        let currentLang = 'en';
        let currentTab = 'active';
        let currentServersList = [];
        let currentSortCol = 4; // DEFAULT SORT BY INDEXED FILES (COLUMN 4)
        let sortAsc = false;   // DESCENDING BY DEFAULT
        let globalUsersChart = null;
        let globalFilesChart = null;
        let serverUsersChart = null;
        let serverFilesChart = null;

        function initPage() {{
            const origin = window.location.href.split('?')[0].split('#')[0];
            const metUrl = origin.substring(0, origin.lastIndexOf('/') + 1) + 'server.met';
            document.getElementById('met-url-display').innerText = metUrl;
            
            buildServerList();
            sortTable(4, false); // Default sort by Indexed Files descending
            renderTable();

            document.addEventListener('click', function(e) {{
                const dropdown = document.getElementById('lang-dropdown');
                if (!e.target.closest('.lang-picker')) {{
                    dropdown.classList.remove('show');
                }}
            }});
        }}

        function buildServerList() {{
            const allServers = Object.values(ALL_SERVERS_MAP);
            if (currentTab === 'active') {{
                currentServersList = allServers.filter(s => s.status === 'online');
            }} else if (currentTab === 'inactive') {{
                currentServersList = allServers.filter(s => s.status === 'offline');
            }} else {{
                currentServersList = [...allServers];
            }}
        }}

        function setCategoryTab(tab) {{
            currentTab = tab;
            document.getElementById('tab-active').classList.toggle('active', tab === 'active');
            document.getElementById('tab-inactive').classList.toggle('active', tab === 'inactive');
            document.getElementById('tab-all').classList.toggle('active', tab === 'all');
            buildServerList();
            filterServers();
        }}

        function renderTable() {{
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            const t = TRANSLATIONS[currentLang] || TRANSLATIONS.en;

            currentServersList.forEach(s => {{
                const ed2kLink = `ed2k://|server|${{s.ip}}|${{s.port}}|/`;
                const isOnline = s.status === 'online';
                const maxUsers = s.max_users ? formatNum(s.max_users) : 'N/A';
                const capacityPct = s.max_users && s.max_users > 0 ? Math.min(100, Math.round((s.users / s.max_users) * 100)) : 0;
                
                const nameDisplay = s.name && s.name !== 'N/A' ? escapeHtml(s.name) : 'N/A';
                const descDisplay = s.description && s.description !== 'N/A' ? escapeHtml(s.description) : 'N/A';
                const verDisplay = s.version && s.version !== 'N/A' ? escapeHtml(s.version) : 'N/A';

                // 2-LINE FORMATTING FOR HARD / SOFT LIMITS
                let limitsHtml = '<span class="badge badge-limit">N/A</span>';
                if (s.soft_files || s.hard_files) {{
                    const softText = s.soft_files ? formatNum(s.soft_files) : 'N/A';
                    const hardText = s.hard_files ? formatNum(s.hard_files) : 'N/A';
                    limitsHtml = `
                        <div class="limits-stack">
                            <span class="badge-limit-line">Soft: ${{softText}}</span>
                            <span class="badge-limit-line">Hard: ${{hardText}}</span>
                        </div>
                    `;
                }}

                const tr = document.createElement('tr');
                if (!isOnline) tr.className = 'tr-offline';

                tr.innerHTML = `
                    <td>${{s.flag || '🌐'}}</td>
                    <td>
                        <div class="server-name-cell">
                            <span>${{nameDisplay}} ${{!isOnline ? '<span class="badge badge-status-offline">OFFLINE</span>' : ''}}</span>
                            <span class="server-desc" title="${{descDisplay}}">${{descDisplay}}</span>
                        </div>
                    </td>
                    <td class="num-font">${{s.ip}}:${{s.port}}</td>
                    <td style="text-align:right">
                        <div class="num-font" style="font-weight:700">${{formatNum(s.users)}} <span style="font-size:11px;color:var(--text-muted)">/ ${{maxUsers}}</span></div>
                        ${{s.max_users ? `<div class="capacity-bar"><div class="capacity-fill" style="width:${{capacityPct}}%"></div></div>` : ''}}
                    </td>
                    <td class="num-font" style="text-align:right;font-weight:600">${{formatNum(s.files)}}</td>
                    <td>${{limitsHtml}}</td>
                    <td><span class="badge badge-version">${{verDisplay}}</span></td>
                    <td style="text-align:center">
                        <div class="action-cell">
                            ${{isOnline ? `<a href="${{ed2kLink}}" class="btn-action-add" title="Add to eMule">➕ ${{t.btnAdd}}</a>` : ''}}
                            <button class="btn-action-history" onclick="openServerHistory('${{s.key}}')">
                                ${{t.btnAnalytics}}
                            </button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterServers() {{
            const q = document.getElementById('search-input').value.toLowerCase().trim();
            buildServerList();
            if (q) {{
                currentServersList = currentServersList.filter(s => 
                    (s.name && s.name.toLowerCase().includes(q)) ||
                    s.ip.includes(q) ||
                    (s.description && s.description.toLowerCase().includes(q)) ||
                    (s.country_name && s.country_name.toLowerCase().includes(q))
                );
            }}
            sortTable(currentSortCol, false);
        }}

        function sortTable(colIndex, toggle = true) {{
            if (toggle) {{
                if (currentSortCol === colIndex) sortAsc = !sortAsc;
                else {{ currentSortCol = colIndex; sortAsc = false; }}
            }}

            currentServersList.sort((a, b) => {{
                let valA, valB;
                switch(colIndex) {{
                    case 0: valA = a.country_name || ''; valB = b.country_name || ''; break;
                    case 1: valA = (a.name || '').toLowerCase(); valB = (b.name || '').toLowerCase(); break;
                    case 2: valA = a.ip; valB = b.ip; break;
                    case 3: valA = a.users || 0; valB = b.users || 0; break;
                    case 4: valA = a.files || 0; valB = b.files || 0; break;
                    case 5: valA = a.hard_files || a.soft_files || 9999999; valB = b.hard_files || b.soft_files || 9999999; break;
                    case 6: valA = a.version || ''; valB = b.version || ''; break;
                    default: valA = a.files || 0; valB = b.files || 0;
                }}
                if (valA < valB) return sortAsc ? -1 : 1;
                if (valA > valB) return sortAsc ? 1 : -1;
                return 0;
            }});

            renderTable();
        }}

        function toggleGlobalTrends() {{
            const panel = document.getElementById('global-trends-panel');
            const show = !panel.classList.contains('show');
            panel.classList.toggle('show', show);

            if (show && !globalUsersChart) {{
                renderGlobalCharts();
            }}
        }}

        function renderGlobalCharts() {{
            const gh = HISTORY_DATA.global_history || [];
            const labels = gh.map(p => p.timestamp.split(' ')[0]);
            const usersData = gh.map(p => p.total_users);
            const filesData = gh.map(p => p.total_files);

            const ctx1 = document.getElementById('chart-global-users').getContext('2d');
            globalUsersChart = new Chart(ctx1, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total Users',
                        data: usersData,
                        borderColor: '#6366f1',
                        backgroundColor: 'rgba(99, 102, 241, 0.15)',
                        fill: true,
                        tension: 0.3
                    }}]
                }},
                options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
            }});

            const ctx2 = document.getElementById('chart-global-files').getContext('2d');
            globalFilesChart = new Chart(ctx2, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total Files',
                        data: filesData,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.15)',
                        fill: true,
                        tension: 0.3
                    }}]
                }},
                options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
            }});
        }}

        function openServerHistory(key) {{
            const s = ALL_SERVERS_MAP[key];
            if (!s) return;

            const titleName = s.name && s.name !== 'N/A' ? escapeHtml(s.name) : 'N/A';
            document.getElementById('modal-server-title').innerHTML = `${{s.flag || '🌐'}} ${{titleName}}`;
            document.getElementById('modal-server-sub').innerText = `IP: ${{s.ip}}:${{s.port}} | Country: ${{s.country_name || 'N/A'}}`;
            
            const isOnline = s.status === 'online';
            document.getElementById('modal-badge-status').className = isOnline ? 'badge badge-status-online' : 'badge badge-status-offline';
            document.getElementById('modal-badge-status').innerText = isOnline ? '🟢 ONLINE' : '🔴 OFFLINE';
            
            document.getElementById('modal-badge-ver').innerText = `Version: ${{s.version || 'N/A'}}`;
            document.getElementById('modal-badge-seen').innerText = `First Seen: ${{s.first_seen || 'N/A'}} • Last Seen: ${{s.last_seen || 'N/A'}}`;

            const auditBox = document.getElementById('modal-audit-content');
            let auditHtml = '';

            if (s.name_history && s.name_history.length > 1) {{
                auditHtml += '<h5 style="font-size:12px;color:var(--primary);margin-bottom:6px">Name Change History</h5><ul class="audit-list">';
                s.name_history.forEach(nh => {{
                    auditHtml += `<li class="audit-item"><div class="audit-date">📅 ${{nh.timestamp}}</div><strong>${{escapeHtml(nh.name)}}</strong></li>`;
                }});
                auditHtml += '</ul>';
            }}

            if (s.desc_history && s.desc_history.length > 1) {{
                auditHtml += '<h5 style="font-size:12px;color:var(--accent-cyan);margin-top:10px;margin-bottom:6px">Description Change History</h5><ul class="audit-list">';
                s.desc_history.forEach(dh => {{
                    auditHtml += `<li class="audit-item"><div class="audit-date">📅 ${{dh.timestamp}}</div>${{escapeHtml(dh.description)}}</li>`;
                }});
                auditHtml += '</ul>';
            }}

            if (!auditHtml) {{
                auditHtml = '<p style="font-size:12.5px;color:var(--text-muted)">No name or description changes recorded yet for this server.</p>';
            }}
            auditBox.innerHTML = auditHtml;

            const metrics = s.metrics || [];
            const labels = metrics.map(m => m.timestamp.split(' ')[0]);
            const usersData = metrics.map(m => m.users);
            const filesData = metrics.map(m => m.files);

            if (serverUsersChart) serverUsersChart.destroy();
            if (serverFilesChart) serverFilesChart.destroy();

            const ctxUsers = document.getElementById('chart-server-users').getContext('2d');
            serverUsersChart = new Chart(ctxUsers, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Users',
                        data: usersData,
                        borderColor: '#6366f1',
                        backgroundColor: 'rgba(99, 102, 241, 0.2)',
                        fill: true, tension: 0.3
                    }}]
                }},
                options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
            }});

            const ctxFiles = document.getElementById('chart-server-files').getContext('2d');
            serverFilesChart = new Chart(ctxFiles, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Files',
                        data: filesData,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.2)',
                        fill: true, tension: 0.3
                    }}]
                }},
                options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
            }});

            document.getElementById('history-modal').classList.add('show');
        }}

        function closeModalDirect() {{
            document.getElementById('history-modal').classList.remove('show');
        }}

        function closeModal(e) {{
            if (e.target.classList.contains('modal-overlay')) closeModalDirect();
        }}

        function toggleLangDropdown(e) {{
            e.stopPropagation();
            document.getElementById('lang-dropdown').classList.toggle('show');
        }}

        function selectLang(code, name, flag) {{
            currentLang = code;
            document.getElementById('current-lang-text').innerText = name;
            document.getElementById('current-flag').src = `https://flagcdn.io/${{flag}}.svg`;
            document.getElementById('lang-dropdown').classList.remove('show');
            applyLanguage(code);
        }}

        function formatNum(n) {{
            return n !== null && n !== undefined && n !== 0 ? n.toLocaleString() : 'N/A';
        }}

        function applyLanguage(lang) {{
            const t = TRANSLATIONS[lang] || TRANSLATIONS.en;
            document.getElementById('txt-title').innerText = t.title;
            document.getElementById('txt-subtitle').innerText = t.subtitle;
            document.getElementById('lbl-servers').innerText = t.servers;
            document.getElementById('lbl-users').innerText = t.users;
            document.getElementById('lbl-files').innerText = t.files;
            document.getElementById('lbl-monitored').innerText = t.monitored;
            document.getElementById('txt-hero-title').innerText = t.heroTitle;
            document.getElementById('txt-updated').innerText = t.updated;
            document.getElementById('txt-btn-download').innerText = t.btnDownload;
            document.getElementById('txt-btn-copy-url').innerText = t.btnCopyUrl;
            document.getElementById('txt-btn-copy-ed2k').innerText = t.btnCopyEd2k;
            document.getElementById('txt-btn-trends').innerText = t.btnTrends;
            document.getElementById('th-geo').innerText = t.thGeo;
            document.getElementById('th-name').innerText = t.thName;
            document.getElementById('th-ip').innerText = t.thIp;
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
            renderTable();
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
            const t = TRANSLATIONS[currentLang] || TRANSLATIONS.en;
            const metUrl = document.getElementById('met-url-display').innerText;
            navigator.clipboard.writeText(metUrl).then(() => showToast(t.toastCopiedMet));
        }}

        function copyAllEd2k() {{
            const t = TRANSLATIONS[currentLang] || TRANSLATIONS.en;
            const activeServers = Object.values(ALL_SERVERS_MAP).filter(s => s.status === 'online');
            const links = activeServers.map(s => `ed2k://|server|${{s.ip}}|${{s.port}}|/`).join('\\n');
            navigator.clipboard.writeText(links).then(() => showToast(t.toastCopiedAll));
        }}

        function escapeHtml(str) {{
            if (!str) return 'N/A';
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
    print("   Active eD2k Server Harvester, Historical Analytics & Portal           ")
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
                    print(f"  [ONLINE] {ip}:{port} | {res['name']} | {res['users']:,} users | {res['files']:,} files")
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

    candidate_servers.update(newly_discovered_peers)
    update_servers_txt(INPUT_FILE, candidate_servers)

    # 5. Enrich active servers with GeoIP location data
    enrich_with_geo(active_servers)

    # 6. Historical Data Management
    print("\n--- Updating Historical Analytics & Audit Log Database ---")
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    history_mgr = HistoryManager(HISTORY_FILE)
    history_mgr.update(active_servers, candidate_servers, now_utc)
    history_mgr.save()

    # 7. Sort active servers by Indexed Files descending by default
    active_servers.sort(key=lambda s: (s.get("files", 0), s.get("users", 0)), reverse=True)

    # 8. Generate Output Files
    print("\n--- Generating Directory Artefacts ---")
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

    generate_html(HTML_FILE, active_servers, history_mgr.data, stats_meta)
    print(f"  [+] Generated Glassmorphism HTML Portal & Analytics: {HTML_FILE}")

    print("\n==========================================================================")
    print(f"   SUCCESS! Directory updated with {len(active_servers)} active eD2k servers.")
    print("==========================================================================")

if __name__ == "__main__":
    main()
