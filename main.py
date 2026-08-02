import socket
import struct
import os
import datetime
import urllib.request
import json
import time
import sys
import zlib
import random

# --- CONFIGURATION ---
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")
TIMEOUT = 4.0 # Secondes d'attente max

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def ip_to_int(ip):
    packed = socket.inet_aton(ip)
    return struct.unpack("<I", packed)[0]

def get_country_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            code = data.get("countryCode", "XX")
            if code == "XX": return "❓", "XX"
            flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
            return flag, code
    except:
        return "❓", "XX"

# --- LOGIQUE eD2K (Parseur UDP/TCP) ---
def parse_ed2k_tags(payload, offset, num_tags):
    """Décode les Tags eDonkey/eMule (TLV) avec gestion stricte du bit 0x80 (bNameIsID)"""
    tags = {}
    for _ in range(num_tags):
        if offset >= len(payload): break
            
        tag_type_full = payload[offset]
        offset += 1
        
        bNameIsID = (tag_type_full & 0x80) != 0
        tag_type = tag_type_full & 0x7F 
        
        name = None
        if bNameIsID:
            if offset + 1 > len(payload): break
            name = payload[offset]
            offset += 1
        else:
            if offset + 2 > len(payload): break
            name_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if offset + name_len > len(payload): break
            
            if name_len == 1:
                name = payload[offset]
            else:
                name = payload[offset:offset+name_len].decode('latin1', errors='ignore')
            offset += name_len
            
        val = None
        if tag_type == 0x01: # Hash
            if offset + 16 > len(payload): break
            val = payload[offset:offset+16]
            offset += 16
        elif tag_type == 0x02: # String
            if offset + 2 > len(payload): break
            val_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if offset + val_len > len(payload): break
            try:
                val = payload[offset:offset+val_len].decode('utf-8')
            except UnicodeDecodeError:
                val = payload[offset:offset+val_len].decode('latin1', errors='ignore')
            offset += val_len
        elif tag_type == 0x03: # Uint32
            if offset + 4 > len(payload): break
            val = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
        elif tag_type == 0x04: # Float32
            if offset + 4 > len(payload): break
            val = struct.unpack_from("<f", payload, offset)[0]
            offset += 4
        elif tag_type == 0x08: # Uint16
            if offset + 2 > len(payload): break
            val = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
        elif tag_type == 0x09: # Uint8
            if offset + 1 > len(payload): break
            val = payload[offset]
            offset += 1
        elif tag_type in (0x11, 0x07): # Blob
            if offset + 4 > len(payload): break
            val_len = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
            if offset + val_len > len(payload): break
            val = payload[offset:offset+val_len]
            offset += val_len
        else:
            break
            
        if name is not None:
            tags[name] = val
        
    return tags, offset

def get_server_info_udp(ip, tcp_port):
    """Interrogation UDP de aMule"""
    udp_port = tcp_port + 4
    info = {
        'active': False, 'users': 0, 'files': 0, 'max_users': 0, 
        'name': f'Server ({ip})', 'desc': 'Aucune description', 'method': f'UDP'
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    # Statistiques
    challenge_stat = random.randint(1, 0xFFFFFFFF)
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0x96, challenge_stat), (ip, udp_port))
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) >= 14 and data[0] == 0xE3 and data[1] == 0x97: 
                    resp_challenge, users, files = struct.unpack_from("<III", data, 2)
                    if resp_challenge == challenge_stat:
                        info['users'], info['files'] = users, files
                        if len(data) >= 18:
                            info['max_users'] = struct.unpack_from("<I", data, 14)[0]
                        info['active'] = True
                        break
            except socket.timeout: break
    except: pass
                
    # Description
    challenge_desc = (random.randint(1, 65535) << 16) | 0xF0FF
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0xA2, challenge_desc), (ip, udp_port))
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data, _ = sock.recvfrom(4096)
                if len(data) >= 2 and data[0] == 0xE3 and data[1] == 0xA3: 
                    if len(data) >= 6:
                        resp_challenge = struct.unpack_from("<I", data, 2)[0]
                        if resp_challenge == challenge_desc and len(data) >= 10:
                            tag_count = struct.unpack_from("<I", data, 6)[0]
                            tags, _ = parse_ed2k_tags(data, 10, tag_count)
                            if 0x01 in tags: info['name'] = str(tags[0x01])
                            if 0x0B in tags: info['desc'] = str(tags[0x0B])
                    info['active'] = True
                    break
            except socket.timeout: break
    except: pass
    finally: sock.close()
        
    return info if info['active'] else None

def get_server_info_tcp(ip, port):
    """Fallback TCP"""
    info = {
        'active': False, 'users': 0, 'files': 0, 'max_users': 0, 
        'name': f'Server ({ip})', 'desc': 'Aucune description', 'method': 'TCP'
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    
    try:
        sock.connect((ip, port))
        
        username = b"http://www.emule-project.net"
        tag_user = struct.pack("<BHB", 0x02, 1, 0x01) + struct.pack("<H", len(username)) + username
        tags_data = tag_user + struct.pack("<BHBI", 0x03, 1, 0x11, 0x3C) + struct.pack("<BHBI", 0x03, 1, 0x0F, 4662) + struct.pack("<BHBI", 0x03, 1, 0xFB, 0x003C0000) + struct.pack("<BHBI", 0x03, 1, 0x20, 0x1D)
        
        payload = struct.pack("<16sIHI", os.urandom(16), 0, 4662, 5) + tags_data
        sock.send(struct.pack("<BI", 0xE3, len(payload) + 1) + struct.pack("<B", 0x01) + payload)
        
        start_time = time.time()
        found_status = found_ident = False
        
        while time.time() - start_time < 5.0:
            if found_status and found_ident: break
            try: header = sock.recv(5)
            except socket.timeout: break
            if not header or len(header) < 5: break
                
            protocol, packet_len = struct.unpack("<BI", header)
            if packet_len == 0 or packet_len > 1024*1024: continue
                
            data = b""
            while len(data) < packet_len:
                chunk = sock.recv(min(packet_len - len(data), 4096))
                if not chunk: break
                data += chunk
            if len(data) < packet_len: break
                
            if protocol == 0xD4:
                try: data = zlib.decompress(data)
                except: continue

            if not data: continue
            pkt_opcode, pkt_payload = data[0], data[1:]
            
            if pkt_opcode == 0x05: 
                break
            elif pkt_opcode == 0x18: break
            elif pkt_opcode == 0x34:
                if len(pkt_payload) >= 8:
                    info['users'], info['files'] = struct.unpack("<II", pkt_payload[:8])
                    found_status = True
            elif pkt_opcode == 0x32:
                if len(pkt_payload) >= 26:
                    tag_count = struct.unpack_from("<I", pkt_payload, 22)[0]
                    tags, _ = parse_ed2k_tags(pkt_payload, 26, tag_count)
                    if 0x01 in tags: info['name'] = str(tags[0x01])
                    if 0x0B in tags: info['desc'] = str(tags[0x0B])
                    found_ident = True
                    
        if found_status or found_ident: info['active'] = True
    except: pass
    finally: sock.close()
        
    return info if info['active'] else None

def get_server_info(ip, port):
    info = get_server_info_udp(ip, port)
    if info: return info
    return get_server_info_tcp(ip, port)

# --- GÉNÉRATION FICHIERS ---
def write_tag_string_id(tag_id, value):
    val_bytes = value.encode('utf-8', errors='ignore')
    tag = struct.pack("<B H B H", 2, 1, tag_id, len(val_bytes))
    tag += val_bytes
    return tag

def generate_server_met(servers):
    with open(MET_FILE, "wb") as f:
        f.write(struct.pack("<B", 0xE0))
        f.write(struct.pack("<I", len(servers)))
        
        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s['ip'])))
            f.write(struct.pack("<H", s['port']))
            
            tags = []
            if s['stats']['name']: tags.append(write_tag_string_id(1, s['stats']['name']))
            if s['stats']['desc']: tags.append(write_tag_string_id(2, s['stats']['desc']))
                
            f.write(struct.pack("<I", len(tags)))
            for tag in tags:
                f.write(tag)

def generate_html(servers):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active eD2k Servers</title>
    <style>
        :root {{ --bg: #f4f4f9; --text: #333; --primary: #3498db; --header: #2c3e50; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        
        .top-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }}
        h1 {{ color: var(--header); margin: 0; font-size: 24px; }}
        select#lang {{ padding: 8px; border-radius: 5px; border: 1px solid #ccc; font-size: 14px; cursor: pointer; }}
        
        .info-panel {{ background: #e8f4fd; padding: 15px; border-left: 4px solid var(--primary); border-radius: 4px; margin-bottom: 20px; font-size: 14px; }}
        .btn {{ display: inline-block; padding: 10px 18px; background: var(--primary); color: white; text-decoration: none; border-radius: 6px; font-weight: bold; transition: background 0.3s; }}
        .btn:hover {{ background: #2980b9; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 12px 15px; border-bottom: 1px solid #eee; text-align: left; }}
        th {{ background: var(--header); color: white; cursor: pointer; user-select: none; transition: background 0.2s; white-space: nowrap; }}
        th:hover {{ background: #34495e; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .num {{ font-family: monospace; font-size: 13px; text-align: right; }}
        .desc-col {{ max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .tag {{ font-size: 10px; background: #ddd; padding: 2px 5px; border-radius: 3px; margin-left: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1 id="page-title">🌐 Active eD2k Servers</h1>
            <select id="lang" onchange="changeLang(this.value)">
                <option value="en">🇬🇧 English</option>
                <option value="fr">🇫🇷 Français</option>
                <option value="es">🇪🇸 Español</option>
            </select>
        </div>

        <div class="info-panel">
            <p><span id="txt-update">Last update:</span> <strong>{now}</strong> UTC</p>
            <a href="server.met" class="btn" id="btn-download">⬇️ Download server.met</a>
            <p style="margin-bottom: 0; color: #555;"><i id="txt-copy">Copy this file's URL into your eMule settings for automatic updates.</i></p>
        </div>
        
        <div style="overflow-x:auto;">
            <table id="server-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)" id="th-flag">Geo ↕</th>
                        <th onclick="sortTable(1)" id="th-name">Name ↕</th>
                        <th onclick="sortTable(2)" id="th-desc">Description ↕</th>
                        <th onclick="sortTable(3)" id="th-ip">IP:Port ↕</th>
                        <th onclick="sortTable(4)" style="text-align:right" id="th-users">Users ↕</th>
                        <th onclick="sortTable(5)" style="text-align:right" id="th-max">Max Users ↕</th>
                        <th onclick="sortTable(6)" style="text-align:right" id="th-files">Files ↕</th>
                    </tr>
                </thead>
                <tbody>"""

    for s in servers:
        meth_tag = f'<span class="tag">{s["stats"]["method"]}</span>'
        html += f"""
                    <tr>
                        <td title="{s['country_code']}">{s['flag']}</td>
                        <td style="font-weight: bold;">{s['stats']['name']} {meth_tag}</td>
                        <td class="desc-col" title="{s['stats']['desc']}">{s['stats']['desc']}</td>
                        <td class="num">{s['ip']}:{s['port']}</td>
                        <td class="num">{s['stats']['users']:,}</td>
                        <td class="num">{s['stats']['max_users']:,}</td>
                        <td class="num">{s['stats']['files']:,}</td>
                    </tr>"""
    
    html += """
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const translations = {
            en: {
                title: "🌐 Active eD2k Servers", update: "Last update:", download: "⬇️ Download server.met", copy: "Copy this file's URL into your eMule settings for automatic updates.",
                thFlag: "Geo ↕", thName: "Name ↕", thDesc: "Description ↕", thIP: "IP:Port ↕", thUsers: "Users ↕", thMax: "Max Users ↕", thFiles: "Files ↕"
            },
            fr: {
                title: "🌐 Serveurs eD2k Actifs", update: "Dernière mise à jour :", download: "⬇️ Télécharger server.met", copy: "Copiez l'URL de ce fichier dans les paramètres d'eMule pour la mise à jour automatique.",
                thFlag: "Géo ↕", thName: "Nom ↕", thDesc: "Description ↕", thIP: "IP:Port ↕", thUsers: "Utilisateurs ↕", thMax: "Max Utilisateurs ↕", thFiles: "Fichiers ↕"
            },
            es: {
                title: "🌐 Servidores eD2k Activos", update: "Última actualización:", download: "⬇️ Descargar server.met", copy: "Copie la URL de este archivo en eMule para actualizaciones automáticas.",
                thFlag: "Geo ↕", thName: "Nombre ↕", thDesc: "Descripción ↕", thIP: "IP:Puerto ↕", thUsers: "Usuarios ↕", thMax: "Máx Usuarios ↕", thFiles: "Archivos ↕"
            }
        };

        function changeLang(lang) {
            const t = translations[lang];
            document.getElementById("page-title").innerText = t.title;
            document.getElementById("txt-update").innerText = t.update;
            document.getElementById("btn-download").innerText = t.download;
            document.getElementById("txt-copy").innerText = t.copy;
            document.getElementById("th-flag").innerText = t.thFlag;
            document.getElementById("th-name").innerText = t.thName;
            document.getElementById("th-desc").innerText = t.thDesc;
            document.getElementById("th-ip").innerText = t.thIP;
            document.getElementById("th-users").innerText = t.thUsers;
            document.getElementById("th-max").innerText = t.thMax;
            document.getElementById("th-files").innerText = t.thFiles;
        }

        function sortTable(n) {
            const table = document.getElementById("server-table");
            let rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            switching = true; dir = "asc"; 
            
            while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    
                    let valX = x.innerHTML.toLowerCase().replace(/,/g, '').replace(/<[^>]*>?/gm, '').trim();
                    let valY = y.innerHTML.toLowerCase().replace(/,/g, '').replace(/<[^>]*>?/gm, '').trim();
                    
                    if (!isNaN(parseFloat(valX)) && !isNaN(parseFloat(valY))) {
                        valX = parseFloat(valX); valY = parseFloat(valY);
                    }
                    
                    if (dir == "asc") { if (valX > valY) { shouldSwitch = true; break; } } 
                    else if (dir == "desc") { if (valX < valY) { shouldSwitch = true; break; } }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true; switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc"; switching = true;
                    }
                }
            }
        }
    </script>
</body>
</html>"""
    
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    ensure_dir(OUTPUT_DIR)
    if not os.path.exists(INPUT_FILE):
        print(f"Fichier {INPUT_FILE} introuvable.")
        return
    
    active_servers = []
    
    with open(INPUT_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            
            try:
                ip, port_str = line.split(":")
                port = int(port_str)
                
                print(f"Test de {ip}:{port}...")
                stats = get_server_info(ip, port)
                
                if stats:
                    print(f"  -> Actif ✅ | {stats['method']} | {stats['name']} | {stats['users']} users")
                    
                    flag, country_code = get_country_info(ip)
                    
                    active_servers.append({
                        "ip": ip,
                        "port": port,
                        "flag": flag,
                        "country_code": country_code,
                        "stats": stats
                    })
                    time.sleep(1.5)
                else:
                    print("  -> Hors ligne ❌")
                    
            except Exception as e:
                print(f"Erreur avec '{line}': {e}")
                
    print(f"\nTerminé. {len(active_servers)} serveurs actifs.")
    
    if active_servers:
        generate_server_met(active_servers)
        generate_html(active_servers)
    else:
        print("Aucun serveur actif, pas de mise à jour des fichiers.")

if __name__ == "__main__":
    main()
