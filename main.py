import socket
import struct
import os
import datetime
import urllib.request
import json
import random

# --- CONFIGURATION ---
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def ip_to_int(ip):
    packed = socket.inet_aton(ip)
    return struct.unpack("<I", packed)[0]

# --- LOGIQUE GeoIP (BATCH OPTIMISÉ) ---
def enrich_with_geo(servers):
    if not servers: return
    
    for i in range(0, len(servers), 100):
        chunk = servers[i:i+100]
        queries = [{"query": s["ip"], "fields": "countryCode"} for s in chunk]
        
        try:
            req = urllib.request.Request("http://ip-api.com/batch")
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'Mozilla/5.0')
            jsondata = json.dumps(queries).encode('utf-8')
            
            with urllib.request.urlopen(req, data=jsondata, timeout=5) as response:
                results = json.loads(response.read().decode())
                
                for s, res in zip(chunk, results):
                    code = res.get("countryCode", "XX")
                    s["country_code"] = code
                    if code != "XX":
                        s["flag"] = f'<img src="https://flagcdn.io/{code.lower()}.svg" width="24" height="18" alt="{code}" style="vertical-align: middle; border-radius: 2px; box-shadow: 0 0 2px rgba(0,0,0,0.3);">'
                    else:
                        s["flag"] = "❓"
        except Exception as e:
            print(f"Erreur GeoIP Batch : {e}")
            for s in chunk:
                s["country_code"], s["flag"] = "XX", "❓"

# --- LOGIQUE eD2K (UDP Uniquement) ---
def parse_ed2k_tags(payload, offset, num_tags):
    tags = {}
    for _ in range(num_tags):
        if offset >= len(payload): break
        tag_type = payload[offset] & 0x7F
        offset += 1
        if offset + 2 > len(payload): break
        name_len = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        if offset + name_len > len(payload): break
        
        name = payload[offset] if name_len == 1 else None
        offset += name_len
            
        val = None
        if tag_type == 0x02: # String
            val_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            try: val = payload[offset:offset+val_len].decode('utf-8', errors='ignore')
            except: val = payload[offset:offset+val_len].decode('latin1', errors='ignore')
            offset += val_len
        elif tag_type == 0x03: # Uint32
            val = struct.unpack_from("<I", payload, offset)[0]
            offset += 4
        else:
            break
            
        if name is not None and val is not None:
            tags[name] = val
    return tags

def get_server_info(ip, tcp_port):
    udp_port = tcp_port + 4
    info = {
        'active': False, 'name': 'Inconnu', 'desc': 'Aucune description', 
        'version': 'Inconnue', 'users': 0, 'files': 0
    }
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    challenge_stat = random.randint(1, 0xFFFFFFFF)
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0x96, challenge_stat), (ip, udp_port))
        data, _ = sock.recvfrom(1024)
        if len(data) >= 14 and data[0] == 0xE3 and data[1] == 0x97: 
            resp_challenge, users, files = struct.unpack_from("<III", data, 2)
            if resp_challenge == challenge_stat:
                info['users'], info['files'] = users, files
    except Exception: pass
                
    challenge_desc = (random.randint(1, 65535) << 16) | 0xF0FF
    try:
        sock.sendto(struct.pack("<BBI", 0xE3, 0xA2, challenge_desc), (ip, udp_port))
        data, _ = sock.recvfrom(4096)
        if len(data) >= 10 and data[0] == 0xE3 and data[1] == 0xA3: 
            resp_challenge = struct.unpack_from("<I", data, 2)[0]
            if resp_challenge == challenge_desc:
                tag_count = struct.unpack_from("<I", data, 6)[0]
                tags = parse_ed2k_tags(data, 10, tag_count)
                
                if 0x01 in tags: info['name'] = str(tags[0x01])
                if 0x0B in tags: info['desc'] = str(tags[0x0B])
                if 0x91 in tags:
                    v = tags[0x91]
                    info['version'] = f"{v >> 16}.{v & 0xFFFF}" if isinstance(v, int) else str(v)
    except Exception: pass
    finally: sock.close()
        
    if info['users'] > 0 or info['name'] != 'Inconnu':
        info['active'] = True
        
    return info if info['active'] else None

# --- GÉNÉRATION FICHIER BINAIRE (CORRIGÉE SELON CODE SOURCE aMule) ---
def write_tag_string_id(tag_id, value):
    """Encode un tag String avec un identifiant numérique (ID).
       Format attendu dans un fichier .met (Type 0x02, NameLength = 1, Name = ID)"""
    val_bytes = str(value).encode('utf-8', errors='ignore')
    tag = struct.pack("<B H B H", 2, 1, tag_id, len(val_bytes))
    tag += val_bytes
    return tag

def write_tag_uint32_name(name_str, value):
    """Encode un tag Uint32 avec un nom textuel (String Name).
       Obligatoire pour "files" et "users" selon le parseur C++."""
    name_bytes = name_str.encode('ascii')
    # Type 0x03, Longueur du nom, Nom en string, Valeur sur 4 octets
    tag = struct.pack("<B H", 3, len(name_bytes))
    tag += name_bytes
    tag += struct.pack("<I", int(value))
    return tag

def generate_server_met(servers):
    with open(MET_FILE, "wb") as f:
        f.write(struct.pack("<B", 0xE0)) # Header eD2k
        f.write(struct.pack("<I", len(servers))) # Nombre de serveurs
        
        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s['ip'])))
            f.write(struct.pack("<H", s['port']))
            
            tags = []
            stats = s['stats']
            
            # Tags standards utilisant des IDs
            if stats.get('name'): 
                tags.append(write_tag_string_id(1, stats['name'])) # ST_SERVERNAME
            if stats.get('desc'): 
                tags.append(write_tag_string_id(11, stats['desc'])) # ST_DESCRIPTION
            if stats.get('version') and stats['version'] != 'Inconnue': 
                tags.append(write_tag_string_id(17, stats['version'])) # ST_VERSION
            
            # Tags obligatoirement textuels (cf. bloc default du fichier C++)
            if stats.get('users'): 
                tags.append(write_tag_uint32_name("users", stats['users']))
            if stats.get('files'): 
                tags.append(write_tag_uint32_name("files", stats['files']))
                
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
    <link rel="icon" type="image/svg+xml" href="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg">
    <style>
        :root {{ --bg: #f4f4f9; --text: #333; --primary: #3498db; --header: #2c3e50; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        
        .top-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }}
        h1 {{ color: var(--header); margin: 0; font-size: 24px; display: flex; align-items: center; }}
        
        .lang-selector {{ display: flex; gap: 10px; }}
        .lang-selector img {{ cursor: pointer; border-radius: 3px; box-shadow: 0 1px 3px rgba(0,0,0,0.2); transition: transform 0.2s, box-shadow 0.2s; }}
        .lang-selector img:hover {{ transform: scale(1.1); box-shadow: 0 2px 5px rgba(0,0,0,0.4); }}
        
        .info-panel {{ background: #e8f4fd; padding: 15px; border-left: 4px solid var(--primary); border-radius: 4px; margin-bottom: 20px; font-size: 14px; }}
        .btn {{ display: inline-block; padding: 10px 18px; background: var(--primary); color: white; text-decoration: none; border-radius: 6px; font-weight: bold; transition: background 0.3s; }}
        .btn:hover {{ background: #2980b9; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 12px 15px; border-bottom: 1px solid #eee; text-align: left; }}
        th {{ background: var(--header); color: white; cursor: pointer; user-select: none; transition: background 0.2s; white-space: nowrap; }}
        th:hover {{ background: #34495e; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .num {{ font-family: monospace; font-size: 13px; text-align: right; }}
        .desc-col {{ max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .tag {{ font-size: 11px; background: #eee; padding: 3px 6px; border-radius: 4px; margin-left: 5px; color: #555; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1>
                <img src="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg" alt="eMule" width="40" height="40" style="margin-right: 12px;">
                <span id="page-title">Active eD2k Servers</span>
            </h1>
            <div class="lang-selector">
                <img src="https://flagcdn.io/gb.svg" width="24" height="18" alt="English" title="English" onclick="changeLang('en')">
                <img src="https://flagcdn.io/fr.svg" width="24" height="18" alt="Français" title="Français" onclick="changeLang('fr')">
                <img src="https://flagcdn.io/es.svg" width="24" height="18" alt="Español" title="Español" onclick="changeLang('es')">
            </div>
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
                        <th onclick="sortTable(3)" id="th-version">Version ↕</th>
                        <th onclick="sortTable(4)" id="th-ip">IP:Port ↕</th>
                        <th onclick="sortTable(5)" style="text-align:right" id="th-users">Users ↕</th>
                        <th onclick="sortTable(6)" style="text-align:right" id="th-files">Files ↕</th>
                    </tr>
                </thead>
                <tbody>"""

    for s in servers:
        html += f"""
                    <tr>
                        <td title="{s['country_code']}">{s['flag']}</td>
                        <td style="font-weight: bold;">{s['stats']['name']}</td>
                        <td class="desc-col" title="{s['stats']['desc']}">{s['stats']['desc']}</td>
                        <td><span class="tag">{s['stats']['version']}</span></td>
                        <td class="num">{s['ip']}:{s['port']}</td>
                        <td class="num">{s['stats']['users']:,}</td>
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
                title: "Active eD2k Servers", update: "Last update:", download: "⬇️ Download server.met", copy: "Copy this file's URL into your eMule settings for automatic updates.",
                thFlag: "Geo ↕", thName: "Name ↕", thDesc: "Description ↕", thVersion: "Version ↕", thIP: "IP:Port ↕", thUsers: "Users ↕", thFiles: "Files ↕"
            },
            fr: {
                title: "Serveurs eD2k Actifs", update: "Dernière mise à jour :", download: "⬇️ Télécharger server.met", copy: "Copiez l'URL de ce fichier dans les paramètres d'eMule pour la mise à jour automatique.",
                thFlag: "Géo ↕", thName: "Nom ↕", thDesc: "Description ↕", thVersion: "Version ↕", thIP: "IP:Port ↕", thUsers: "Utilisateurs ↕", thFiles: "Fichiers ↕"
            },
            es: {
                title: "Servidores eD2k Activos", update: "Última actualización:", download: "⬇️ Descargar server.met", copy: "Copie la URL de este archivo en eMule para actualizaciones automáticas.",
                thFlag: "Geo ↕", thName: "Nombre ↕", thDesc: "Descripción ↕", thVersion: "Versión ↕", thIP: "IP:Puerto ↕", thUsers: "Usuarios ↕", thFiles: "Archivos ↕"
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
            document.getElementById("th-version").innerText = t.thVersion;
            document.getElementById("th-ip").innerText = t.thIP;
            document.getElementById("th-users").innerText = t.thUsers;
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
</html>
"""
    
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    ensure_dir(OUTPUT_DIR)
    if not os.path.exists(INPUT_FILE):
        print(f"Fichier {INPUT_FILE} introuvable.")
        return
    
    active_servers = []
    
    print("--- 1. Analyse des serveurs eD2k (UDP) ---")
    with open(INPUT_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            
            try:
                ip, port_str = line.split(":")
                port = int(port_str)
                
                stats = get_server_info(ip, port)
                if stats:
                    print(f"  ✅ Actif : {ip}:{port} | {stats['name']} | {stats['files']} fichiers")
                    active_servers.append({
                        "ip": ip,
                        "port": port,
                        "stats": stats
                    })
                else:
                    print(f"  ❌ Hors ligne : {ip}:{port}")
                    
            except Exception as e:
                print(f"Erreur locale avec '{line}': {e}")
                
    if active_servers:
        print("\n--- 2. Résolution des drapeaux (Batch API) ---")
        enrich_with_geo(active_servers)
        
        print("\n--- 3. Tri et Génération ---")
        active_servers.sort(key=lambda s: s['stats']['files'], reverse=True)
        
        generate_server_met(active_servers)
        generate_html(active_servers)
        print(f"\nTerminé avec succès. {len(active_servers)} serveurs publiés.")
    else:
        print("\nAucun serveur actif trouvé, génération annulée.")

if __name__ == "__main__":
    main()
