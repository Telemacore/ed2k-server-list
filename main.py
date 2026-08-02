import socket
import struct
import os
import datetime
import urllib.request
import json
import time

# --- CONFIGURATION ---
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")
TIMEOUT = 4.0 # Secondes pour la poignée de main TCP eD2k

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

def parse_ed2k_tags(data):
    """Décode les tags binaires eD2k pour extraire le Nom et la Description"""
    tags = {}
    try:
        if len(data) < 4: return tags
        count = struct.unpack("<I", data[:4])[0]
        offset = 4
        for _ in range(count):
            if offset >= len(data): break
            t_type = data[offset]
            offset += 1
            
            if offset + 2 > len(data): break
            name_len = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            
            if offset + name_len > len(data): break
            name = data[offset:offset+name_len]
            offset += name_len
            
            val = None
            if t_type == 2: # Tag de type String
                if offset + 2 > len(data): break
                val_len = struct.unpack("<H", data[offset:offset+2])[0]
                offset += 2
                if offset + val_len > len(data): break
                val_bytes = data[offset:offset+val_len]
                offset += val_len
                try:
                    val = val_bytes.decode('utf-8')
                except:
                    val = val_bytes.decode('latin1', errors='ignore')
            elif t_type == 3: # Tag de type Integer (32 bit)
                if offset + 4 > len(data): break
                val = struct.unpack("<I", data[offset:offset+4])[0]
                offset += 4
            elif t_type == 8: # Tag de type Integer (16 bit)
                if offset + 2 > len(data): break
                val = struct.unpack("<H", data[offset:offset+2])[0]
                offset += 2
            elif t_type == 9: # Tag de type Integer (8 bit)
                if offset + 1 > len(data): break
                val = struct.unpack("<B", data[offset:offset+1])[0]
                offset += 1
            else:
                break # Type inconnu, on stoppe la lecture pour éviter un décalage
                
            if val is not None:
                tags[name] = val
    except:
        pass
    return tags

def probe_ed2k_server(ip, port):
    """Se connecte au serveur et effectue le handshake eD2k pour obtenir les infos réelles"""
    stats = {
        "active": False,
        "name": f"Server ({ip})",
        "desc": "Aucune description",
        "users": 0,
        "max_users": 0,
        "files": 0
    }
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        
        # 1. Construction du paquet "Login Request" (Simule un client eMule)
        user_hash = os.urandom(16)
        client_name = b"GitHub_ServerProbe"
        # Tag Nom Client
        t_name = struct.pack("<B H B H", 2, 1, 1, len(client_name)) + client_name
        # Tag Version (0x3C = eMule 0.60)
        t_version = struct.pack("<B H B I", 3, 1, 0x11, 0x3C)
        tags = t_name + t_version
        
        payload = struct.pack("<16s I H I", user_hash, 0, 4662, 2) + tags
        packet = b'\x01' + payload # 0x01 = OP_LOGINREQUEST
        s.sendall(struct.pack("<B I", 0xE3, len(packet)) + packet)
        
        # 2. Écoute des réponses du serveur
        start_time = time.time()
        got_status = False
        got_ident = False
        
        while time.time() - start_time < TIMEOUT:
            if got_status and got_ident:
                break
                
            hdr = s.recv(5)
            if len(hdr) < 5: break
            magic, size = struct.unpack("<B I", hdr)
            
            # 0xE3 (eDonkey) ou 0xC5 (eMule)
            if magic not in (0xE3, 0xC5) or size > 65536: 
                break
            
            data = b""
            while len(data) < size:
                chunk = s.recv(min(4096, size - len(data)))
                if not chunk: break
                data += chunk
            
            if not data: break
            
            opcode = data[0]
            payload = data[1:]
            
            if opcode == 0x34: # OP_SERVERSTATUS (Stats utilisateurs/fichiers)
                if len(payload) >= 8:
                    stats["users"], stats["files"] = struct.unpack("<I I", payload[:8])
                    got_status = True
                    if len(payload) >= 12: 
                        stats["max_users"] = struct.unpack("<I", payload[8:12])[0]
            
            elif opcode == 0x41: # OP_SERVERIDENT (Métadonnées du serveur)
                if len(payload) > 26:
                    tag_data = payload[22:] # On ignore le Hash(16), l'IP(4) et le Port(2)
                    tag_dict = parse_ed2k_tags(tag_data)
                    # L'ID b'\x01' est le Nom, l'ID b'\x02' est la Description
                    if b'\x01' in tag_dict: stats["name"] = str(tag_dict[b'\x01'])
                    if b'\x02' in tag_dict: stats["desc"] = str(tag_dict[b'\x02'])
                    got_ident = True
                    
        s.close()
        
        if got_status or got_ident:
            stats["active"] = True
            
    except Exception as e:
        pass
        
    return stats

def write_tag_string_id(tag_id, value):
    """Génère un tag pour le server.met en utilisant l'ID eD2k au lieu d'une chaîne"""
    val_bytes = value.encode('utf-8', errors='ignore')
    tag = struct.pack("<B H B H", 2, 1, tag_id, len(val_bytes))
    tag += val_bytes
    return tag

def generate_server_met(servers):
    """Compile le binaire avec les vraies métadonnées capturées"""
    with open(MET_FILE, "wb") as f:
        f.write(struct.pack("<B", 0xE0))
        f.write(struct.pack("<I", len(servers)))
        
        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s['ip'])))
            f.write(struct.pack("<H", s['port']))
            
            tags = []
            if s['stats']['name']: tags.append(write_tag_string_id(1, s['stats']['name']))
            if s['stats']['desc']: tags.append(write_tag_string_id(2, s['stats']['desc']))
                
            f.write(struct.pack("<I", len(tags))) # Nombre de tags pour ce serveur
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
        h1 {{ color: var(--header); margin: 0; }}
        select#lang {{ padding: 8px; border-radius: 5px; border: 1px solid #ccc; font-size: 14px; cursor: pointer; }}
        
        .info-panel {{ background: #e8f4fd; padding: 15px; border-left: 4px solid var(--primary); border-radius: 4px; margin-bottom: 20px; }}
        .btn {{ display: inline-block; padding: 12px 20px; background: var(--primary); color: white; text-decoration: none; border-radius: 6px; font-weight: bold; transition: background 0.3s; }}
        .btn:hover {{ background: #2980b9; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
        th, td {{ padding: 12px 15px; border-bottom: 1px solid #eee; text-align: left; }}
        th {{ background: var(--header); color: white; cursor: pointer; user-select: none; transition: background 0.2s; white-space: nowrap; }}
        th:hover {{ background: #34495e; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .num {{ font-family: monospace; font-size: 13px; }}
        .desc-col {{ max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
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
            <p><i id="txt-copy">Copy this file's URL into your eMule settings for automatic updates.</i></p>
        </div>
        
        <div style="overflow-x:auto;">
            <table id="server-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)" id="th-flag">Country ↕</th>
                        <th onclick="sortTable(1)" id="th-name">Name ↕</th>
                        <th onclick="sortTable(2)" id="th-desc">Description ↕</th>
                        <th onclick="sortTable(3)" id="th-ip">IP:Port ↕</th>
                        <th onclick="sortTable(4)" id="th-users">Users ↕</th>
                        <th onclick="sortTable(5)" id="th-max">Max Users ↕</th>
                        <th onclick="sortTable(6)" id="th-files">Files ↕</th>
                    </tr>
                </thead>
                <tbody>"""

    for s in servers:
        html += f"""
                    <tr>
                        <td title="{s['country_code']}">{s['flag']}</td>
                        <td style="font-weight: bold;">{s['stats']['name']}</td>
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
                thFlag: "Country ↕", thName: "Name ↕", thDesc: "Description ↕", thIP: "IP:Port ↕", thUsers: "Users ↕", thMax: "Max Users ↕", thFiles: "Files ↕"
            },
            fr: {
                title: "🌐 Serveurs eD2k Actifs", update: "Dernière mise à jour :", download: "⬇️ Télécharger server.met", copy: "Copiez l'URL de ce fichier dans les paramètres d'eMule pour la mise à jour automatique.",
                thFlag: "Pays ↕", thName: "Nom ↕", thDesc: "Description ↕", thIP: "IP:Port ↕", thUsers: "Utilisateurs ↕", thMax: "Max Utilisateurs ↕", thFiles: "Fichiers ↕"
            },
            es: {
                title: "🌐 Servidores eD2k Activos", update: "Última actualización:", download: "⬇️ Descargar server.met", copy: "Copie la URL de este archivo en eMule para actualizaciones automáticas.",
                thFlag: "País ↕", thName: "Nombre ↕", thDesc: "Descripción ↕", thIP: "IP:Puerto ↕", thUsers: "Usuarios ↕", thMax: "Máx Usuarios ↕", thFiles: "Archivos ↕"
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
            switching = true;
            dir = "asc"; 
            
            while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i + 1].getElementsByTagName("TD")[n];
                    
                    let valX = x.innerHTML.toLowerCase().replace(/,/g, '');
                    let valY = y.innerHTML.toLowerCase().replace(/,/g, '');
                    
                    if (!isNaN(parseFloat(valX)) && !isNaN(parseFloat(valY))) {
                        valX = parseFloat(valX);
                        valY = parseFloat(valY);
                    }
                    
                    if (dir == "asc") {
                        if (valX > valY) { shouldSwitch = true; break; }
                    } else if (dir == "desc") {
                        if (valX < valY) { shouldSwitch = true; break; }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc";
                        switching = true;
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
                
                print(f"Interrogation eD2k de {ip}:{port}...")
                stats = probe_ed2k_server(ip, port)
                
                if stats["active"]:
                    print(f"  -> Actif ✅ | Nom : {stats['name']} | Users : {stats['users']}")
                    
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
                print(f"Erreur locale avec '{line}': {e}")
                
    print(f"\nTerminé. {len(active_servers)} serveurs actifs.")
    
    generate_server_met(active_servers)
    generate_html(active_servers)

if __name__ == "__main__":
    main()
