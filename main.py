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
TIMEOUT = 3 # Secondes d'attente max pour le ping TCP

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def ip_to_int(ip):
    packed = socket.inet_aton(ip)
    return struct.unpack("<I", packed)[0]

def check_server_tcp(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except:
        return False

def get_country_info(ip):
    """Récupère le code pays via ip-api.com (respecte la limite de 45 requêtes/min)"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            code = data.get("countryCode", "XX")
            if code == "XX": return "❓", "XX"
            # Convertit le code pays en emoji drapeau
            flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
            return flag, code
    except:
        return "❓", "XX"

def get_mock_ed2k_stats(ip):
    """
    Simule la récupération des métadonnées eD2k.
    Pour avoir les vrais chiffres, il faudrait implémenter un client UDP eDonkey (OP_GETSERVERINFO).
    """
    return {
        "name": f"eDonkeyServer ({ip})",
        "desc": "Standard eD2k Server",
        "users": 1500,
        "max_users": 50000,
        "files": 125000
    }

def write_tag_string(name, value):
    tag = struct.pack("<B", 2)
    tag += struct.pack("<H", len(name))
    tag += name.encode('utf-8')
    tag += struct.pack("<H", len(value))
    tag += value.encode('utf-8')
    return tag

def generate_server_met(servers):
    with open(MET_FILE, "wb") as f:
        f.write(struct.pack("<B", 0xE0))
        f.write(struct.pack("<I", len(servers)))
        
        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s['ip'])))
            f.write(struct.pack("<H", s['port']))
            tag_data = write_tag_string("server_name", s['stats']['name'])
            f.write(struct.pack("<I", 1))
            f.write(tag_data)

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
        .container {{ max-width: 1000px; margin: auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        
        .top-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
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
                        <td>{s['stats']['name']}</td>
                        <td>{s['stats']['desc']}</td>
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
        // --- MULTILINGUAL (i18n) DICTIONARY ---
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

        // --- SORTING LOGIC ---
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
            if not line or line.startswith("#"):
                continue
            
            try:
                ip, port_str = line.split(":")
                port = int(port_str)
                
                print(f"Test de {ip}:{port}...")
                if check_server_tcp(ip, port):
                    print("  -> Actif ✅")
                    
                    # Récupération GeoIP et métadonnées
                    flag, country_code = get_country_info(ip)
                    stats = get_mock_ed2k_stats(ip)
                    
                    active_servers.append({
                        "ip": ip,
                        "port": port,
                        "flag": flag,
                        "country_code": country_code,
                        "stats": stats
                    })
                    
                    time.sleep(1.5) # Pause pour ne pas saturer l'API gratuite ip-api
                    
                else:
                    print("  -> Hors ligne ❌")
                    
            except Exception as e:
                print(f"Erreur avec la ligne '{line}': {e}")
                
    print(f"\nTerminé. {len(active_servers)} serveurs actifs.")
    
    generate_server_met(active_servers)
    generate_html(active_servers)

if __name__ == "__main__":
    main()
