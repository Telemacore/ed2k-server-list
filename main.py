import socket
import struct
import os
import datetime

# --- CONFIGURATION ---
INPUT_FILE = "servers.txt"
OUTPUT_DIR = "public"
MET_FILE = os.path.join(OUTPUT_DIR, "server.met")
HTML_FILE = os.path.join(OUTPUT_DIR, "index.html")
TIMEOUT = 3 # Secondes d'attente max pour le ping

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def ip_to_int(ip):
    \"\"\"Convertit une IP string en entier (Little Endian) pour le binaire.\"\"\"
    packed = socket.inet_aton(ip)
    return struct.unpack("<I", packed)[0]

def check_server(ip, port):
    \"\"\"Tente d'établir une connexion TCP pour vérifier si le serveur est actif.\"\"\"
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def write_tag_string(name, value):
    \"\"\"Génère un tag binaire de type string (Type 2) pour le format eD2k.\"\"\"
    tag = struct.pack("<B", 2) # Type 2 = String
    tag += struct.pack("<H", len(name))
    tag += name.encode('utf-8')
    tag += struct.pack("<H", len(value))
    tag += value.encode('utf-8')
    return tag

def generate_server_met(servers):
    \"\"\"Génère le fichier binaire strict server.met\"\"\"
    with open(MET_FILE, "wb") as f:
        f.write(struct.pack("<B", 0xE0)) # Header eD2k
        f.write(struct.pack("<I", len(servers))) # Nombre de serveurs
        
        for s in servers:
            f.write(struct.pack("<I", ip_to_int(s['ip'])))
            f.write(struct.pack("<H", s['port']))
            
            # 1 tag par défaut : Le nom du serveur
            tag_data = write_tag_string("server_name", f"Serveur Actif ({s['ip']})")
            
            f.write(struct.pack("<I", 1)) # Nombre de tags
            f.write(tag_data)

def generate_html(servers):
    \"\"\"Génère une page d'accueil simple pour présenter les serveurs actifs.\"\"\"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f\"\"\"
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Liste de Serveurs eD2k</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f4f9; color: #333; margin: 40px; }}
            .container {{ max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background: #34495e; color: white; }}
            .btn {{ display: inline-block; padding: 10px 15px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-bottom: 20px; }}
            .btn:hover {{ background: #2980b9; }}
            .status {{ color: green; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Serveurs eD2k Actifs</h1>
            <p>Dernière mise à jour : <strong>{now}</strong> UTC</p>
            <a href="server.met" class="btn">⬇️ Télécharger server.met</a>
            <p><i>Copiez l'URL de ce fichier dans eMule pour la mise à jour automatique.</i></p>
            
            <table>
                <tr>
                    <th>Adresse IP</th>
                    <th>Port</th>
                    <th>Statut</th>
                    <th>Lien eD2k</th>
                </tr>
    \"\"\"
    for s in servers:
        html += f\"\"\"
                <tr>
                    <td>{s['ip']}</td>
                    <td>{s['port']}</td>
                    <td class="status">En ligne</td>
                    <td><a href="ed2k://|server|{s['ip']}|{s['port']}|/">Ajouter</a></td>
                </tr>
        \"\"\"
    
    html += \"\"\"
            </table>
        </div>
    </body>
    </html>
    \"\"\"
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
                if check_server(ip, port):
                    print("  -> Actif ✅")
                    active_servers.append({"ip": ip, "port": port})
                else:
                    print("  -> Hors ligne ❌")
                    
            except Exception as e:
                print(f"Erreur avec la ligne '{line}': {e}")
                
    print(f"\\nTerminé. {len(active_servers)} serveurs actifs trouvés.")
    
    generate_server_met(active_servers)
    generate_html(active_servers)
    print(f"Fichiers générés dans le dossier '{OUTPUT_DIR}'.")

if __name__ == "__main__":
    main()
