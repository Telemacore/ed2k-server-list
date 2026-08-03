# 🌐 Active eD2k Server List & Automated Harvester

[![Actualiser server.met](https://github.com/Telemacore/ed2k-server-list/actions/workflows/update.yml/badge.svg)](https://github.com/Telemacore/ed2k-server-list/actions/workflows/update.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

An automated, high-performance eD2k (eMule / eDonkey / aMule) active server list harvester and modern web directory portal.

<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/4/4a/EMule_mascot.svg" alt="eMule Mascot" width="100">
</p>

---

## ✨ Features

- **⚡ Multi-Threaded UDP Probing**: Rapidly checks server availability, latency (ping RTT), active users, indexed files, maximum user capacity, and file limits (soft/hard).
- **📡 Peer Discovery & Self-Expanding Database**: Automatically queries online eD2k servers via TCP (`OP_SERVERLIST`) and fetches remote community `server.met` files to discover and save new active servers into `servers.txt`.
- **📦 Multi-Format Exports**:
  - `server.met`: Binary file for direct eMule / aMule auto-update integration.
  - `servers.json`: Full REST JSON API containing all server metadata & metrics.
  - `servers.txt`: Plain text IP:Port seed list.
  - `index.html`: Ultra-modern Glassmorphism dashboard web portal.
- **🎨 Glassmorphism Web Portal**:
  - Interactive multi-column sorting & real-time search filtering.
  - Dark / Light mode toggle.
  - Multi-language UI switcher (English, French, Spanish, German, Italian).
  - Quick-copy `ed2k://` links and `server.met` direct update URL buttons.
- **🤖 Fully Automated**: Built-in GitHub Actions workflow refreshes the list every 6 hours and deploys directly to GitHub Pages.

---

## 🚀 How to Use with eMule / aMule

### Automatic `server.met` Updates
1. Copy your GitHub Pages hosted `server.met` URL:
   ```text
   https://<your-username>.github.io/ed2k-server-list/server.met
   ```
2. Open **eMule** → **Options** → **Server**.
3. Check *"Auto-update server list at startup"* and paste the URL into **"Update server.met from URL"**.

---

## 🛠️ Local Development & Running

### Requirements
- Python 3.10 or higher
- Standard Python libraries (`socket`, `struct`, `urllib`, `json`, `concurrent.futures`, `zlib`) - **No external pip packages required!**

### Run Harvester
```bash
python main.py
```

The script will:
1. Load `servers.txt`.
2. Fetch distant community `server.met` lists.
3. Probe candidate servers via UDP concurrently.
4. Discover peer servers via TCP handshake.
5. Enrich active servers with country flags via GeoIP.
6. Generate updated files inside the `public/` directory.

---

## 📁 Repository Structure

```text
├── main.py               # Core Python harvester, protocol parser, and web generator
├── servers.txt           # Seed list of known eD2k servers (auto-expanding)
├── public/               # Generated website & data artifacts (published to GitHub Pages)
│   ├── index.html        # Glassmorphism Web Dashboard
│   ├── server.met        # eMule binary server list
│   ├── servers.json      # Public REST API endpoint
│   └── servers.txt       # Raw IP:PORT list
└── .github/workflows/
    └── update.yml        # GitHub Actions 6-hour cron workflow
```

---

## 📄 License
Released under the [MIT License](LICENSE).
