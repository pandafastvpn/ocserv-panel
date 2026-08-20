# ocserv-panel

A lightweight one-click installer and web panel for **ocserv (OpenConnect VPN server)** with **RADIUS authentication and accounting** support.

Designed for **Debian 12**, built with **Go**, zero external dependencies. No Nginx, no PHP, no database — just a single binary.

## What This Is

This is a **VPN node panel** — it runs on each ocserv server and lets you:

- Configure ocserv settings (ports, VPN network, DNS, routes)
- Manage user groups with per-group speed limits, session timeouts, routes
- Configure RADIUS server connection (host, port, shared secret)
- Upload TLS certificates
- View online sessions and disconnect users
- Monitor node health (CPU, memory, traffic stats)
- Start/stop/reload ocserv service

It is **not** a billing system or sales platform. It is the **node-side management tool** that connects to your central RADIUS server (e.g. ToughRADIUS) for authentication and accounting.

## Quick Install (Debian 12)

```bash
git clone https://github.com/yourname/ocserv-panel.git
cd ocserv-panel
sudo bash install.sh
```

Custom settings:

```bash
sudo PANEL_PORT=8443 PANEL_USER=admin PANEL_PASS=yourpass bash install.sh
```

After installation, open `https://your-server-ip:8443` in your browser.

## Important: Fix Windows Line Endings

If you cloned on Windows and uploaded to Linux, fix CRLF before running:

```bash
sed -i 's/\r$//' install.sh main.go go.mod
sed -i 's/\r$//' templates/*.html
sudo bash install.sh
```

## What Gets Installed

| Component | Path |
|-----------|------|
| Panel binary | `/opt/ocserv-panel/ocserv-panel` |
| Panel config | `/opt/ocserv-panel/data/config.json` |
| ocserv config | `/etc/ocserv/ocserv.conf` |
| Group configs | `/etc/ocserv/config-per-group/` |
| RADIUS client config | `/etc/radiusclient/radiusclient.conf` |
| RADIUS servers | `/etc/radiusclient/servers` |
| TLS certificate | `/etc/ocserv/server-cert.pem` |
| TLS key | `/etc/ocserv/server-key.pem` |
| Systemd service | `/etc/systemd/system/ocserv-panel.service` |

## RADIUS Configuration

The installer configures ocserv with:

```
auth = "radius[config=/etc/radiusclient/radiusclient.conf,groupconfig=true]"
acct = "radius[config=/etc/radiusclient/radiusclient.conf]"
stats-report-time = 300
```

- `auth` — RADIUS authentication
- `acct` — RADIUS accounting (Start/Stop/Interim-Update with traffic stats)
- `groupconfig=true` — reads group policies from RADIUS reply attributes
- `stats-report-time = 300` — sends interim accounting every 5 minutes with `Acct-Input-Octets` and `Acct-Output-Octets`

### Connecting to ToughRADIUS

1. Install ToughRADIUS on your central server
2. Open ocserv-panel → **RADIUS Settings**
3. Set ToughRADIUS server IP, auth port (1812), acct port (1813), shared secret
4. Save — ocserv reloads automatically
5. Add this ocserv node as a NAS client in ToughRADIUS with the same shared secret

## Speed Limit Reference

| Speed | bytes/sec |
|-------|-----------|
| 1 Mbps | 125000 |
| 5 Mbps | 625000 |
| 10 Mbps | 1250000 |
| 50 Mbps | 6250000 |
| 100 Mbps | 12500000 |

## Managing Groups

Groups are stored as files in `/etc/ocserv/config-per-group/`. Each file supports:

- `rx-data-per-sec` — download speed limit
- `tx-data-per-sec` — upload speed limit
- `session-timeout` — max session duration
- `idle-timeout` — auto-disconnect when idle
- `dns` — per-group DNS servers
- `route` / `no-route` — per-group routing
- `max-same-clients` — concurrent connections per user

Users are assigned to groups via the RADIUS `Class` attribute (e.g. `OU=premium`).

## Useful Commands

```bash
systemctl start ocserv         # Start VPN
systemctl stop ocserv          # Stop VPN
systemctl restart ocserv       # Restart VPN
systemctl restart ocserv-panel # Restart panel
occtl show users               # View connected users
occtl show status              # View server status
occtl disconnect user <name>   # Disconnect a user
occtl reload                   # Reload configuration
journalctl -u ocserv-panel -f  # View panel logs
```

## Architecture

```
┌───────────────────────────────────────────┐
│  Central Server                            │
│  ┌──────────────┐  ┌──────────────────┐   │
│  │ ToughRADIUS   │  │ PHP Sales Panel  │   │
│  │ Auth + Acct   │  │ Users, Orders,   │   │
│  │ Port 1812/    │  │ Plans, Billing  │   │
│  │      1813     │  │                  │   │
│  └──────┬────────┘  └──────────────────┘   │
└─────────┼─────────────────────────────────┘
          │ RADIUS Auth + Accounting
    ┌─────┴─────┐
    │           │
┌───┴────┐  ┌───┴────┐  ┌────────┐
│ Node 1 │  │ Node 2 │  │ Node N │
│ocserv+ │  │ocserv+ │  │ocserv+ │
│panel  │  │panel  │  │panel  │
└────────┘  └────────┘  └────────┘
```

## Requirements

- Debian 12 (Bookworm)
- Root access
- Public IP or port forwarding for TCP/UDP 443

## License

MIT
