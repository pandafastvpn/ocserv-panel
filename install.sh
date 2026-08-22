#!/usr/bin/env bash
# Re-exec a LF-only copy when the script was copied from Windows.
# Bash parses a script before executing it, so normalizing later is too late.
if [[ -z "${OCSERV_PANEL_LF_REEXEC:-}" ]] && grep -q $'\r' "$0" 2>/dev/null; then
    lf_copy="$(mktemp /tmp/ocserv-panel-install.XXXXXX)"
    trap 'rm -f "$lf_copy"' EXIT
    tr -d '\r' < "$0" > "$lf_copy"
    chmod 700 "$lf_copy"
    export OCSERV_PANEL_LF_REEXEC=1
    exec bash "$lf_copy" "$@"
fi

set -euo pipefail

# ============================================================
# ocserv-panel one-click installer for Debian 12
# https://github.com/yourname/ocserv-panel
# ============================================================

VERSION="1.0.0"
GO_VERSION="1.23.4"
OCSERV_VERSION="1.5.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }
step()    { echo -e "${CYAN}[STEP]${NC} $1"; }

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    error "Please run as root: sudo bash install.sh"
    exit 1
fi

# Record the directory where install.sh lives
# This must happen BEFORE any cd commands
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export SCRIPT_DIR

# Default config
PANEL_PORT="${PANEL_PORT:-8443}"
PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASS="${PANEL_PASS:-admin123}"
VPN_NETWORK="${VPN_NETWORK:-10.0.0.0}"
VPN_NETMASK="${VPN_NETMASK:-255.255.255.0}"

INSTALL_DIR="/opt/ocserv-panel"
TEMPLATE_DIR="${INSTALL_DIR}/templates"
DATA_DIR="${INSTALL_DIR}/data"
OCSERV_CONF_DIR="/etc/ocserv"
RADIUS_DIR="/etc/radiusclient"
GROUP_DIR="${OCSERV_CONF_DIR}/config-per-group"
CERT_DIR="${OCSERV_CONF_DIR}"

echo ""
echo "========================================"
echo "  ocserv-panel installer v${VERSION}"
echo "========================================"
echo "  Panel Port:    ${PANEL_PORT}"
echo "  Panel User:    ${PANEL_USER}"
echo "  Panel Pass:    ${PANEL_PASS}"
echo "  VPN Network:   ${VPN_NETWORK}/${VPN_NETMASK}"
echo "========================================"
echo ""

# ============================================================
# 1. System dependencies
# ============================================================
step "1/9 Installing system dependencies..."

export DEBIAN_FRONTEND=noninteractive

# Kill any stuck apt processes
kill $(lsof -t /var/lib/dpkg/lock-frontend 2>/dev/null) 2>/dev/null || true
kill $(lsof -t /var/lib/apt/lists/lock 2>/dev/null) 2>/dev/null || true

# Wait for apt to be ready (max 60 seconds)
for i in $(seq 1 30); do
    if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

apt-get update -qq 2>/dev/null || true

apt-get install -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=30 \
    ocserv \
    freeradius-utils \
    iptables \
    iproute2 \
    curl \
    wget \
    ca-certificates \
    net-tools \
    procps \
    gnutls-bin \
    lsof \
    build-essential \
    meson \
    ninja-build \
    pkg-config \
    libgnutls28-dev \
    libev-dev \
    libreadline-dev \
    libtasn1-bin \
    libpam0g-dev \
    liblz4-dev \
    libseccomp-dev \
    libnl-route-3-dev \
    libkrb5-dev \
    libradcli-dev \
    liboath-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    libtalloc-dev \
    gperf \
    2>&1 | tail -10

# occtl is included in the ocserv package on Debian
if ! command -v occtl >/dev/null 2>&1; then
    warn "occtl not found in PATH. It should be part of the ocserv package."
    warn "Try: dpkg -L ocserv | grep occtl"
fi

info "System dependencies installed."

# ============================================================
# 2. Build ocserv from source
# ============================================================
step "2/9 Building ocserv ${OCSERV_VERSION} from source..."

OCSERV_TARBALL="ocserv-${OCSERV_VERSION}.tar.xz"
cd /tmp
if [ ! -f "${OCSERV_TARBALL}" ]; then
    info "Downloading ocserv ${OCSERV_VERSION} source..."
    wget -q --timeout=120 "https://www.infradead.org/ocserv/download/${OCSERV_TARBALL}" -O "${OCSERV_TARBALL}" || {
        error "Failed to download ocserv source. Check: https://www.infradead.org/ocserv/download/"
        exit 1
    }
fi

rm -rf "ocserv-${OCSERV_VERSION}"
tar -xf "${OCSERV_TARBALL}" || {
    error "Failed to extract ocserv source."
    exit 1
}

cd "ocserv-${OCSERV_VERSION}"
info "Running meson setup (RADIUS/PAM/seccomp/LZ4 enabled)..."
meson setup build \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    -Dpam=enabled \
    -Dradius=enabled \
    -Dseccomp=enabled \
    -Dlz4=enabled \
    -Dlibnl=enabled \
    -Dgssapi=disabled \
    -Doidc-auth=disabled \
    -Dfirewall-script=iptables || {
    error "meson setup failed."
    exit 1
}

info "Compiling (this may take several minutes)..."
ninja -C build || {
    error "ocserv build failed."
    exit 1
}

info "Installing ocserv to /usr (overrides apt version)..."
ninja -C build install || {
    error "ocserv install failed."
    exit 1
}

cd /tmp
rm -rf "ocserv-${OCSERV_VERSION}" "${OCSERV_TARBALL}"

if command -v ocserv >/dev/null 2>&1; then
    info "ocserv version: $(ocserv --version 2>/dev/null | head -1)"
else
    warn "ocserv binary not found in PATH after build."
fi
info "ocserv ${OCSERV_VERSION} built and installed."

# ============================================================
# 3. Install Go
# ============================================================
step "3/9 Checking Go installation..."

NEED_GO=true
if command -v go >/dev/null 2>&1; then
    GO_VER=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
    if [ -n "$GO_VER" ]; then
        GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
        GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
        if [ "$GO_MAJOR" -gt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 21 ]); then
            info "Go ${GO_VER} already installed."
            NEED_GO=false
        fi
    fi
fi

if [ "$NEED_GO" = true ]; then
    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in
        amd64)  GO_ARCH="amd64" ;;
        arm64)  GO_ARCH="arm64" ;;
        *)      error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    info "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
    cd /tmp
    wget -q --timeout=60 "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O go.tar.gz || {
        error "Failed to download Go. Try manually: https://go.dev/dl/"
        exit 1
    }

    info "Installing Go..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go.tar.gz
    rm -f go.tar.gz

    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/root/go
    export GOPROXY=https://goproxy.cn,direct

    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo 'export GOPATH=/root/go' >> /etc/profile
        echo 'export GOPROXY=https://goproxy.cn,direct' >> /etc/profile
    fi

    info "Go ${GO_VERSION} installed."
fi

export PATH=$PATH:/usr/local/go/bin
export GOPATH=/root/go
export GOPROXY=https://goproxy.cn,direct

# ============================================================
# 3. Directories
# ============================================================
step "4/9 Creating directories..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$TEMPLATE_DIR/static"
mkdir -p "$DATA_DIR"
mkdir -p "$OCSERV_CONF_DIR"
mkdir -p "$RADIUS_DIR"
mkdir -p "$GROUP_DIR"
mkdir -p "$CERT_DIR"

info "Directories created."

# ============================================================
# 4. Copy source files
# ============================================================
step "5/9 Copying source files..."

# Use SCRIPT_DIR from the top of the script, but also try fallbacks
if [ ! -f "${SCRIPT_DIR}/main.go" ]; then
    # Try current working directory
    if [ -f "$(pwd)/main.go" ]; then
        SCRIPT_DIR="$(pwd)"
    # Try the directory where sudo was invoked
    elif [ -f "${SUDO_PWD}/main.go" ]; then
        SCRIPT_DIR="${SUDO_PWD}"
    elif [ -f "${HOME}/ocserv-panel/main.go" ]; then
        SCRIPT_DIR="${HOME}/ocserv-panel"
    else
        error "main.go not found."
        error "SCRIPT_DIR=${SCRIPT_DIR}"
        error "PWD=$(pwd)"
        error "SUDO_PWD=${SUDO_PWD:-unset}"
        error "HOME=${HOME}"
        error ""
        error "Please run: cd /path/to/ocserv-panel && sudo bash install.sh"
        exit 1
    fi
fi

info "Source directory: ${SCRIPT_DIR}"

cp -f "${SCRIPT_DIR}/main.go" "${INSTALL_DIR}/main.go"
info "Copied main.go"

if [ -f "${SCRIPT_DIR}/go.mod" ]; then
    cp -f "${SCRIPT_DIR}/go.mod" "${INSTALL_DIR}/go.mod"
    info "Copied go.mod"
else
    warn "go.mod not found, creating one..."
    echo "module ocserv-panel" > "${INSTALL_DIR}/go.mod"
    echo "" >> "${INSTALL_DIR}/go.mod"
    echo "go 1.21" >> "${INSTALL_DIR}/go.mod"
fi

if [ -d "${SCRIPT_DIR}/templates" ]; then
    cp -rf "${SCRIPT_DIR}/templates/"* "${TEMPLATE_DIR}/"
    info "Copied templates"
else
    error "templates/ directory not found in ${SCRIPT_DIR}"
    exit 1
fi

# Verify files are in place
ls -la "${INSTALL_DIR}/main.go" "${INSTALL_DIR}/go.mod" || {
    error "File copy verification failed."
    exit 1
}

info "Source files copied."

# ============================================================
# 5. Build the panel
# ============================================================
step "6/9 Building ocserv-panel..."

cd "$INSTALL_DIR"

# Normalize all copied text assets if the source checkout came from Windows.
# The installer itself is normalized before Bash parses it (see top of file).
find . -type f \( -name '*.go' -o -name '*.mod' -o -name '*.sum' -o -name '*.html' -o -name '*.css' -o -name '*.js' \) \
    -exec sed -i 's/\r$//' {} + 2>/dev/null || true

info "Running go mod tidy..."
export CGO_ENABLED=0
go mod tidy 2>&1 || true

info "Building..."
go build -o ocserv-panel . 2>&1 || {
    error "Build failed. Trying with verbose output..."
    go build -v -o ocserv-panel . 2>&1
    exit 1
}

chmod +x ocserv-panel
info "Panel binary built: ${INSTALL_DIR}/ocserv-panel"

# ============================================================
# 6. Generate self-signed certificate
# ============================================================
step "7/9 Generating TLS certificate..."

if [ ! -f "${CERT_DIR}/server-cert.pem" ]; then
    info "Generating self-signed certificate..."
    certtool --generate-privkey --outfile "${CERT_DIR}/server-key.pem" 2>/dev/null || {
        warn "certtool not available, generating with openssl..."
        openssl genrsa -out "${CERT_DIR}/server-key.pem" 2048 2>/dev/null
        openssl req -new -x509 -key "${CERT_DIR}/server-key.pem" \
            -out "${CERT_DIR}/server-cert.pem" \
            -days 3650 \
            -subj "/CN=ocserv-node" 2>/dev/null
    }

    if [ ! -f "${CERT_DIR}/server-cert.pem" ]; then
        cat > /tmp/cert.tmpl <<EOF
organization = ocserv
cn = localhost
tls_www_server
signing_key
encryption_key
EOF
        certtool --generate-self-signed \
            --load-privkey "${CERT_DIR}/server-key.pem" \
            --template /tmp/cert.tmpl \
            --outfile "${CERT_DIR}/server-cert.pem" 2>/dev/null || true
        rm -f /tmp/cert.tmpl
    fi

    chmod 600 "${CERT_DIR}/server-key.pem"
    chmod 644 "${CERT_DIR}/server-cert.pem"
    info "Self-signed certificate generated."
else
    info "Certificate already exists, skipping."
fi

# ============================================================
# 7. Generate configs
# ============================================================
step "8/9 Generating configuration files..."

# --- Panel config ---
# Always regenerate config.json to ensure paths are correct
cat > "${DATA_DIR}/config.json" <<EOJSON
{
  "panel_port": ${PANEL_PORT},
  "panel_user": "${PANEL_USER}",
  "panel_pass": "${PANEL_PASS}",
  "panel_secret": "$(head -c 32 /dev/urandom | xxd -p)",
  "ocserv_conf": "/etc/ocserv/ocserv.conf",
  "radius_conf": "/etc/radiusclient/radiusclient.conf",
  "radius_servers": "/etc/radiusclient/servers",
  "group_dir": "/etc/ocserv/config-per-group",
  "cert_dir": "/etc/ocserv",
  "nas_identifier": "$(hostname -s)",
  "default_if": "$(ip route show default 2>/dev/null | awk '{print $5}' | head -1 || echo eth0)",
  "vpn_network": "${VPN_NETWORK}",
  "vpn_netmask": "${VPN_NETMASK}",
  "tun_device": "vpns"
}
EOJSON
info "Panel config created."

# --- RADIUS client config ---
cat > "${RADIUS_DIR}/radiusclient.conf" <<EOF
# RADIUS client configuration - managed by ocserv-panel
# 注意: secret 不写在这里，写在 servers 文件里
authserver localhost:1812
acctserver localhost:1813
servers /etc/radiusclient/servers
dictionary /etc/radiusclient/dictionary
radius_timeout 5
radius_retries 3
EOF

cat > "${RADIUS_DIR}/servers" <<EOF
# RADIUS server definitions - managed by ocserv-panel
# Format: hostname secret  (no port number)
localhost    testing123
EOF

# RADIUS dictionary - self-contained, radcli format
# Do NOT use INCLUDE or copy freeradius dictionaries (incompatible format)
# This file contains all attributes needed by ocserv
# Valid types: string, integer, ipaddr, ipv4addr, ipv6addr, ipv6prefix, date

# Clean up any incompatible files copied from previous runs
rm -f "${RADIUS_DIR}"/dictionary.* 2>/dev/null || true
rm -f "${RADIUS_DIR}"/dictionary.compat 2>/dev/null || true

cat > "${RADIUS_DIR}/dictionary" <<'DICTEOF'
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string
ATTRIBUTE CHAP-Password 3 string
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE NAS-Port 5 integer
ATTRIBUTE Service-Type 6 integer
ATTRIBUTE Framed-Protocol 7 integer
ATTRIBUTE Framed-IP-Address 8 ipaddr
ATTRIBUTE Framed-IP-Netmask 9 ipaddr
ATTRIBUTE Framed-Routing 10 integer
ATTRIBUTE Filter-Id 11 string
ATTRIBUTE Framed-MTU 12 integer
ATTRIBUTE Framed-Compression 13 integer
ATTRIBUTE Login-IP-Host 14 ipaddr
ATTRIBUTE Login-Service 15 integer
ATTRIBUTE Login-TCP-Port 16 integer
ATTRIBUTE Reply-Message 18 string
ATTRIBUTE Callback-Number 19 string
ATTRIBUTE Callback-Id 20 string
ATTRIBUTE Framed-Route 22 string
ATTRIBUTE Framed-IPX-Network 23 ipaddr
ATTRIBUTE State 24 string
ATTRIBUTE Class 25 string
ATTRIBUTE Vendor-Specific 26 string
ATTRIBUTE Session-Timeout 27 integer
ATTRIBUTE Idle-Timeout 28 integer
ATTRIBUTE Termination-Action 29 integer
ATTRIBUTE Called-Station-Id 30 string
ATTRIBUTE Calling-Station-Id 31 string
ATTRIBUTE NAS-Identifier 32 string
ATTRIBUTE Proxy-State 33 string
ATTRIBUTE Login-LAT-Service 34 string
ATTRIBUTE Login-LAT-Node 35 string
ATTRIBUTE Login-LAT-Group 36 string
ATTRIBUTE Framed-AppleTalk-Link 37 integer
ATTRIBUTE Framed-AppleTalk-Network 38 integer
ATTRIBUTE Framed-AppleTalk-Zone 39 string
ATTRIBUTE Acct-Status-Type 40 integer
ATTRIBUTE Acct-Delay-Time 41 integer
ATTRIBUTE Acct-Input-Octets 42 integer
ATTRIBUTE Acct-Output-Octets 43 integer
ATTRIBUTE Acct-Session-Id 44 string
ATTRIBUTE Acct-Authentic 45 integer
ATTRIBUTE Acct-Session-Time 46 integer
ATTRIBUTE Acct-Input-Packets 47 integer
ATTRIBUTE Acct-Output-Packets 48 integer
ATTRIBUTE Acct-Terminate-Cause 49 integer
ATTRIBUTE Acct-Multi-Session-Id 50 string
ATTRIBUTE Acct-Link-Count 51 integer
ATTRIBUTE Acct-Input-Gigawords 52 integer
ATTRIBUTE Acct-Output-Gigawords 53 integer
ATTRIBUTE CHAP-Challenge 60 string
ATTRIBUTE NAS-Port-Type 61 integer
ATTRIBUTE Port-Limit 62 integer
ATTRIBUTE Login-LAT-Port 63 integer
ATTRIBUTE Tunnel-Type 64 string
ATTRIBUTE Tunnel-Medium-Type 65 string
ATTRIBUTE Tunnel-Client-Endpoint 66 string
ATTRIBUTE Tunnel-Server-Endpoint 67 string
ATTRIBUTE Acct-Tunnel-Connection 68 string
ATTRIBUTE Tunnel-Password 69 string
ATTRIBUTE ARAP-Password 70 string
ATTRIBUTE ARAP-Features 71 string
ATTRIBUTE ARAP-Zone-Access 72 integer
ATTRIBUTE ARAP-Security 73 integer
ATTRIBUTE ARAP-Security-Data 74 string
ATTRIBUTE Password-Retry 75 integer
ATTRIBUTE Prompt 76 integer
ATTRIBUTE Connect-Info 77 string
ATTRIBUTE Configuration-Token 78 string
ATTRIBUTE EAP-Message 79 string
ATTRIBUTE Message-Authenticator 80 string
ATTRIBUTE Tunnel-Private-Group-ID 81 string
ATTRIBUTE Tunnel-Assignment-ID 82 string
ATTRIBUTE Tunnel-Preference 83 string
ATTRIBUTE ARAP-Challenge-Response 84 string
ATTRIBUTE Acct-Interim-Interval 85 integer
ATTRIBUTE Acct-Tunnel-Packets-Lost 86 integer
ATTRIBUTE NAS-Port-Id 87 string
ATTRIBUTE Framed-Pool 89 string
ATTRIBUTE NAS-IPv6-Address 95 string
ATTRIBUTE Framed-Interface-Id 96 string
ATTRIBUTE Framed-IPv6-Prefix 97 ipv6prefix
ATTRIBUTE Login-IPv6-Host 98 string
ATTRIBUTE Framed-IPv6-Route 99 string
ATTRIBUTE Framed-IPv6-Pool 100 string
ATTRIBUTE Delegated-IPv6-Prefix 123 ipv6prefix

VENDOR Microsoft 311

VALUE Service-Type Login 1
VALUE Service-Type Framed 2
VALUE Service-Type Callback-Login 3
VALUE Service-Type Callback-Framed 4
VALUE Service-Type Outbound 5

VALUE Framed-Protocol PPP 1

VALUE Framed-Routing None 0
VALUE Framed-Routing Send 1
VALUE Framed-Routing Listen 2
VALUE Framed-Routing Send-Listen 3

VALUE Acct-Status-Type Start 1
VALUE Acct-Status-Type Stop 2
VALUE Acct-Status-Type Interim-Update 3
VALUE Acct-Status-Type Accounting-On 7
VALUE Acct-Status-Type Accounting-Off 8

VALUE Acct-Authentic Radius 1
VALUE Acct-Authentic Local 2
VALUE Acct-Authentic Remote 3

VALUE Acct-Terminate-Cause User-Request 1
VALUE Acct-Terminate-Cause Lost-Carrier 2
VALUE Acct-Terminate-Cause Lost-Service 3
VALUE Acct-Terminate-Cause Idle-Timeout 4
VALUE Acct-Terminate-Cause Session-Timeout 5
VALUE Acct-Terminate-Cause Admin-Reset 6
VALUE Acct-Terminate-Cause Admin-Reboot 7
VALUE Acct-Terminate-Cause Port-Error 8
VALUE Acct-Terminate-Cause NAS-Error 9
VALUE Acct-Terminate-Cause NAS-Request 10
VALUE Acct-Terminate-Cause NAS-Reboot 11
VALUE Acct-Terminate-Cause Port-Unneeded 12
VALUE Acct-Terminate-Cause Port-Preempted 13
VALUE Acct-Terminate-Cause Port-Suspended 14
VALUE Acct-Terminate-Cause Service-Unavailable 15
VALUE Acct-Terminate-Cause Callback 16
VALUE Acct-Terminate-Cause User-Error 17
VALUE Acct-Terminate-Cause Host-Request 18

VALUE NAS-Port-Type Async 0
VALUE NAS-Port-Type Sync 1
VALUE NAS-Port-Type ISDN 2
VALUE NAS-Port-Type ISDN-V120 3
VALUE NAS-Port-Type ISDN-V110 4
VALUE NAS-Port-Type Virtual 5
VALUE NAS-Port-Type Ethernet 15
DICTEOF

# Fix CRLF just in case
sed -i 's/\r$//' "${RADIUS_DIR}/dictionary" 2>/dev/null || true

# Verify dictionary has User-Name attribute
if grep -q "User-Name" "${RADIUS_DIR}/dictionary" 2>/dev/null; then
    info "RADIUS dictionary configured."
else
    warn "RADIUS dictionary may be incomplete!"
fi

chmod 644 "${RADIUS_DIR}/radiusclient.conf" "${RADIUS_DIR}/servers"
chmod 644 "${RADIUS_DIR}/dictionary"
info "RADIUS client config created."

# --- ocserv main config ---
cat > "${OCSERV_CONF_DIR}/ocserv.conf" <<EOF
# ocserv configuration - managed by ocserv-panel
# Generated: $(date '+%Y-%m-%d %H:%M:%S')

# === Authentication (RADIUS) ===
# RADIUS 只做认证，组策略由本地 config-per-group 管理
auth = "radius[config=/etc/radiusclient/radiusclient.conf]"
acct = "radius[config=/etc/radiusclient/radiusclient.conf]"
stats-report-time = 300

# === Server ===
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
isolate-workers = true
max-clients = 1024
max-same-clients = 2
rate-limit-ms = 100
try-mtu-discovery = true
keepalive = 32400
dpd = 60
mobile-dpd = 180
switch-to-tcp-timeout = 25

# === TLS ===
server-cert = ${CERT_DIR}/server-cert.pem
server-key = ${CERT_DIR}/server-key.pem
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"

# === Timeouts ===
auth-timeout = 240
cookie-timeout = 60
deny-roaming = false
rekey-time = 172800
rekey-method = ssl

# === Banning ===
max-ban-score = 80
ban-reset-time = 1200

# === Network ===
device = vpns
predictable-ips = true
default-domain = vpn.local
ipv4-network = ${VPN_NETWORK}
ipv4-netmask = ${VPN_NETMASK}
ping-leases = false
tunnel-all-dns = true
dns = 8.8.8.8

# === Routes ===
route = default

# === Per-group config ===
# FreeRADIUS 控制组/会话策略，通过返回的 Class / Session-Timeout / Idle-Timeout 等属性下发。
# 本地 config-per-group 在当前 ocserv 版本会与 radius supplemental config 冲突，因此不启用。

# === Cisco compat ===
cisco-client-compat = true
dtls-legacy = true

# === Logging ===
log-level = 2
use-occtl = true
server-stats-reset-time = 604800
EOF

# Create default group config if it doesn't exist
if [ ! -f "${GROUP_DIR}/default" ]; then
    cat > "${GROUP_DIR}/default" <<'EOF'
# Default group - applied when user doesn't select a group
# No rate limiting, no restrictions
EOF
fi

info "ocserv config created."

# --- Systemd: ocserv ---
# Do NOT overwrite the Debian-provided ocserv.service, just ensure it exists
if [ ! -f /lib/systemd/system/ocserv.service ] && [ ! -f /etc/systemd/system/ocserv.service ]; then
    cat > /etc/systemd/system/ocserv.service <<'EOF'
[Unit]
Description=OpenConnect SSL VPN server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/ocserv -f -c /etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

# --- Systemd: ocserv-panel ---
cat > /etc/systemd/system/ocserv-panel.service <<EOF
[Unit]
Description=ocserv-panel Web Management
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/ocserv-panel
WorkingDirectory=${INSTALL_DIR}
Environment=HOME=/root
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
info "Systemd services configured."

# ============================================================
# 8. Start services
# ============================================================
step "9/9 Starting services..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
if ! grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
fi

# Get default interface
DEFAULT_IF=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
if [ -z "$DEFAULT_IF" ]; then
    DEFAULT_IF="eth0"
fi

# Setup NAT
VPN_CIDR=$(echo "${VPN_NETWORK}" | sed 's/\.[0-9]*$/\.0\/24/')
iptables -t nat -A POSTROUTING -s "${VPN_CIDR}" -o "$DEFAULT_IF" -j MASQUERADE 2>/dev/null || true

# Start panel
systemctl enable ocserv-panel
systemctl restart ocserv-panel
sleep 1

if systemctl is-active --quiet ocserv-panel; then
    info "ocserv-panel started successfully."
else
    warn "ocserv-panel failed to start. Check: journalctl -u ocserv-panel"
fi

# Start ocserv
systemctl enable ocserv
systemctl restart ocserv 2>/dev/null || true
sleep 2

if systemctl is-active --quiet ocserv; then
    info "ocserv started successfully."
else
    warn "ocserv failed to start. Diagnosing..."
    warn "--- ocserv config test ---"
    ocserv -c /etc/ocserv/ocserv.conf -t 2>&1 || true
    warn "--- systemctl status ---"
    systemctl status ocserv --no-pager -l 2>&1 | tail -20 || true
    warn "--- journalctl last 20 lines ---"
    journalctl -u ocserv --no-pager -n 20 2>&1 || true
    warn ""
    warn "Common causes:"
    warn "  1. TLS certificate missing or invalid -> check /etc/ocserv/server-cert.pem"
    warn "  2. RADIUS config file not found -> check /etc/radiusclient/radiusclient.conf and /etc/radiusclient/servers"
    warn "  3. RADIUS dictionary missing -> run: cp /usr/share/radiusclient/dictionary* /etc/radiusclient/"
    warn "  4. Port 443 already in use -> run: ss -tlnp | grep 443"
fi

if systemctl is-active --quiet ocserv; then
    info "ocserv started successfully."
else
    warn "ocserv not running yet. You may need to upload a proper TLS certificate."
fi

# ============================================================
# Done
# ============================================================
SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1 || echo "your-server-ip")

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "  Panel URL:   https://${SERVER_IP}:${PANEL_PORT}"
echo "  Username:    ${PANEL_USER}"
echo "  Password:    ${PANEL_PASS}"
echo ""
echo "  VPN Port:    443 (TCP/UDP)"
echo "  VPN Network: ${VPN_CIDR}"
echo ""
echo "  Next steps:"
echo "    1. Open the panel URL in your browser"
echo "    2. Go to RADIUS Settings, configure your RADIUS server"
echo "    3. Go to Certificates, upload your TLS certificate"
echo "    4. Go to User Groups, create groups with policies"
echo "    5. Start ocserv from the dashboard"
echo ""
echo "  Useful commands:"
echo "    systemctl restart ocserv-panel  # Restart panel"
echo "    systemctl restart ocserv        # Restart VPN"
echo "    occtl show users                # View connected users"
echo "    journalctl -u ocserv-panel -f   # View panel logs"
echo ""
echo "========================================"
echo ""
