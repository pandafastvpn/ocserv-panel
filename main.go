package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================
// Data Structures
// ============================================================

type AppConfig struct {
	PanelPort     int    `json:"panel_port"`
	PanelUser     string `json:"panel_user"`
	PanelPass     string `json:"panel_pass"`
	PanelSecret   string `json:"panel_secret"`
	OcservConf    string `json:"ocserv_conf"`
	RadiusConf    string `json:"radius_conf"`
	RadiusServ    string `json:"radius_servers"`
	AuthMode      string `json:"auth_mode"`
	LocalPasswd   string `json:"local_passwd"`
	GroupDir      string `json:"group_dir"`
	CertDir       string `json:"cert_dir"`
	NasIdentifier string `json:"nas_identifier"`
	DefaultIF     string `json:"default_if"`
	VPNNetwork    string `json:"vpn_network"`
	VPNNetmask    string `json:"vpn_netmask"`
	TunDevice     string `json:"tun_device"`
}

type GroupConfig struct {
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	RxDataPerSec   int    `json:"rx_data_per_sec"`
	TxDataPerSec   int    `json:"tx_data_per_sec"`
	SessionTimeout int    `json:"session_timeout"`
	IdleTimeout    int    `json:"idle_timeout"`
	DNS            string `json:"dns"`
	Routes         string `json:"routes"`
	NoRoutes       string `json:"no_routes"`
	MaxSameClients int    `json:"max_same_clients"`
}

type RadiusServer struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	AcctPort     int    `json:"acct_port"`
	NasIdentifier string `json:"nas_identifier"`
}

type SessionInfo struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	IP       string `json:"ip"`
	VPNIP    string `json:"vpn_ip"`
	Since    string `json:"since"`
	RxBytes  string `json:"rx_bytes"`
	TxBytes  string `json:"tx_bytes"`
	Duration string `json:"duration"`
	State    string `json:"state"`
}

type ServerStatus struct {
	Status     string `json:"status"`
	TotalUsers int    `json:"total_users"`
	TotalRx    string `json:"total_rx"`
	TotalTx    string `json:"total_tx"`
	Uptime     string `json:"uptime"`
	CPUUsage   string `json:"cpu_usage"`
	MemUsage   string `json:"mem_usage"`
}

type OcservSettings struct {
	TcpPort             int    `json:"tcp_port"`
	UdpPort             int    `json:"udp_port"`
	MaxClients          int    `json:"max_clients"`
	MaxSameClients      int    `json:"max_same_clients"`
	VPNNetwork          string `json:"vpn_network"`
	VPNNetmask          string `json:"vpn_netmask"`
	DNS                 string `json:"dns"`
	Route               string `json:"route"`
	Device              string `json:"device"`
	XmlConfigFile       string `json:"xml_config_file"`
	StatsReport         int    `json:"stats_report"`
	TunnelAllDNS        bool   `json:"tunnel_all_dns"`
	AuthTimeout         int    `json:"auth_timeout"`
	CookieTimeout       int    `json:"cookie_timeout"`
	DPD                 int    `json:"dpd"`
	MobileDPD           int    `json:"mobile_dpd"`
	RekeyTime           int    `json:"rekey_time"`
	SwitchToTCPTimeout   int    `json:"switch_to_tcp_timeout"`
	Keepalive           int    `json:"keepalive"`
	MaxBanScore         int    `json:"max_ban_score"`
	BanResetTime        int    `json:"ban_reset_time"`
}

// ============================================================
// Application State
// ============================================================

var (
	config    *AppConfig
	configMu  sync.RWMutex
	sessionMu sync.Mutex
	sessions  = make(map[string]string)
	tplMux    sync.RWMutex
	tplCache  = make(map[string]*template.Template)
)

const configPath = "/opt/ocserv-panel/data/config.json"
const templateDir = "/opt/ocserv-panel/templates"

// ============================================================
// Config Loading
// ============================================================

func loadConfig() (*AppConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(cfg *AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}

func getConfig() *AppConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return config
}

func setConfig(cfg *AppConfig) {
	configMu.Lock()
	config = cfg
	configMu.Unlock()
	_ = saveConfig(cfg)
}

// ============================================================
// Template rendering — each page is a complete standalone template
// ============================================================

var tplFuncs = template.FuncMap{
	"htmlattr":    func(s string) template.HTMLAttr { return template.HTMLAttr(s) },
	"rawhtml":     func(s string) template.HTML { return template.HTML(s) },
	"splitLines":  func(s string) []string { return strings.Split(s, "\n") },
	"splitColon":  func(s string) []string { return strings.SplitN(s, ":", 3) },
}

func renderPage(w http.ResponseWriter, page string, data interface{}) {
	// Always re-parse templates (no cache) to ensure latest version is used
	t, err := template.New(page).Funcs(tplFuncs).ParseFiles(filepath.Join(templateDir, page))
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	t.ExecuteTemplate(w, page, data)
}

// ============================================================
// Auth Middleware
// ============================================================

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("ocserv_panel_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sessionMu.Lock()
		username, ok := sessions[cookie.Value]
		sessionMu.Unlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		_ = username
		next(w, r)
	}
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ============================================================
// Main
// ============================================================

func main() {
	var err error

	config, err = loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/static/", serveStatic)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)

	mux.HandleFunc("/", authMiddleware(handleDashboard))
	mux.HandleFunc("/ocserv", authMiddleware(handleOcservSettings))
	mux.HandleFunc("/ocserv/save", authMiddleware(handleOcservSave))
	mux.HandleFunc("/groups", authMiddleware(handleGroups))
	mux.HandleFunc("/groups/save", authMiddleware(handleGroupSave))
	mux.HandleFunc("/groups/delete", authMiddleware(handleGroupDelete))
	mux.HandleFunc("/radius", authMiddleware(handleRadius))
	mux.HandleFunc("/radius/save", authMiddleware(handleRadiusSave))
	mux.HandleFunc("/radius/test", authMiddleware(handleRadiusTest))
	mux.HandleFunc("/sessions", authMiddleware(handleSessions))
	mux.HandleFunc("/sessions/disconnect", authMiddleware(handleSessionDisconnect))
	mux.HandleFunc("/sessions/json", authMiddleware(handleSessionsJSON))
	mux.HandleFunc("/certs", authMiddleware(handleCerts))
	mux.HandleFunc("/certs/upload", authMiddleware(handleCertUpload))
	mux.HandleFunc("/monitor", authMiddleware(handleMonitor))
	mux.HandleFunc("/monitor/json", authMiddleware(handleMonitorJSON))
	mux.HandleFunc("/settings", authMiddleware(handleSettings))
	mux.HandleFunc("/settings/save", authMiddleware(handleSettingsSave))
	mux.HandleFunc("/users", authMiddleware(handleLocalUsers))
	mux.HandleFunc("/users/save", authMiddleware(handleLocalUserSave))
	mux.HandleFunc("/users/delete", authMiddleware(handleLocalUserDelete))
	mux.HandleFunc("/logs", authMiddleware(handleLogs))
	mux.HandleFunc("/logs/json", authMiddleware(handleLogsJSON))
	mux.HandleFunc("/ocserv/start", authMiddleware(handleOcservStart))
	mux.HandleFunc("/ocserv/stop", authMiddleware(handleOcservStop))
	mux.HandleFunc("/ocserv/restart", authMiddleware(handleOcservRestart))
	mux.HandleFunc("/ocserv/reload", authMiddleware(handleOcservReload))

	cfg := getConfig()
	addr := fmt.Sprintf(":%d", cfg.PanelPort)

	log.Printf("ocserv-panel 启动在 %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ============================================================
// Static Files
// ============================================================

func serveStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[len("/static/"):]
	fullPath := filepath.Join(templateDir, "static", path)
	http.ServeFile(w, r, fullPath)
}

// ============================================================
// Login / Logout
// ============================================================

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		renderPage(w, "login.html", nil)
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	cfg := getConfig()
	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.PanelUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(cfg.PanelPass)) == 1

	if !userMatch || !passMatch {
		renderPage(w, "login.html", map[string]string{"Error": "用户名或密码错误"})
		return
	}

	token := generateToken()
	sessionMu.Lock()
	sessions[token] = username
	sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "ocserv_panel_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("ocserv_panel_session")
	if err == nil {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
		sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "ocserv_panel_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ============================================================
// Dashboard
// ============================================================

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	status := getOcservStatus()
	userCount := getOnlineUserCount()
	cfg := getConfig()

	var ocservLog string
	if status != "running" {
		ocservLog = getOcservErrorLog()
	}

	data := map[string]interface{}{
		"Active":        "dashboard",
		"Status":        status,
		"UserCount":     userCount,
		"Config":        cfg,
		"OcservRunning": isOcservRunning(),
		"PanelPort":     cfg.PanelPort,
		"OcservLog":     ocservLog,
	}
	renderPage(w, "dashboard.html", data)
}

func getOcservErrorLog() string {
	var parts []string

	// Config test
	cmd := exec.Command("ocserv", "-c", "/etc/ocserv/ocserv.conf", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil || len(output) > 0 {
		parts = append(parts, "=== 配置检测 ===\n"+string(output))
	}

	// Journalctl
	cmd = exec.Command("journalctl", "-u", "ocserv", "--no-pager", "-n", "30")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		parts = append(parts, "=== ocserv 日志 ===\n"+string(output))
	}

	// Systemctl status
	cmd = exec.Command("systemctl", "status", "ocserv", "--no-pager", "-l")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		parts = append(parts, "=== 服务状态 ===\n"+string(output))
	}

	return strings.Join(parts, "\n\n")
}

// ============================================================
// Ocserv Settings
// ============================================================

func handleOcservSettings(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	settings := readOcservSettings()
	data := map[string]interface{}{
		"Active":        "ocserv",
		"Settings":      settings,
		"NasIdentifier": cfg.NasIdentifier,
	}
	renderPage(w, "ocserv.html", data)
}

func handleOcservSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/ocserv", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	settings := OcservSettings{
		TcpPort:           atoiDefault(r.FormValue("tcp_port"), 443),
		UdpPort:           atoiDefault(r.FormValue("udp_port"), 443),
		MaxClients:        atoiDefault(r.FormValue("max_clients"), 1024),
		MaxSameClients:    atoiDefault(r.FormValue("max_same_clients"), 2),
		VPNNetwork:        r.FormValue("vpn_network"),
		VPNNetmask:        r.FormValue("vpn_netmask"),
		DNS:               r.FormValue("dns"),
		Route:              r.FormValue("route"),
		Device:           r.FormValue("device"),
		XmlConfigFile:    strings.TrimSpace(r.FormValue("xml_config_file")),
		StatsReport:      atoiDefault(r.FormValue("stats_report"), 300),
		TunnelAllDNS:      r.FormValue("tunnel_all_dns") == "on",
		AuthTimeout:       atoiDefault(r.FormValue("auth_timeout"), 240),
		CookieTimeout:     atoiDefault(r.FormValue("cookie_timeout"), 60),
		DPD:               atoiDefault(r.FormValue("dpd"), 60),
		MobileDPD:         atoiDefault(r.FormValue("mobile_dpd"), 180),
		RekeyTime:         atoiDefault(r.FormValue("rekey_time"), 172800),
		SwitchToTCPTimeout: atoiDefault(r.FormValue("switch_to_tcp_timeout"), 25),
		Keepalive:         atoiDefault(r.FormValue("keepalive"), 32400),
		MaxBanScore:       atoiDefault(r.FormValue("max_ban_score"), 80),
		BanResetTime:      atoiDefault(r.FormValue("ban_reset_time"), 1200),
	}
	writeOcservSettings(settings)

	// Verify the values written back are consistent with what was submitted.
	verify := readOcservSettings()
	if verify.StatsReport != settings.StatsReport ||
		verify.Keepalive != settings.Keepalive ||
		verify.DPD != settings.DPD ||
		verify.MobileDPD != settings.MobileDPD ||
		verify.CookieTimeout != settings.CookieTimeout ||
		verify.AuthTimeout != settings.AuthTimeout ||
		verify.RekeyTime != settings.RekeyTime ||
		verify.MaxBanScore != settings.MaxBanScore ||
		verify.BanResetTime != settings.BanResetTime {
		http.Error(w, "配置写入后回读不一致，请检查 ocserv.conf 是否被其他进程修改", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ocserv", http.StatusSeeOther)
}

func readOcservSettings() OcservSettings {
	cfg := getConfig()
	data, _ := os.ReadFile(cfg.OcservConf)
	content := string(data)
	return OcservSettings{
		TcpPort:           getIntFromConfig(content, "tcp-port", 443),
		UdpPort:           getIntFromConfig(content, "udp-port", 443),
		MaxClients:        getIntFromConfig(content, "max-clients", 1024),
		MaxSameClients:    getIntFromConfig(content, "max-same-clients", 2),
		VPNNetwork:        getStrFromConfig(content, "ipv4-network", "10.0.0.0"),
		VPNNetmask:        getStrFromConfig(content, "ipv4-netmask", "255.255.255.0"),
		DNS:               getStrFromConfig(content, "dns", "8.8.8.8"),
		Route:             getStrFromConfig(content, "route", "default"),
		Device:            getStrFromConfig(content, "device", "vpns"),
		XmlConfigFile:     getStrFromConfig(content, "user-profile", ""),
		StatsReport:       getIntFromConfig(content, "stats-report-time", 300),
		TunnelAllDNS:      strings.Contains(content, "tunnel-all-dns = true"),
		AuthTimeout:       getIntFromConfig(content, "auth-timeout", 240),
		CookieTimeout:     getIntFromConfig(content, "cookie-timeout", 60),
		DPD:               getIntFromConfig(content, "dpd", 60),
		MobileDPD:         getIntFromConfig(content, "mobile-dpd", 180),
		RekeyTime:         getIntFromConfig(content, "rekey-time", 172800),
		SwitchToTCPTimeout: getIntFromConfig(content, "switch-to-tcp-timeout", 25),
		Keepalive:         getIntFromConfig(content, "keepalive", 32400),
		MaxBanScore:       getIntFromConfig(content, "max-ban-score", 80),
		BanResetTime:      getIntFromConfig(content, "ban-reset-time", 1200),
	}
}

func writeOcservSettings(s OcservSettings) {
	cfg := getConfig()
	authMethod := fmt.Sprintf("radius[config=%s,groupconfig=true,nas-identifier=%s]", cfg.RadiusConf, cfg.NasIdentifier)
	if cfg.AuthMode == "local" {
		authMethod = fmt.Sprintf("plain[passwd=%s]", localPasswdPath(cfg))
	}
	tunnelDNS := "false"
	if s.TunnelAllDNS {
		tunnelDNS = "true"
	}
	routeValue := strings.TrimSpace(s.Route)
	if routeValue == "" {
		routeValue = "default"
	}
	// config-per-group only works when supplemental config is 'file'. With RADIUS
	// groupconfig=true this is forbidden; per-user/group policy is read from the
	// RADIUS reply instead, so the local group files only apply in local mode.
	groupConfig := ""
	if cfg.AuthMode == "local" {
		groupConfig = fmt.Sprintf("config-per-group = %s", cfg.GroupDir)
	}
	profileConfig := ""
	if s.XmlConfigFile != "" {
		profileConfig = fmt.Sprintf("user-profile = %s", s.XmlConfigFile)
	}
	content := fmt.Sprintf(`# ocserv configuration - managed by ocserv-panel
# Last updated: %s

# RADIUS 认证（FreeRADIUS）
auth = "%s"
acct = "radius[config=%s,nas-identifier=%s]"
# Send Interim-Update records regularly; FreeRADIUS uses these for live usage.
stats-report-time = %d

# === Server ===
tcp-port = %d
udp-port = %d
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
isolate-workers = true
max-clients = %d
max-same-clients = %d
rate-limit-ms = 100
try-mtu-discovery = true
keepalive = %d
dpd = %d
mobile-dpd = %d
switch-to-tcp-timeout = %d

# === TLS ===
server-cert = %s/server-cert.pem
server-key = %s/server-key.pem
tls-priorities = "NORMAL:%%SERVER_PRECEDENCE:%%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"

# === Timeouts ===
auth-timeout = %d
cookie-timeout = %d
deny-roaming = false
rekey-time = %d
rekey-method = ssl

# === Banning ===
max-ban-score = %d
ban-reset-time = %d

# === Network ===
device = %s
predictable-ips = true
default-domain = vpn.local
ipv4-network = %s
ipv4-netmask = %s
ping-leases = false
tunnel-all-dns = %s
dns = %s
%s

# === Routes ===
route = %s

# === Per-group config ===
%s

# === Cisco compat ===
cisco-client-compat = true
dtls-legacy = true

# === Logging ===
log-level = 2
use-occtl = true
server-stats-reset-time = 604800
`,
		time.Now().Format("2006-01-02 15:04:05"),
		authMethod, cfg.RadiusConf, cfg.NasIdentifier, s.StatsReport,
		s.TcpPort, s.UdpPort, s.MaxClients, s.MaxSameClients,
		s.Keepalive, s.DPD, s.MobileDPD, s.SwitchToTCPTimeout,
		cfg.CertDir, cfg.CertDir,
		s.AuthTimeout, s.CookieTimeout, s.RekeyTime,
		s.MaxBanScore, s.BanResetTime,
		s.Device, s.VPNNetwork, s.VPNNetmask, tunnelDNS, s.DNS,
		profileConfig, routeValue, groupConfig,
	)

	content = strings.ReplaceAll(content, "display-name =", "# display-name =")

	// Ensure default group config exists
	defaultGroupPath := filepath.Join(cfg.GroupDir, "default")
	if !fileExists(defaultGroupPath) {
		os.WriteFile(defaultGroupPath, []byte("# Default group\n"), 0644)
	}
	_ = os.WriteFile(cfg.OcservConf, []byte(content), 0644)
	updateSelectGroup()
}

// ============================================================
// Groups
// ============================================================

func handleGroups(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	groups := listGroups(cfg.GroupDir)
	data := map[string]interface{}{
		"Active":   "groups",
		"Groups":   groups,
		"AuthMode": cfg.AuthMode,
	}
	renderPage(w, "groups.html", data)
}

func handleGroupSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	name := r.FormValue("name")
	if !isValidName(name) {
		http.Error(w, "Invalid group name", http.StatusBadRequest)
		return
	}
	cfg := getConfig()
	groupPath := filepath.Join(cfg.GroupDir, name)
	var lines []string
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if displayName != "" {
		// Metadata is kept in a comment so ocserv does not parse it as an option.
		lines = append(lines, fmt.Sprintf("# display-name = %s", displayName))
	}
	rx := atoiDefault(r.FormValue("rx_data_per_sec"), 0)
	tx := atoiDefault(r.FormValue("tx_data_per_sec"), 0)
	st := atoiDefault(r.FormValue("session_timeout"), 0)
	it := atoiDefault(r.FormValue("idle_timeout"), 0)
	dns := r.FormValue("dns")
	routes := r.FormValue("routes")
	noRoutes := r.FormValue("no_routes")
	msc := atoiDefault(r.FormValue("max_same_clients"), 0)
	if rx > 0 {
		lines = append(lines, fmt.Sprintf("rx-data-per-sec = %d", rx))
	}
	if tx > 0 {
		lines = append(lines, fmt.Sprintf("tx-data-per-sec = %d", tx))
	}
	if st > 0 {
		lines = append(lines, fmt.Sprintf("session-timeout = %d", st))
	}
	if it > 0 {
		lines = append(lines, fmt.Sprintf("idle-timeout = %d", it))
	}
	if dns != "" {
		for _, d := range strings.Fields(dns) {
			lines = append(lines, fmt.Sprintf("dns = %s", d))
		}
	}
	for _, route := range strings.Fields(routes) {
		lines = append(lines, fmt.Sprintf("route = %s", route))
	}
	for _, route := range strings.Fields(noRoutes) {
		lines = append(lines, fmt.Sprintf("no-route = %s", route))
	}
	if msc > 0 {
		lines = append(lines, fmt.Sprintf("max-same-clients = %d", msc))
	}
	content := fmt.Sprintf("# Group: %s\n# Generated: %s\n%s\n", name, time.Now().Format("2006-01-02 15:04:05"), strings.Join(lines, "\n"))
	_ = os.WriteFile(groupPath, []byte(content), 0644)
	updateSelectGroup()
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !isValidName(name) {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}
	cfg := getConfig()
	_ = os.Remove(filepath.Join(cfg.GroupDir, name))
	updateSelectGroup()
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func listGroups(dir string) []GroupConfig {
	var groups []GroupConfig
	entries, err := os.ReadDir(dir)
	if err != nil {
		return groups
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		g := parseGroupConfig(name, string(data))
		groups = append(groups, g)
	}
	return groups
}

func parseGroupConfig(name, content string) GroupConfig {
	g := GroupConfig{Name: name, DisplayName: name}
	displayNameRe := regexp.MustCompile(`(?m)^\s*#\s*display-name\s*=\s*(.+)$`)
	if m := displayNameRe.FindStringSubmatch(content); m != nil {
		g.DisplayName = strings.TrimSpace(m[1])
	}
	g.RxDataPerSec = getIntFromConfig(content, "rx-data-per-sec", 0)
	g.TxDataPerSec = getIntFromConfig(content, "tx-data-per-sec", 0)
	g.SessionTimeout = getIntFromConfig(content, "session-timeout", 0)
	g.IdleTimeout = getIntFromConfig(content, "idle-timeout", 0)
	g.DNS = getStrFromConfig(content, "dns", "")
	g.MaxSameClients = getIntFromConfig(content, "max-same-clients", 0)
	routeRe := regexp.MustCompile(`(?m)^route\s*=\s*(.+)$`)
	noRouteRe := regexp.MustCompile(`(?m)^no-route\s*=\s*(.+)$`)
	var routes, noRoutes []string
	for _, m := range routeRe.FindAllStringSubmatch(content, -1) {
		routes = append(routes, strings.TrimSpace(m[1]))
	}
	for _, m := range noRouteRe.FindAllStringSubmatch(content, -1) {
		noRoutes = append(noRoutes, strings.TrimSpace(m[1]))
	}
	g.Routes = strings.Join(routes, " ")
	g.NoRoutes = strings.Join(noRoutes, " ")
	return g
}

// ============================================================
// RADIUS Settings
// ============================================================

func handleRadius(w http.ResponseWriter, r *http.Request) {
	srv := readRadiusServer()
	data := map[string]interface{}{
		"Active": "radius",
		"Radius": srv,
	}
	renderPage(w, "radius.html", data)
}

func handleRadiusSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/radius", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	host := r.FormValue("host")
	port := atoiDefault(r.FormValue("port"), 1812)
	secret := r.FormValue("secret")
	acctPort := atoiDefault(r.FormValue("acct_port"), 1813)
	if !isValidIP(host) && !isValidDomain(host) {
		http.Error(w, "Invalid RADIUS server address", http.StatusBadRequest)
		return
	}
	writeRadiusServer(host, port, secret, acctPort)
	http.Redirect(w, r, "/radius", http.StatusSeeOther)
}

func handleRadiusTest(w http.ResponseWriter, r *http.Request) {
	srv := readRadiusServer()
	testUser := r.URL.Query().Get("user")
	if testUser == "" {
		testUser = "testuser"
	}
	testPass := r.URL.Query().Get("pass")
	if testPass == "" {
		testPass = "testpass"
	}
	result := testRadiusConnection(srv.Host, srv.Port, srv.Secret, testUser, testPass)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

func readRadiusServer() RadiusServer {
	cfg := getConfig()
	srv := RadiusServer{Port: 1812, AcctPort: 1813}

	// Read host and port from radiusclient.conf
	data, _ := os.ReadFile(cfg.RadiusConf)
	content := string(data)
	authServer := getStrFromConfig(content, "authserver", "localhost:1812")
	if strings.Contains(authServer, ":") {
		parts := strings.Split(authServer, ":")
		srv.Host = parts[0]
		srv.Port, _ = strconv.Atoi(parts[1])
	} else {
		srv.Host = authServer
	}

	// Read secret from servers file
	// Format: hostname secret (no port)
	serversData, _ := os.ReadFile(cfg.RadiusServ)
	serversContent := string(serversData)
	re := regexp.MustCompile(`(?m)^(\S+)\s+(\S+)$`)
	for _, line := range strings.Split(serversContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m != nil && len(m) >= 3 {
			srv.Host = m[1]
			srv.Secret = m[2]
			break
		}
	}

	return srv
}

func writeRadiusServer(host string, port int, secret string, acctPort int) {
	cfg := getConfig()
	radiusConf := fmt.Sprintf(`# RADIUS client configuration - managed by ocserv-panel
# 注意: secret 不写在这里，写在 servers 文件里
authserver %s:%d
acctserver %s:%d
servers /etc/radiusclient/servers
dictionary /etc/radiusclient/dictionary
radius_timeout 5
radius_retries 3
# Keep accounting enabled even if the authentication server is slow.
`, host, port, host, acctPort)
	serversConf := fmt.Sprintf(`# RADIUS server definitions - managed by ocserv-panel
# Format: hostname secret  (no port number)
%s    %s
`, host, secret)
	_ = os.WriteFile(cfg.RadiusConf, []byte(radiusConf), 0644)
	_ = os.WriteFile(cfg.RadiusServ, []byte(serversConf), 0644)
	exec.Command("systemctl", "restart", "ocserv").Run()
}

func testRadiusConnection(host string, port int, secret string, testUser string, testPass string) string {
	if host == "" || host == "localhost" {
		return "未配置远程 RADIUS 服务器，请先在上方设置服务器地址。"
	}
	cmd := exec.Command("radtest", testUser, testPass, host, fmt.Sprintf("%d", port), secret)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("连接失败: %v\n输出: %s", err, string(output))
	}
	out := string(output)
	if strings.Contains(out, "Access-Accept") {
		return fmt.Sprintf("RADIUS 服务器可达，认证成功 (Access-Accept)。\n\n测试账号: %s\n\n完整响应:\n%s", testUser, out)
	}
	if strings.Contains(out, "Access-Reject") {
		return fmt.Sprintf("RADIUS 服务器可达。认证被拒绝 (Access-Reject)。\n\n测试账号: %s\n如果使用的是真实账号密码，请检查账号状态。\n\n完整响应:\n%s", testUser, out)
	}
	return fmt.Sprintf("RADIUS 服务器响应:\n\n%s", out)
}

// ============================================================
// Sessions
// ============================================================

func handleSessions(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{"Active": "sessions"}
	renderPage(w, "sessions.html", data)
}

func handleSessionsJSON(w http.ResponseWriter, r *http.Request) {
	users := getOnlineUsers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handleSessionDisconnect(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}
	cmd := exec.Command("occtl", "disconnect", "user", username)
	_ = cmd.Run()
	http.Redirect(w, r, "/sessions", http.StatusSeeOther)
}

func getOnlineUsers() []SessionInfo {
	cmd := exec.Command("occtl", "-j", "show", "users")
	output, err := cmd.Output()
	if err != nil {
		return getOnlineUsersText()
	}

	var records []map[string]interface{}
	if err := json.Unmarshal(output, &records); err != nil {
		return getOnlineUsersText()
	}

	users := make([]SessionInfo, 0, len(records))
	for _, record := range records {
		user := SessionInfo{
			Username: sessionField(record, "Username", "username", "user"),
			ID:       sessionField(record, "ID", "id"),
			IP:       sessionField(record, "Remote IP", "remote_ip", "IP", "ip"),
			VPNIP:    sessionField(record, "IPv4", "vpn_ip", "VPNIP"),
			Since:    sessionField(record, "Last connected at", "since", "Since", "Session started at"),
			RxBytes:  sessionField(record, "RX", "rx_bytes", "RxBytes", "rx"),
			TxBytes:  sessionField(record, "TX", "tx_bytes", "TxBytes", "tx"),
			Duration: sessionField(record, "_Last connected at", "duration", "Duration"),
			State:    sessionField(record, "State", "state"),
		}
		if user.Username == "" && user.ID == "" {
			continue
		}
		users = append(users, user)
	}
	return users
}

func sessionField(record map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		for actual, value := range record {
			if strings.EqualFold(actual, key) {
				return fmt.Sprint(value)
			}
		}
	}
	return ""
}

func getOnlineUsersText() []SessionInfo {
	cmd := exec.Command("occtl", "-n", "show", "users")
	output, err := cmd.Output()
	if err != nil {
		return []SessionInfo{}
	}
	lines := strings.Split(string(output), "\n")
	var users []SessionInfo
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Username") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || (len(fields) >= 3 && fields[0] == "id" && fields[1] == "user" && fields[2] == "vhost") {
			continue
		}
		if len(fields) >= 3 {
			user := SessionInfo{
				ID:       fields[0],
				Username: fields[1],
			}
			if len(fields) >= 4 {
				user.IP = fields[3]
			}
			if len(fields) >= 5 {
				user.VPNIP = fields[4]
			}
			if len(fields) >= 7 {
				user.Since = fields[6]
			}
			if len(fields) >= 9 {
				user.State = fields[8]
			}
			users = append(users, user)
		}
	}
	return users
}

func getOnlineUserCount() int {
	return len(getOnlineUsers())
}

// ============================================================
// Certificates
// ============================================================

func handleCerts(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	certPath := filepath.Join(cfg.CertDir, "server-cert.pem")
	keyPath := filepath.Join(cfg.CertDir, "server-key.pem")
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	var certSize, keySize int64
	var certTime, keyTime string
	if certExists {
		stat, _ := os.Stat(certPath)
		certSize = stat.Size()
		certTime = stat.ModTime().Format("2006-01-02 15:04:05")
	}
	if keyExists {
		stat, _ := os.Stat(keyPath)
		keySize = stat.Size()
		keyTime = stat.ModTime().Format("2006-01-02 15:04:05")
	}
	data := map[string]interface{}{
		"Active":     "certs",
		"CertPath":   certPath,
		"KeyPath":    keyPath,
		"CertExists": certExists,
		"KeyExists":  keyExists,
		"CertSize":   certSize,
		"KeySize":    keySize,
		"CertTime":   certTime,
		"KeyTime":    keyTime,
	}
	renderPage(w, "certs.html", data)
}

func handleCertUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/certs", http.StatusSeeOther)
		return
	}
	cfg := getConfig()
	r.ParseMultipartForm(32 << 20)

	certFile, certHeader, err := r.FormFile("cert")
	if err != nil {
		http.Error(w, "证书文件必填: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer certFile.Close()

	keyFile, keyHeader, err := r.FormFile("key")
	if err != nil {
		http.Error(w, "密钥文件必填: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer keyFile.Close()

	certPath := filepath.Join(cfg.CertDir, "server-cert.pem")
	keyPath := filepath.Join(cfg.CertDir, "server-key.pem")

	// Write cert
	certOut, err := os.Create(certPath)
	if err != nil {
		http.Error(w, "写入证书失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(certOut, certFile); err != nil {
		certOut.Close()
		http.Error(w, "复制证书数据失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certOut.Close()
	os.Chmod(certPath, 0644)

	// Write key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		http.Error(w, "写入密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(keyOut, keyFile); err != nil {
		keyOut.Close()
		http.Error(w, "复制密钥数据失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	keyOut.Close()
	os.Chmod(keyPath, 0600)

	// Verify files
	certStat, _ := os.Stat(certPath)
	keyStat, _ := os.Stat(keyPath)
	if certStat == nil || certStat.Size() == 0 {
		http.Error(w, "证书文件写入后为空，上传可能失败", http.StatusInternalServerError)
		return
	}
	if keyStat == nil || keyStat.Size() == 0 {
		http.Error(w, "密钥文件写入后为空，上传可能失败", http.StatusInternalServerError)
		return
	}

	log.Printf("证书已上传: cert=%s (%d bytes), key=%s (%d bytes)",
		certHeader.Filename, certStat.Size(), keyHeader.Filename, keyStat.Size())

	// Reload ocserv to pick up new cert
	exec.Command("systemctl", "restart", "ocserv").Run()
	time.Sleep(2 * time.Second)

	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

// ============================================================
// Node Monitor
// ============================================================

func handleMonitor(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{"Active": "monitor"}
	renderPage(w, "monitor.html", data)
}

func handleMonitorJSON(w http.ResponseWriter, r *http.Request) {
	status := getNodeStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func getNodeStatus() ServerStatus {
	s := ServerStatus{}
	if isOcservRunning() {
		s.Status = "running"
	} else {
		s.Status = "stopped"
	}
	s.TotalUsers = getOnlineUserCount()
	if rx, tx, ok := getOcservTraffic(); ok {
		s.TotalRx = rx
		s.TotalTx = tx
	} else {
		rx, tx := getSystemTraffic()
		s.TotalRx = rx
		s.TotalTx = tx
	}
	s.CPUUsage = getCPUUsage()
	s.MemUsage = getMemUsage()
	uptimeCmd := exec.Command("uptime")
	uptimeOut, err := uptimeCmd.Output()
	if err == nil {
		s.Uptime = strings.TrimSpace(string(uptimeOut))
	}
	return s
}

func getCPUUsage() string {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return "N/A"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				break
			}
			var vals []int64
			for _, f := range fields[1:] {
				v, err := strconv.ParseInt(f, 10, 64)
				if err != nil {
					vals = nil
					break
				}
				vals = append(vals, v)
			}
			if len(vals) < 4 {
				break
			}
			idle := vals[3]
			total := int64(0)
			for _, v := range vals {
				total += v
			}
			if total <= 0 {
				break
			}
			used := float64(total-idle) / float64(total) * 100
			return fmt.Sprintf("%.0f%%", used)
		}
	}
	return "N/A"
}

func getMemUsage() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "N/A"
	}
	var totalKB, availKB int64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d kB", &totalKB)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d kB", &availKB)
		}
	}
	if totalKB <= 0 {
		return "N/A"
	}
	usedKB := totalKB - availKB
	usedPct := float64(usedKB) / float64(totalKB) * 100
	return fmt.Sprintf("%dMB / %dMB (%.0f%%)", usedKB/1024, totalKB/1024, usedPct)
}

func getOcservTraffic() (string, string, bool) {
	cmd := exec.Command("occtl", "-n", "show", "status")
	output, err := cmd.Output()
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(string(output), "\n")
	var rx, tx string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "bytes") && strings.Contains(lower, "rx") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				rx = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "bytes") && strings.Contains(lower, "tx") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				tx = strings.TrimSpace(parts[1])
			}
		}
	}
	if rx == "" && tx == "" {
		return "", "", false
	}
	return rx, tx, true
}

func getSystemTraffic() (string, string) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return "N/A", "N/A"
	}
	var rxBytes, txBytes int64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		rx, _ := strconv.ParseInt(fields[0], 10, 64)
		tx, _ := strconv.ParseInt(fields[8], 10, 64)
		rxBytes += rx
		txBytes += tx
	}
	return humanBytes(rxBytes), humanBytes(txBytes)
}

func humanBytes(v int64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%dB", v)
	}
	d := float64(v)
	exp := 0
	for d >= unit && exp < 5 {
		d /= unit
		exp++
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f%s", d, units[exp])
}

// ============================================================
// Logs
// ============================================================

func handleLogs(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{"Active": "logs"}
	renderPage(w, "logs.html", data)
}

func handleLogsJSON(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type")
	cfg := getConfig()
	var output string

	switch logType {
	case "configtest":
		cmd := exec.Command("ocserv", "-c", cfg.OcservConf, "-t")
		out, _ := cmd.CombinedOutput()
		output = string(out)
		if output == "" {
			output = "配置检测通过，无错误。"
		}
	case "logs":
		cmd := exec.Command("journalctl", "-u", "ocserv", "--no-pager", "-n", "50")
		out, err := cmd.Output()
		if err != nil {
			output = "无法读取日志: " + err.Error()
		} else {
			output = string(out)
		}
	case "conf":
		data, err := os.ReadFile(cfg.OcservConf)
		if err != nil {
			output = "无法读取配置文件: " + err.Error()
		} else {
			output = string(data)
		}
	case "radius":
		data, err := os.ReadFile(cfg.RadiusConf)
		if err != nil {
			output = "无法读取 RADIUS 配置: " + err.Error()
		} else {
			output = string(data)
		}
	case "radius_servers":
		data, err := os.ReadFile(cfg.RadiusServ)
		if err != nil {
			output = "无法读取 servers 文件: " + err.Error()
		} else {
			output = string(data)
		}
	case "dictionary":
		data, err := os.ReadFile("/etc/radiusclient/dictionary")
		if err != nil {
			output = "无法读取字典文件: " + err.Error()
		} else {
			output = string(data)
		}
	case "config_json":
		data, err := os.ReadFile(configPath)
		if err != nil {
			output = "无法读取 config.json: " + err.Error()
		} else {
			output = string(data)
		}
	default:
		output = "Unknown type"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"output": output})
}

// ============================================================
// Local ocserv users
// ============================================================

func handleLocalUsers(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	data, _ := os.ReadFile(localPasswdPath(cfg))
	groups := listGroups(cfg.GroupDir)
	renderPage(w, "users.html", map[string]interface{}{
		"Active": "users",
		"Users":  strings.TrimSpace(string(data)),
		"Groups": groups,
	})
}

func groupNameExists(cfg *AppConfig, name string) bool {
	if name == "default" {
		return true
	}
	for _, g := range listGroups(cfg.GroupDir) {
		if g.Name == name {
			return true
		}
	}
	return false
}

func handleLocalUserSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	var selectedGroups []string
	for _, g := range r.Form["group"] {
		g = strings.TrimSpace(g)
		if g != "" {
			selectedGroups = append(selectedGroups, g)
		}
	}
	if !isValidName(username) || password == "" {
		http.Error(w, "Invalid username or empty password", http.StatusBadRequest)
		return
	}
	cfg := getConfig()
	if len(selectedGroups) == 0 {
		selectedGroups = []string{"default"}
	}
	for _, g := range selectedGroups {
		if !groupNameExists(cfg, g) {
			http.Error(w, "Group does not exist: "+g, http.StatusBadRequest)
			return
		}
	}
	groupValue := strings.Join(selectedGroups, ",")
	path := localPasswdPath(cfg)
	os.MkdirAll(filepath.Dir(path), 0755)
	// Note: ocpasswd 1.5.0 has no -u <username> option (-u means --unlock).
	// The username is a positional argument, e.g.:
	//   ocpasswd -c <file> -g <group> <username>
	cmd := exec.Command("ocpasswd", "-c", path, "-g", groupValue, username)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// ocpasswd reads a single password line from stdin when not a tty.
	cmd.Stdin = strings.NewReader(password + "\n")
	if err := cmd.Run(); err != nil {
		http.Error(w, "Failed to create local user: "+strings.TrimSpace(stderr.String()), http.StatusInternalServerError)
		return
	}
	os.Chmod(path, 0600)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func handleLocalUserDelete(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if !isValidName(username) {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}
	cfg := getConfig()
	path := localPasswdPath(cfg)
	data, _ := os.ReadFile(path)
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, username+":") {
			continue
		}
		kept = append(kept, line)
	}
	_ = os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0600)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// ============================================================
// Panel Settings
// ============================================================

func handleSettings(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	data := map[string]interface{}{
		"Active":        "settings",
		"User":          cfg.PanelUser,
		"Pass":          cfg.PanelPass,
		"Port":          cfg.PanelPort,
		"NasIdentifier": cfg.NasIdentifier,
		"AuthMode":      cfg.AuthMode,
		"Saved":         r.URL.Query().Get("saved") == "1",
	}
	renderPage(w, "settings.html", data)
}

func handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	cfg := getConfig()
	cfg.PanelUser = r.FormValue("username")
	cfg.PanelPass = r.FormValue("password")
	cfg.PanelPort = atoiDefault(r.FormValue("port"), 8443)
	cfg.NasIdentifier = strings.TrimSpace(r.FormValue("nas_identifier"))
	if cfg.NasIdentifier == "" {
		cfg.NasIdentifier = strings.TrimSpace(cfg.DefaultIF)
	}
	mode := r.FormValue("auth_mode")
	if mode != "local" {
		mode = "radius"
	}
	cfg.AuthMode = mode
	if cfg.LocalPasswd == "" {
		cfg.LocalPasswd = "/etc/ocserv/ocpasswd"
	}
	setConfig(cfg)
	writeOcservAuthMode(cfg.AuthMode)

	// Restart panel in background
	go func() {
		time.Sleep(1 * time.Second)
		exec.Command("systemctl", "restart", "ocserv-panel").Run()
	}()

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// ============================================================
// Ocserv Control
// ============================================================

func handleOcservStart(w http.ResponseWriter, r *http.Request) {
	exec.Command("systemctl", "start", "ocserv").Run()
	time.Sleep(1 * time.Second)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleOcservStop(w http.ResponseWriter, r *http.Request) {
	exec.Command("systemctl", "stop", "ocserv").Run()
	time.Sleep(1 * time.Second)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleOcservRestart(w http.ResponseWriter, r *http.Request) {
	exec.Command("systemctl", "restart", "ocserv").Run()
	time.Sleep(2 * time.Second)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleOcservReload(w http.ResponseWriter, r *http.Request) {
	reloadOcserv()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func reloadOcserv() {
	exec.Command("occtl", "reload").Run()
}

func localPasswdPath(cfg *AppConfig) string {
	if cfg.LocalPasswd != "" {
		return cfg.LocalPasswd
	}
	return "/etc/ocserv/ocpasswd"
}

func writeOcservAuthMode(mode string) {
	cfg := getConfig()
	if mode != "local" {
		mode = "radius"
	}
	data, err := os.ReadFile(cfg.OcservConf)
	if err != nil {
		return
	}
	content := string(data)
	localAuth := fmt.Sprintf("auth = \"plain[passwd=%s]\"", localPasswdPath(cfg))
	radiusAuth := fmt.Sprintf("auth = \"radius[config=%s,groupconfig=true,nas-identifier=%s]\"", cfg.RadiusConf, cfg.NasIdentifier)
	content = strings.Replace(content, localAuth, radiusAuth, 1)
	content = strings.Replace(content, radiusAuth, localAuth, 1)
	configPerGroupLine := fmt.Sprintf("config-per-group = %s", cfg.GroupDir)
	if mode == "local" {
		if !strings.Contains(content, configPerGroupLine) {
			content += "\n" + configPerGroupLine + "\n"
		}
	} else {
		content = strings.ReplaceAll(content, configPerGroupLine+"\n", "")
		content = strings.ReplaceAll(content, configPerGroupLine+"\r\n", "")
		content = strings.ReplaceAll(content, configPerGroupLine, "")
	}
	_ = os.WriteFile(cfg.OcservConf, []byte(content), 0644)
	exec.Command("systemctl", "restart", "ocserv").Run()
}

// updateSelectGroup writes group config files and updates ocserv.conf
// to include all available groups in select-group lines.
// With groupconfig=true, ocserv will read group policies from RADIUS Class attribute,
// but select-group is still needed for the client to show the group dropdown.
func updateSelectGroup() {
	cfg := getConfig()
	groups := listGroups(cfg.GroupDir)

	// Ensure default group config exists
	defaultGroupPath := filepath.Join(cfg.GroupDir, "default")
	if !fileExists(defaultGroupPath) {
		os.WriteFile(defaultGroupPath, []byte("# Default group\n"), 0644)
	}

	// Build select-group lines
	var lines []string
	// Always include default group first
	lines = append(lines, "select-group = default[默认组]")
	for _, g := range groups {
		if g.Name == "default" {
			continue
		}
		lines = append(lines, fmt.Sprintf("select-group = %s[%s]", g.Name, g.DisplayName))
	}

	selectGroupBlock := strings.Join(lines, "\n")

	// Read current ocserv.conf
	confPath := cfg.OcservConf
	data, err := os.ReadFile(confPath)
	if err != nil {
		log.Printf("updateSelectGroup: cannot read %s: %v", confPath, err)
		return
	}
	content := string(data)

	// Remove existing select-group lines
	var newLines []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "select-group =") ||
			strings.HasPrefix(strings.TrimSpace(line), "default-select-group") ||
			strings.HasPrefix(strings.TrimSpace(line), "auto-select-group") {
			continue
		}
		newLines = append(newLines, line)
	}
	content = strings.Join(newLines, "\n")

	// Insert select-group block after config-per-group line
	configPerGroupLine := fmt.Sprintf("config-per-group = %s", cfg.GroupDir)
	if strings.Contains(content, configPerGroupLine) {
		content = strings.Replace(content, configPerGroupLine, configPerGroupLine+"\n"+selectGroupBlock, 1)
	} else {
		// Fallback: insert before Cisco compat section
		content = strings.Replace(content, "# === Cisco compat ===", selectGroupBlock+"\n\n# === Cisco compat ===", 1)
	}

	// Write updated config
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		log.Printf("updateSelectGroup: cannot write %s: %v", confPath, err)
		return
	}

	log.Printf("select-group updated: %d groups", len(groups)+1)

	// Restart ocserv to apply changes
	exec.Command("systemctl", "restart", "ocserv").Run()
}

func isOcservRunning() bool {
	cmd := exec.Command("systemctl", "is-active", "ocserv")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

func getOcservStatus() string {
	if isOcservRunning() {
		return "running"
	}
	return "stopped"
}

// ============================================================
// Helpers
// ============================================================

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func getIntFromConfig(content, key string, def int) int {
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^%s\s*=\s*(\d+)`, regexp.QuoteMeta(key)))
	m := re.FindStringSubmatch(content)
	if m != nil {
		v, err := strconv.Atoi(m[1])
		if err == nil {
			return v
		}
	}
	return def
}

func getStrFromConfig(content, key, def string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^%s\s*=\s*(.+)`, regexp.QuoteMeta(key)))
	m := re.FindStringSubmatch(content)
	if m != nil {
		val := strings.TrimSpace(m[1])
		val = strings.Trim(val, `"`)
		return val
	}
	return def
}

func isValidName(name string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return matched
}

func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

func isValidDomain(domain string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`, domain)
	return matched
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// avoid unused import
var _ = html.EscapeString
