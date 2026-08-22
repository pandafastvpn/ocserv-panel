# Ocserv-面板


一个轻量级的一键安装ocserv+radius客户端并带管理面板，适用于ocserv（OpenConnect VPN服务器），支持本地和RADIUS认证、计费。

只在Debian 12测试 ，使用 Go 构建，零外部依赖。无需Nginx、PHP、数据库，只有一个二进制文件。
## 关于

这是一个VPN节点面板，在面板可以做到以下功能：



- 配置ocserv设置（端口、VPN网络、DNS、路由）
- 管理用户组，按组速度限制、会话超时、路由
- 配置RADIUS服务器连接（主机、端口、共享秘密）
- 上传TLS证书
- 查看连接用户并可以断开某个用户的连接
- 监控节点健康状况（CPU、内存、流量统计）
- 启动/停止/重新加载ocserv服务

它不是一个计费系统或销售平台。可以连接到你中央RADIUS服务器（例如ToughRADIUS）进行认证和计费。



## 快速安装 (Debian 12)

```bash
apt update && apt install git sudo -y
git clone https://github.com/pandafastvpn/ocserv-panel.git
cd ocserv-panel
sudo bash install.sh
```

也可以自定义安装:

```bash
sudo PANEL_PORT=8443 PANEL_USER=admin PANEL_PASS=yourpass bash install.sh
```

安装完成后，在浏览器中打开。 `https://your-server-ip:8443` i

## Important: Fix Windows Line Endings

If you cloned on Windows and uploaded to Linux, fix CRLF before running:

```bash
sed -i 's/\r$//' install.sh main.go go.mod
sed -i 's/\r$//' templates/*.html
sudo bash install.sh
```

## 安装内容

| Component | Path |
|-----------|------|
| 管理面板 | `/opt/ocserv-panel/ocserv-panel` |
| 面板配置	 | `/opt/ocserv-panel/data/config.json` |
| ocserv config | `/etc/ocserv/ocserv.conf` |
| 群组设置 | `/etc/ocserv/config-per-group/` |
| RADIUS 客户端配置 | `/etc/radiusclient/radiusclient.conf` |
| RADIUS 服务端连接插件| `/etc/radiusclient/servers` |
| TLS证书	e | `/etc/ocserv/server-cert.pem` |
| TLS 密匙| `/etc/ocserv/server-key.pem` |
| Systemd 服务| `/etc/systemd/system/ocserv-panel.service` |

## RADIUS 配置


安装程序会默认以下方式配置ocserv：



```
auth = "radius[config=/etc/radiusclient/radiusclient.conf,groupconfig=true]"
acct = "radius[config=/etc/radiusclient/radiusclient.conf]"
stats-report-time = 300
```

- `auth` — RADIUS认证
- `acct` — RADIUS计费（含流量统计的开始/停止/临时更新）
- `groupconfig=true` — 从 RADIUS 回复属性读取组策略
- `stats-report-time = 300` — 每5分钟发送一次临时账目，并且 `Acct-Input-Octets`  `Acct-Output-Octets`

### 连接ToughRADIUS


1. 在你的服务器上安装ToughRADIUS（安装具体看https://github.com/talkincode/toughradius）
2. 打开 安装后ocserv面板 → RADIUS 设置
3. 设置ToughRADIUS服务器IP、认证端口（1812）、账户端口（1813）、共享秘密
4. 保存
5. 在ToughRADIUS中添加这个ocserv节点作为NAS客户端，使用相同的共享秘密

## 限速参考

| 速度 | 字节/秒 |
|-------|-----------|
| 1 Mbps | 125000 |
| 5 Mbps | 625000 |
| 10 Mbps | 1250000 |
| 50 Mbps | 6250000 |
| 100 Mbps | 12500000 |

## 管理组


组以文件形式存储在 `/etc/ocserv/config-per-group/`。每个文件支持：

- `rx-data-per-sec` — 下载速度限制
- `tx-data-per-sec` — 上传速度限制
- `session-timeout` — 最大会话时长
- `idle-timeout` — 空闲自动断开
- `dns` — 群组DNS服务器
- `route` / `no-route` — 群组路由或排除路由
- `max-same-clients` — 每个用户的并发连接

用户可以通过 RADIUS 的`Class` 属性连接到群组（例如  `OU=premium`).

## 实用命令


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

## 要求


- Debian 12 (Bookworm)
- Root a用户
- TCP/UDP 443 的公共 IP 或端口转发

## License

MIT
