# 创游编辑器 · 自建服务端（复活交接包的 `server/` 子目录）

这是**复活交接包**里的服务端部分。整套包还包含 `client/`（客户端基底 + 改包工具 + 解密源码）
与 `docs/`（AI 复活交接手册）。部署到新服务器后，客户端连接的是**新服务器**，与任何旧机器无关。

> ⚠️ **在复活交接包里怎么用本目录**
> - 本目录必须整体放到 `/opt/privsrv`（源码按此固定路径编写，`install.sh` 会强校验）。
> - 正确做法是在**包根**执行：`sudo mkdir -p /opt/privsrv && sudo cp -a server/. /opt/privsrv/`
> - IP 不用在这里单独填：先在包根 `conf/revive.env` 填 `YOUR_SERVER_IP`，再跑 `scripts/sync_ip.sh`
>   会自动写进本目录的 `conf/privsrv.env`。这样服务端与客户端共用同一个 IP。
> - **主文档是包根 `docs/00_AI复活交接手册.md`**，请先读它；本目录 `docs/` 是服务端通用参考。

> ⚠️ **合规与范围**
> - 仅用于个人对已停服软件的自用学习与研究，非商业、不公开、不传播。
> - 客户端及相关商标、美术、音乐等权利归原权利人所有，本包不改变这一点。
> - 所有 IP、证书、后台密码、账号数据均在安装时现场生成，包内不含任何他人地址或凭据。

---

## 30 秒上手（在复活交接包内）

```bash
# 在【包根】执行（不是在本目录里）
sudo mkdir -p /opt/privsrv
sudo cp -a server/. /opt/privsrv/
cd /opt/privsrv

# 一键安装（IP 已由 sync_ip.sh 写好，无需交互）
sudo bash scripts/install.sh

# 自检
bash scripts/check.sh
```

> 若你是把本 `server/` 目录**单独**拿出来部署（脱离复活包），则自行编辑
> `conf/privsrv.env` 的 `PRIVSRV_IP=你的IP`，再跑 `install.sh`。

装完后：
- 手机 WiFi 代理填 `<你的IP>:8080`（或 Android 私人 DNS），并安装信任 `uploads/privsrv-ca.crt`
- 客户端用**任意手机号 + 任意验证码**登录
- 后台：`https://<你的IP>:38443`，密码见 `admin_password.txt`

---

## 文档

| 文件 | 内容 |
|---|---|
| **[docs/开服教程.md](docs/开服教程.md)** | ★ 从零完整教程：环境、安装、手机接入、验证、排错 |
| [docs/手动部署.md](docs/手动部署.md) | 不用一键脚本的分步手动安装 |
| [docs/架构说明.md](docs/架构说明.md) | 组件、端口、数据流、协议编码、信誉分机制 |

## 快速命令

```bash
bash scripts/ctl.sh status     # 6 个服务状态
bash scripts/ctl.sh restart    # 重启全部
bash scripts/ctl.sh logs       # 看日志
bash scripts/check.sh          # 开服自检（服务/端口/证书/回包）
```

## 你需要填/改的东西

几乎只有一处：`conf/privsrv.env` 里的 **`PRIVSRV_IP`**（你的服务器公网 IP）。
其余全部自动：证书为该 IP 现场签发、后台密码随机生成、初始数据库为干净空库（首次登录自动注册、示例作品自动填充）。

## 目录结构

```
privsrv-kit/
├── README.md              本文件
├── docs/                  开服教程 / 手动部署 / 架构说明
├── conf/
│   ├── privsrv.env        ★ 唯一必改：你的服务器 IP
│   ├── nginx/             nginx 配置模板
│   └── systemd/           6 个服务单元
├── scripts/               install / gen_certs / init_admin / ctl / check / ws_probe
├── *.py                   服务端全部代码（后端/WS/后台/代理/DNS/DoT/数据层/功能层）
├── lx_lz4.js              协议编码（配合 node_modules/lz4js）
├── node_modules/lz4js/     内置，无需 npm install
├── data/                  协议定义 + 干净初始库
├── certs/                 空（安装时生成证书）
├── logs/ uploads/         运行目录（封面/根证书）
└── requirements.txt       Python 依赖：flask bcrypt websockets
```

## 端口

| 端口 | 用途 | 是否需对手机开放 |
|---|---|---|
| 80 / 443 | nginx（ws / TLS SNI） | ✅ |
| 8080 | HTTP CONNECT 代理（WiFi 代理） | ✅ |
| 38443 | 后台管理 HTTPS | ✅ |
| 53 / 853 | DNS 劫持 / 私人 DNS | ✅（用私人 DNS 时） |
| 8443 | HTTP 后端 | ❌ 仅本机 |
| 8765 | WebSocket agent | ❌ 仅本机 |

## 环境要求

Linux（Ubuntu 20.04+ / Debian 11+ / CentOS 8+）、root、Python 3.8+、Node.js、nginx、openssl。
Python 依赖见 `requirements.txt`；`lz4js` 已内置。
