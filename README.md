# vps-harden

一个面向 **Debian / Ubuntu VPS** 的一键安全加固脚本：SSH 加固、防火墙、fail2ban、内核参数、审计、自动更新，并带有**防锁死保险**（自动回滚、预览模式、只读自检）。

> **English summary:** A single-file Bash script that hardens a fresh Debian/Ubuntu VPS (SSH, ufw, fail2ban, sysctl, auditd, unattended upgrades) with anti-lockout safeguards: `--dry-run` preview, an auto-rollback timer, and a read-only `--check`. Documentation below is in Chinese.

---

## 目录

- [特点](#特点)
- [重要声明](#重要声明)
- [环境要求](#环境要求)
- [快速开始（照着做就行）](#快速开始照着做就行)
- [运行模式](#运行模式)
- [参数说明](#参数说明)
- [使用示例](#使用示例)
- [脚本会改动什么](#脚本会改动什么)
- [防锁死设计与回滚](#防锁死设计与回滚)
- [常见问题](#常见问题)
- [关于 Lynis 评分](#关于-lynis-评分)
- [已知限制](#已知限制)
- [许可证](#许可证)

---

## 特点

- **防锁死**：先写防火墙放行规则再启用；SSH 配置先用 `sshd -t` 校验再重载；**没有检测到有效公钥时，绝不会关闭密码登录**。
- **自动回滚**：加固后如果 N 分钟内没有执行 `--confirm`，SSH 与防火墙会自动恢复到加固前的状态。
- **预览与自检**：`--dry-run` 只看不改；`--check` 只读核对当前状态，能发现"服务在监听但防火墙没放行"和"密码登录已关闭却没有可用密钥"这类问题。
- **不误伤已有服务**：默认自动放行"当前正在对外监听"的端口（例如代理、网站服务），系统自带的 LLMNR、mDNS、随机临时端口会被排除；疑似管理面板的高位 TCP 端口会单独询问，默认不对公网开放。
- **可重复运行（幂等）**：所有被改动的文件先备份到 `/root/harden-backup-时间戳/`。
- **真实评分**：加固前后各跑一次 [Lynis](https://cisofy.com/lynis/)，输出真实的 Hardening index，并列出剩余建议。

## 重要声明

1. **使用风险自负。** 脚本会修改 SSH、防火墙和内核参数，使用不当可能导致无法登录或服务中断。
2. **先在测试机上试，或先做快照。** 并确认服务商提供 VNC / 网页控制台（SSH 不通时的最后退路）。
3. 首次运行请务必先执行 `--dry-run`，并保持当前 SSH 会话不要关闭。
4. 测试情况：`v1.1` 在 **Debian 13（KVM）** 上完整实机运行过（Lynis 62 → 80）；`v1.2` 的参数校验、回滚、自检、防火墙规则生成等逻辑经过模拟环境测试，**其他系统版本（Debian 11/12、Ubuntu 20.04/22.04/24.04）按逻辑设计应当可用，但未逐一实机验证**。欢迎通过 Issue 反馈。
5. 脚本**不能替代**云厂商安全组、应用自身的安全配置和定期更新。

## 环境要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 11 / 12 / 13、Ubuntu 20.04 / 22.04 / 24.04（其他系统会直接提示并退出） |
| 权限 | root（或 sudo） |
| 初始化系统 | systemd |
| 网络 | 能访问系统软件源（apt） |
| 虚拟化 | KVM、Xen、VMware 等完整虚拟化最稳；OpenVZ / LXC 容器部分项无法生效 |

## 快速开始（照着做就行）

### 0. 准备

- 服务商后台能打开 **VNC / 网页控制台**。
- 记下你的服务正在使用的端口（例如 TCP 443、8443，UDP 443）。
- 查一下自己电脑的公网 IP（用于 fail2ban 白名单，可选但推荐）。

### 1. 在**自己的电脑**上生成 SSH 密钥

> 密钥必须在自己电脑上生成，**私钥不能放到服务器上**。

```bash
ssh-keygen -t ed25519
```

得到两个文件：`id_ed25519`（**私钥，严格保密**）和 `id_ed25519.pub`（公钥，要上传到服务器）。

### 2. 把脚本和公钥传到服务器

```bash
# 在服务器上下载脚本（把 <your-username>/<repo> 换成实际仓库地址）
wget https://raw.githubusercontent.com/<your-username>/<repo>/main/vps-harden.sh
# 建议先阅读脚本内容再运行
less vps-harden.sh
```

把公钥文件 `id_ed25519.pub` 上传到服务器（面板文件管理、`scp` 均可），例如放到 `/root/id_ed25519.pub`：

```bash
scp ~/.ssh/id_ed25519.pub root@服务器IP:/root/
```

### 3. 预览（不修改任何东西）

```bash
sudo bash vps-harden.sh --dry-run \
  --user admin --pubkey-file /root/id_ed25519.pub \
  --allow-tcp 443,8443 --allow-udp 443 \
  --ignore-ip 你的公网IP
```

重点看输出：

- `可用公钥 : 有`（如果是"无"，先不要继续）
- `关闭密码登录 : 是`
- `[防火墙]` 下的端口是否包含你的服务端口

### 4. 正式运行

把上一步命令里的 `--dry-run` 去掉：

```bash
sudo bash vps-harden.sh \
  --user admin --pubkey-file /root/id_ed25519.pub \
  --allow-tcp 443,8443 --allow-udp 443 \
  --ignore-ip 你的公网IP
```

运行结束后，脚本会提示**自动回滚倒计时已开始**（默认 10 分钟）。

### 5. 另开一个终端测试（关键）

**不要关闭原来的窗口。** 在自己电脑上新开终端：

```bash
ssh admin@服务器IP
sudo whoami        # 应输出 root
```

同时测试你的服务（例如代理客户端能否连接）。

### 6. 自检并确认

```bash
sudo bash vps-harden.sh --check     # 没有 FAIL 即可，WARN 请看原因
sudo bash vps-harden.sh --confirm   # 取消自动回滚，加固永久生效
```

> **如果忘记执行 `--confirm`**，倒计时结束后 SSH 配置会被恢复、防火墙会被关闭。这是设计如此，不是故障。

### 7. 重启（可选）

系统更新后可能需要重启。重启前请确认你的服务已设置开机自启。

## 运行模式

| 命令 | 作用 |
|---|---|
| （默认） | 正式加固 |
| `--dry-run` | 只预览，不修改系统 |
| `--check` | 只读自检，有 FAIL 时退出码为 1 |
| `--confirm` | 确认新配置可用，取消自动回滚 |
| `--rollback-now` | 立即回滚 SSH 与防火墙到加固前 |

## 参数说明

### 账户与 SSH

| 参数 | 说明 |
|---|---|
| `--user NAME` | 创建带 sudo 权限的普通用户（仅密钥登录，默认免密 sudo） |
| `--pubkey 'KEY'` | 把公钥内容写入该用户（未指定 `--user` 则写入 root） |
| `--pubkey-file FILE` | 同上，从文件读取公钥 |
| `--copy-root-keys` | 把 root 现有公钥复制给 `--user` 指定的新用户 |
| `--sudo-password` | 新用户执行 sudo 需要密码（会提示设置；设置失败则回退为免密） |
| `--ssh-port N` | 更换 SSH 端口（旧端口会保留，确认新端口可用后再手动移除） |
| `--no-root-login` | 禁止 root 登录（需同时指定 `--user`，且新用户已有公钥） |
| `--ssh-profile P` | `compat`（默认，兼容常见客户端）或 `strict`（更严格的算法与会话数） |
| `--allow-ssh-forwarding` | 允许 SSH 端口转发（默认禁用） |

### 防火墙与 fail2ban

| 参数 | 说明 |
|---|---|
| `--allow-tcp 443,8443` | 额外放行的 TCP 端口（逗号分隔） |
| `--allow-udp 443` | 额外放行的 UDP 端口（逗号分隔） |
| `--allow-from IP,端口/协议` | 仅对指定来源 IP 放行，可重复，例如 `--allow-from 1.2.3.4,8080/tcp` |
| `--no-auto-allow` | 不自动放行"当前正在监听"的端口 |
| `--ufw-limit` | 对 SSH 启用 ufw 连接限速（默认关闭，依赖 fail2ban） |
| `--ignore-ip IP[,IP]` | fail2ban 白名单（通过面板或网页终端运行时无法自动识别你的 IP，请手动指定） |

### 其他

| 参数 | 说明 |
|---|---|
| `--skip-ssh` / `--skip-firewall` / `--skip-sysctl` / `--skip-fail2ban` / `--skip-audit` | 跳过对应模块 |
| `--rollback-minutes N` | 自动回滚等待分钟数（默认 10；0 表示不设置） |
| `--no-rollback-timer` | 关闭自动回滚（不推荐） |
| `--enable-bbr` | 启用 BBR + fq（性能优化，非安全项） |
| `--with-aide` | 安装并初始化 AIDE 文件完整性数据库（耗时较长） |
| `--skip-lynis` | 跳过 Lynis 前后评分 |
| `-y`, `--yes` | 非交互模式，所有确认默认同意（新手不建议） |
| `-h`, `--help` | 显示帮助 |

## 使用示例

```bash
# 最常用：新建用户 + 公钥 + 放行服务端口
sudo bash vps-harden.sh --user admin --pubkey-file /root/id_ed25519.pub \
  --allow-tcp 443 --allow-udp 443 --ignore-ip 1.2.3.4

# 服务商已把公钥注入 root：直接复制给新用户，并禁止 root 登录
sudo bash vps-harden.sh --user admin --copy-root-keys --no-root-login \
  --allow-tcp 443

# 管理面板端口只允许自己的 IP 访问
sudo bash vps-harden.sh --user admin --copy-root-keys \
  --allow-tcp 443 --allow-from 1.2.3.4,8080/tcp

# 只做 SSH 加固，不动防火墙和内核参数
sudo bash vps-harden.sh --user admin --pubkey-file /root/id_ed25519.pub \
  --skip-firewall --skip-sysctl

# 更换 SSH 端口(旧端口会暂时保留)
sudo bash vps-harden.sh --user admin --copy-root-keys --ssh-port 2222 \
  --allow-tcp 443
```

## 脚本会改动什么

**SSH**：新增 `/etc/ssh/sshd_config.d/00-hardening.conf`（老系统必要时在 `sshd_config` 顶部补一行 `Include`）；写入登录横幅 `/etc/issue`、`/etc/issue.net`。有有效公钥时关闭密码登录，限制认证次数，禁用 X11 / 代理转发 / 端口转发（可选放开）。

**防火墙**：安装并启用 `ufw`，默认拒绝入站、允许出站，放行 SSH 与你指定/检测到的服务端口。

**fail2ban**：`/etc/fail2ban/jail.d/99-hardening.local`，SSH 暴力破解递增封禁，支持白名单。

**内核与系统**：`/etc/sysctl.d/99-hardening.conf`、`/etc/modprobe.d/99-hardening.conf`（禁用冷门内核模块）、关闭 core dump、`/etc/login.defs` 与口令复杂度策略、关键文件权限、日志持久化、关闭 LLMNR/mDNS、`/etc/hosts` 补主机名。

**审计与更新**：`auditd` 规则、`rkhunter`、自动安全更新（不自动重启）。

**会安装的软件包**：`ufw fail2ban python3-systemd unattended-upgrades apt-listchanges needrestart libpam-pwquality libpam-tmpdir debsums apt-show-versions auditd rsyslog logrotate chrony rkhunter acct sysstat lynis`（`--with-aide` 时额外安装 `aide`）。

**会停用的服务（若存在）**：`avahi-daemon cups cups-browsed rpcbind bluetooth ModemManager`。

**备份与日志**：

- 改动前的文件备份：`/root/harden-backup-时间戳/`
- 运行日志：`/var/log/vps-harden-时间戳.log`
- 回滚脚本：`/root/harden-rollback-时间戳.sh`

## 防锁死设计与回滚

1. 没有有效公钥 → 不关闭密码登录。
2. `sshd -t` 校验失败 → 自动撤销本次 SSH 改动。
3. 防火墙规则逐条写入并核对，有一条失败就**不启用**防火墙。
4. 自动回滚定时器：改动 SSH / 防火墙之前就已设置，加固结束后重置为 `--rollback-minutes`。
5. 回滚会：恢复 SSH 配置、删除脚本的 fail2ban 配置、**关闭 ufw**。（它是紧急退路，不会撤销用户创建、软件包安装、sysctl 等其他改动。）

**手动回滚**：

```bash
sudo bash vps-harden.sh --rollback-now
```

如果 SSH 已经连不上，请通过服务商的 **VNC / 网页控制台**登录，再执行上面的命令，或把 `/root/harden-backup-*/` 下的文件按原路径拷回。

## 常见问题

**Q：运行后代理 / 网站连不上了？**
先执行 `sudo bash vps-harden.sh --check`。如果看到"正在监听，但防火墙未放行"，补放行即可：`sudo ufw allow 443/tcp`（端口按实际修改）。同时检查云厂商的**安全组**是否放行。

**Q：脚本提示"未检测到有效 SSH 公钥"？**
这是防锁死保护：此时不会关闭密码登录。请确认公钥文件路径正确、内容是以 `ssh-ed25519` 或 `ssh-rsa` 开头的**公钥**（`.pub`），不是私钥。

**Q：为什么 10 分钟后 SSH / 防火墙被恢复了？**
因为没有执行 `--confirm`。自动回滚保险生效。请重新运行脚本，测试通过后及时 `--confirm`。

**Q：输错密钥几次就连不上了？**
fail2ban 会封禁失败次数过多的 IP（默认 1 小时）。通过 VNC 控制台执行 `fail2ban-client unban 你的IP`，并在运行脚本时用 `--ignore-ip` 加入白名单。

**Q：面板 / 网页终端上传文件卡住？**
面板通常用面板服务器的 IP 连接你的 VPS，可能被 fail2ban 封禁。可用 `fail2ban-client status sshd` 查看，并用 `--ignore-ip` 加入白名单；也可以改用 `scp` 上传。

**Q：用了 Docker，端口为什么仍可从外部访问？**
Docker 发布的端口会绕过 ufw。请改为绑定 `127.0.0.1`，或使用 `DOCKER-USER` 链做限制。

**Q：怎么只给自己的 IP 开放管理面板端口？**
使用 `--allow-from 你的IP,端口/tcp`，并且**不要**用 `--allow-tcp` 放行同一个端口。

## 关于 Lynis 评分

在一台全新的 Debian 13 KVM VPS 上实测：**62 → 80**。再往上走，剩余项目多数是 VPS 上做不到的（`/home`、`/var` 独立分区，GRUB 口令等），或与实际安全关系不大。分数仅供参考，**不等同于安全**；达到 90 分在 VPS 上通常较难，也不建议为分数做有风险的改动。

## 已知限制

- 仅支持 Debian / Ubuntu（不支持 CentOS、Rocky、Alpine 等）。
- OpenVZ / LXC 等容器型 VPS：部分 sysctl、内核模块、auditd 项无法生效。
- 云厂商安全组不在脚本管理范围内，需要在控制台单独放行端口。
- 使用 Docker 时，容器发布的端口会绕过 ufw。
- `rp_filter` 严格模式在多网卡 / 策略路由（如 WireGuard、Tailscale）场景下可能影响网络，这类机器请先阅读 `configure_sysctl` 部分再决定是否使用 `--skip-sysctl`。
- 默认会把 `UMASK` 改为 027，并禁用 SSH 端口转发（可用 `--allow-ssh-forwarding` 放开）。
- 回滚只覆盖 SSH 与防火墙。

## 贡献与反馈

欢迎提交 Issue 和 Pull Request。反馈问题时请附上：系统版本（`cat /etc/os-release`）、虚拟化类型（`systemd-detect-virt`）、运行命令（**请去掉你的 IP、用户名和密钥等敏感信息**）以及日志 `/var/log/vps-harden-*.log` 中的相关片段。

## 许可证

[MIT](LICENSE)
