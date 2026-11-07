#!/usr/bin/env bash
#===============================================================================
# vps-harden.sh  v1.2  —  Debian / Ubuntu VPS 安全加固脚本
#
# 设计原则：
#   1. 防锁死：先加防火墙放行规则再启用；SSH 配置经 sshd -t 校验后才 reload；
#      未检测到有效公钥时，绝不关闭密码登录；并设置"自动回滚定时器"——
#      加固后若 N 分钟内没有执行 --confirm，SSH 与防火墙将自动恢复到加固前。
#   2. 防误伤：默认自动放行"当前正在对外监听"的端口(代理服务不会被挡)；
#      默认的 SSH 配置兼容常见客户端(--ssh-profile strict 才启用最严格选项)。
#   3. 可预览、可核对：--dry-run 只看不改；--check 加固后只读自检。
#   4. 可重复运行(幂等)；所有被改动的配置先备份到 /root/harden-backup-时间戳/。
#   5. 前后各跑一次 Lynis，给出真实的 Hardening index，不凭空承诺分数。
#
# 推荐流程：
#   1) 预览:   sudo bash vps-harden.sh --dry-run --user admin --pubkey-file /root/key.pub \
#                      --allow-tcp 443,8443 --allow-udp 443
#   2) 执行:   去掉 --dry-run 重新运行
#   3) 测试:   另开终端用新用户+密钥登录，确认代理端口可用
#   4) 自检:   sudo bash vps-harden.sh --check
#   5) 确认:   sudo bash vps-harden.sh --confirm      (取消自动回滚，使加固永久生效)
#===============================================================================
set -uo pipefail

readonly SCRIPT_VERSION="1.2"
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/harden-backup-${TS}"
LOG_FILE="/var/log/vps-harden-${TS}.log"

MODE="run"                 # run | dry | check | confirm | rollback
SSH_PORT_NEW=""
NEW_USER=""
PUBKEY=""
PUBKEY_FILE=""
ALLOW_TCP=""
ALLOW_UDP=""
AUTO_ALLOW=1
NO_ROOT_LOGIN=0
SSH_FORWARDING=0
SSH_PROFILE="compat"       # compat | strict
UFW_LIMIT=0
IGNORE_IPS=""
COPY_ROOT_KEYS=0
SUDO_PASSWORD=0
ENABLE_BBR=0
WITH_AIDE=0
SKIP_LYNIS=0
SKIP_SSH=0
SKIP_FIREWALL=0
SKIP_SYSCTL=0
SKIP_FAIL2BAN=0
SKIP_AUDIT=0
ROLLBACK_MIN=10
ASSUME_YES=0

declare -a ALLOW_FROM=()
declare -a SSH_PORTS=()
declare -a CUR_SSH_PORTS=()
declare -a FW_RULES=()
declare -A FW_PROC=()
HAVE_KEY=0
SCORE_BEFORE=""
SCORE_AFTER=""
RB_ARMED=0
RB_SCRIPT=""
EPH_LO=32768
EPH_HI=60999

PKGS=(ufw fail2ban python3-systemd unattended-upgrades apt-listchanges needrestart
      libpam-pwquality libpam-tmpdir debsums apt-show-versions auditd rsyslog
      logrotate chrony rkhunter acct sysstat)

#------------------------------- 工具函数 --------------------------------------
info() { printf '[INFO]  %s\n' "$*"; }
ok()   { printf '[ OK ]  %s\n' "$*"; }
warn() { printf '[WARN]  %s\n' "$*" >&2; }
die()  { printf '[FAIL]  %s\n' "$*" >&2; exit 1; }
step() { printf '\n==== %s ====\n' "$*"; }

usage() {
  cat <<'EOF'
用法: sudo bash vps-harden.sh [选项]

运行模式(默认为正式加固):
  --dry-run                只预览将要做什么，不修改系统
  --check                  只读自检：核对 SSH/防火墙/端口/fail2ban 等是否正常
  --confirm                确认新配置可用，取消自动回滚定时器
  --rollback-now           立即执行回滚(恢复 SSH 与防火墙到加固前)

账户与 SSH:
  --user NAME              创建具备 sudo 权限的普通用户(仅密钥登录)
  --pubkey 'KEY'           写入该用户(未指定 --user 则为 root)的 authorized_keys
  --pubkey-file FILE       同上，从文件读取公钥
  --copy-root-keys         把 root 现有的公钥复制给 --user 指定的新用户
  --sudo-password          新用户 sudo 需要密码(默认免密 sudo)；会提示设置密码
  --ssh-port N             更换 SSH 端口(旧端口会保留，确认新端口可用后再手动移除)
  --no-root-login          禁止 root 登录(需同时指定 --user，且新用户已有公钥)
  --ssh-profile P          compat(默认，兼容常见客户端) 或 strict(最严格算法与会话数)
  --allow-ssh-forwarding   允许 SSH 端口转发(默认禁用)

防火墙与 fail2ban:
  --allow-tcp 443,8443     额外放行的 TCP 端口(逗号分隔)
  --allow-udp 443          额外放行的 UDP 端口(逗号分隔)
  --allow-from IP,PORT/P   仅对指定来源 IP 放行端口，可重复。例: --allow-from 1.2.3.4,46124/tcp
  --no-auto-allow          不自动放行"当前正在监听"的端口
  --ufw-limit              对 SSH 启用 ufw 连接限速(默认关闭，依赖 fail2ban)
  --ignore-ip IP[,IP]      fail2ban 白名单(通过面板/网页终端运行时请务必填自己的 IP)

模块开关与其他:
  --skip-ssh --skip-firewall --skip-sysctl --skip-fail2ban --skip-audit
  --rollback-minutes N     自动回滚等待分钟数(默认 10；0 表示不设置自动回滚)
  --no-rollback-timer      等同 --rollback-minutes 0
  --enable-bbr             启用 BBR + fq(提升网络性能，非安全项)
  --with-aide              安装并初始化 AIDE 完整性数据库(耗时较长)
  --skip-lynis             跳过 Lynis 前后评分
  -y, --yes                非交互模式，所有确认默认同意
  -h, --help               显示帮助
EOF
}

need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || die "参数 $1 需要一个值"; }

backup() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  mkdir -p "${BACKUP_DIR}$(dirname "$f")"
  cp -a "$f" "${BACKUP_DIR}${f}" 2>/dev/null || true
}

# write_file PATH MODE  (内容从 stdin 读入；写前自动备份)
write_file() {
  local path="$1" mode="${2:-644}"
  backup "$path"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
}

confirm() {
  local prompt="$1" ans=""
  [[ $ASSUME_YES -eq 1 ]] && return 0
  if [[ -r /dev/tty ]]; then
    read -r -p "$prompt [y/N] " ans </dev/tty || true
  else
    warn "没有可用的终端，无法交互确认；请加 -y 或在终端中运行。"
    return 1
  fi
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_ip()   { [[ "$1" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]]; }

valid_portlist() {
  local list="$1" p
  [[ -z "$list" ]] && return 0
  IFS=',' read -r -a _ports <<< "$list"
  for p in "${_ports[@]}"; do valid_port "$p" || return 1; done
}

APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300)
apt_run() {
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 apt-get "${APT_OPTS[@]}" "$@"
}
apt_install() {
  local p
  for p in "$@"; do
    if dpkg -s "$p" >/dev/null 2>&1; then continue; fi
    if apt_run install --no-install-recommends "$p" >/dev/null 2>&1; then
      ok "已安装 $p"
    else
      warn "安装 $p 失败，已跳过"
    fi
  done
}

svc_exists() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1.service"; }

load_eph_range() {
  if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
    read -r EPH_LO EPH_HI < /proc/sys/net/ipv4/ip_local_port_range
  fi
}

# 系统自带/客户端型端口：不应对公网放行，也不应被当作"缺失规则"
is_noise_port() {
  local proto="$1" port="$2"
  case "$port" in 5355|5353) return 0 ;; esac
  if [[ "$proto" == "udp" ]]; then
    case "$port" in 68|123|323|546) return 0 ;; esac
    (( port >= EPH_LO && port <= EPH_HI )) && return 0
  fi
  return 1
}

#------------------------------- 参数解析 --------------------------------------
parse_args() {
  local v
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)              MODE="dry"; shift ;;
      --check)                MODE="check"; shift ;;
      --confirm)              MODE="confirm"; shift ;;
      --rollback-now)         MODE="rollback"; shift ;;
      --ssh-port)             need_arg "$@"; SSH_PORT_NEW="$2"; shift 2 ;;
      --user)                 need_arg "$@"; NEW_USER="$2"; shift 2 ;;
      --pubkey)               need_arg "$@"; PUBKEY="$2"; shift 2 ;;
      --pubkey-file)          need_arg "$@"; PUBKEY_FILE="$2"; shift 2 ;;
      --copy-root-keys)       COPY_ROOT_KEYS=1; shift ;;
      --sudo-password)        SUDO_PASSWORD=1; shift ;;
      --allow-tcp)            need_arg "$@"; ALLOW_TCP="$2"; shift 2 ;;
      --allow-udp)            need_arg "$@"; ALLOW_UDP="$2"; shift 2 ;;
      --allow-from)           need_arg "$@"; ALLOW_FROM+=("$2"); shift 2 ;;
      --no-auto-allow)        AUTO_ALLOW=0; shift ;;
      --ufw-limit)            UFW_LIMIT=1; shift ;;
      --ignore-ip)            need_arg "$@"; IGNORE_IPS="$2"; shift 2 ;;
      --no-root-login)        NO_ROOT_LOGIN=1; shift ;;
      --ssh-profile)          need_arg "$@"; SSH_PROFILE="$2"; shift 2 ;;
      --allow-ssh-forwarding) SSH_FORWARDING=1; shift ;;
      --skip-ssh)             SKIP_SSH=1; shift ;;
      --skip-firewall)        SKIP_FIREWALL=1; shift ;;
      --skip-sysctl)          SKIP_SYSCTL=1; shift ;;
      --skip-fail2ban)        SKIP_FAIL2BAN=1; shift ;;
      --skip-audit)           SKIP_AUDIT=1; shift ;;
      --rollback-minutes)     need_arg "$@"; ROLLBACK_MIN="$2"; shift 2 ;;
      --no-rollback-timer)    ROLLBACK_MIN=0; shift ;;
      --enable-bbr)           ENABLE_BBR=1; shift ;;
      --with-aide)            WITH_AIDE=1; shift ;;
      --skip-lynis)           SKIP_LYNIS=1; shift ;;
      -y|--yes)               ASSUME_YES=1; shift ;;
      -h|--help)              usage; exit 0 ;;
      *) usage; die "未知参数: $1" ;;
    esac
  done

  [[ -z "$SSH_PORT_NEW" ]] || valid_port "$SSH_PORT_NEW" || die "--ssh-port 不是有效端口"
  valid_portlist "$ALLOW_TCP" || die "--allow-tcp 含无效端口"
  valid_portlist "$ALLOW_UDP" || die "--allow-udp 含无效端口"
  [[ "$ROLLBACK_MIN" =~ ^[0-9]+$ ]] || die "--rollback-minutes 必须是非负整数"
  case "$SSH_PROFILE" in compat|strict) ;; *) die "--ssh-profile 只能是 compat 或 strict" ;; esac

  if [[ -n "$IGNORE_IPS" ]]; then
    for v in ${IGNORE_IPS//,/ }; do valid_ip "$v" || die "--ignore-ip 含无效地址: $v"; done
  fi
  for v in "${ALLOW_FROM[@]:-}"; do
    [[ -n "$v" ]] || continue
    local ip pp port proto
    ip="${v%%,*}"; pp="${v#*,}"
    [[ "$v" == *,* ]] || die "--allow-from 格式应为 IP,端口/协议，例如 1.2.3.4,46124/tcp"
    port="${pp%%/*}"; proto="tcp"; [[ "$pp" == */* ]] && proto="${pp#*/}"
    valid_ip "$ip" && valid_port "$port" && [[ "$proto" =~ ^(tcp|udp)$ ]] \
      || die "--allow-from 参数无效: $v"
  done

  if [[ -n "$NEW_USER" ]]; then
    [[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--user 用户名不合法"
    [[ "$NEW_USER" != "root" ]] || die "--user 不能是 root"
  fi
  if [[ -n "$PUBKEY_FILE" ]]; then
    [[ -r "$PUBKEY_FILE" ]] || die "无法读取 --pubkey-file: $PUBKEY_FILE"
    PUBKEY="$(grep -Ev '^\s*(#|$)' "$PUBKEY_FILE" | head -n1)"
  fi
  if [[ $NO_ROOT_LOGIN -eq 1 && -z "$NEW_USER" ]]; then
    die "--no-root-login 需要同时指定 --user，否则会失去管理员登录方式"
  fi
  if [[ ( $COPY_ROOT_KEYS -eq 1 || $SUDO_PASSWORD -eq 1 ) && -z "$NEW_USER" ]]; then
    die "--copy-root-keys / --sudo-password 需要同时指定 --user"
  fi
}

#------------------------------- 预检 ------------------------------------------
detect_ssh_ports() {
  mkdir -p /run/sshd
  mapfile -t CUR_SSH_PORTS < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un)
  [[ ${#CUR_SSH_PORTS[@]} -gt 0 ]] || CUR_SSH_PORTS=(22)
  SSH_PORTS=("${CUR_SSH_PORTS[@]}")
}

preflight() {
  step "环境检查"
  [[ $EUID -eq 0 ]] || die "请使用 root 运行: sudo bash $0"
  [[ -r /etc/os-release ]] || die "无法识别系统"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ok "系统: ${PRETTY_NAME:-$ID}" ;;
    *) die "仅支持 Debian / Ubuntu，当前: ${PRETTY_NAME:-unknown}" ;;
  esac
  [[ -d /run/systemd/system ]] || die "需要 systemd"
  command -v apt-get >/dev/null || die "缺少 apt-get"

  local virt
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  info "虚拟化类型: ${virt:-none}"
  case "$virt" in
    openvz|lxc|lxc-libvirt|systemd-nspawn|docker|podman)
      warn "容器型 VPS：部分 sysctl / 内核模块 / auditd 项无法生效，评分会偏低，属正常现象。" ;;
  esac

  load_eph_range
  detect_ssh_ports
  info "当前 SSH 端口: ${CUR_SSH_PORTS[*]}"

  if [[ -n "$SSH_PORT_NEW" ]]; then
    local found=0 p
    for p in "${CUR_SSH_PORTS[@]}"; do [[ "$p" == "$SSH_PORT_NEW" ]] && found=1; done
    if [[ $found -eq 0 ]]; then
      if ss -H -tln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${SSH_PORT_NEW}$"; then
        die "端口 ${SSH_PORT_NEW} 已被其他服务占用，请更换"
      fi
      SSH_PORTS=("$SSH_PORT_NEW" "${CUR_SSH_PORTS[@]}")
    fi
  fi
}

show_plan() {
  step "执行计划"
  cat <<EOF
  系统更新与自动安全更新
  SSH 加固        : $([[ $SKIP_SSH -eq 1 ]] && echo "跳过" || echo "端口 ${SSH_PORTS[*]}；配置档 ${SSH_PROFILE}；仅在检测到有效公钥时关闭密码登录")
  新建 sudo 用户  : ${NEW_USER:-(不创建)}$([[ $SUDO_PASSWORD -eq 1 ]] && echo "，sudo 需要密码")$([[ $COPY_ROOT_KEYS -eq 1 ]] && echo "，复制 root 公钥")
  禁止 root 登录  : $([[ $NO_ROOT_LOGIN -eq 1 ]] && echo 是 || echo "否(配置公钥后 root 仅允许密钥登录)")
  防火墙(ufw)     : $([[ $SKIP_FIREWALL -eq 1 ]] && echo "跳过" || echo "默认拒绝入站；放行 SSH$([[ $UFW_LIMIT -eq 1 ]] && echo '(限速)')、$([[ $AUTO_ALLOW -eq 1 ]] && echo '当前监听端口、')手动指定端口")
  fail2ban        : $([[ $SKIP_FAIL2BAN -eq 1 ]] && echo "跳过" || echo "SSH 暴力破解防护(递增封禁)")
  内核/网络加固   : $([[ $SKIP_SYSCTL -eq 1 ]] && echo "跳过" || echo "sysctl、禁用冷门内核模块、禁用 core dump")
  审计与完整性    : $([[ $SKIP_AUDIT -eq 1 ]] && echo "跳过" || echo "auditd、rkhunter$([[ $WITH_AIDE -eq 1 ]] && echo '、AIDE')")
  自动回滚保险    : $([[ $ROLLBACK_MIN -gt 0 ]] && echo "开启 —— 加固后 ${ROLLBACK_MIN} 分钟内未执行 --confirm 将自动恢复 SSH/防火墙" || echo "关闭")
  备份目录        : ${BACKUP_DIR}
  日志文件        : ${LOG_FILE}

  重要：请保持当前 SSH 会话不要关闭；完成后另开终端测试登录。
EOF
  confirm "确认开始加固？" || die "已取消"
}

#------------------------------- 预览模式 --------------------------------------
dry_run_report() {
  preflight
  step "预览模式(dry-run)：不会修改系统"
  local key_ok=0 tmp p r who miss="" saved_yes="$ASSUME_YES"

  if [[ -n "$PUBKEY" ]]; then
    tmp="$(mktemp)"; printf '%s\n' "$PUBKEY" > "$tmp"
    if ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then key_ok=1; else warn "提供的公钥格式无效，将被忽略"; fi
    rm -f "$tmp"
  fi
  user_has_valid_key root && key_ok=1
  if [[ -n "$NEW_USER" ]] && id "$NEW_USER" >/dev/null 2>&1 && user_has_valid_key "$NEW_USER"; then key_ok=1; fi
  if [[ $COPY_ROOT_KEYS -eq 1 ]] && user_has_valid_key root; then key_ok=1; fi

  echo "  [账户]"
  echo "    新用户             : ${NEW_USER:-无}"
  echo "    可用公钥           : $([[ $key_ok -eq 1 ]] && echo 有 || echo "无 —— 将不会关闭密码登录")"
  echo "    关闭密码登录       : $([[ $key_ok -eq 1 && $SKIP_SSH -eq 0 ]] && echo 是 || echo 否)"
  echo "    root 登录          : $([[ $NO_ROOT_LOGIN -eq 1 ]] && echo "禁止" || echo "保持/仅密钥")"
  echo "  [SSH]"
  echo "    端口               : ${SSH_PORTS[*]}"
  echo "    配置档             : ${SSH_PROFILE}$([[ $SKIP_SSH -eq 1 ]] && echo '(已跳过)')"
  echo "    端口转发           : $([[ $SSH_FORWARDING -eq 1 ]] && echo 允许 || echo 禁用)"

  echo "  [防火墙]"
  if [[ $SKIP_FIREWALL -eq 1 ]]; then
    echo "    已跳过"
  else
    ASSUME_YES=1; build_fw_rules; ASSUME_YES="$saved_yes"
    for p in "${SSH_PORTS[@]}"; do printf '    %-14s %s\n' "${p}/tcp" "(SSH$([[ $UFW_LIMIT -eq 1 ]] && echo '，限速'))"; done
    for r in "${FW_RULES[@]:-}"; do
      [[ -n "$r" ]] || continue
      who="${FW_PROC[$r]:-手动指定}"; printf '    %-14s %s\n' "$r" "(${who})"
    done
    for r in "${ALLOW_FROM[@]:-}"; do [[ -n "$r" ]] && printf '    %-14s %s\n' "$r" "(仅限该来源 IP)"; done
    (( ${#FW_RULES[@]} == 0 )) && warn "除 SSH 外没有放行端口；若有代理/网站服务，请用 --allow-tcp/--allow-udp 指定"
  fi

  echo "  [fail2ban 白名单]"
  echo "    当前登录 IP        : $(detect_client_ip || echo '未能识别(通过面板/网页终端运行时请用 --ignore-ip 指定)')"
  echo "    额外白名单         : ${IGNORE_IPS:-无}"

  echo "  [软件包]"
  for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || miss+="$p "; done
  echo "    将安装             : ${miss:-(均已安装)}"
  echo "  [模块]"
  echo "    sysctl/模块黑名单  : $([[ $SKIP_SYSCTL -eq 1 ]] && echo 跳过 || echo 执行)"
  echo "    auditd/rkhunter    : $([[ $SKIP_AUDIT -eq 1 ]] && echo 跳过 || echo 执行)"
  echo "  [安全保险]"
  echo "    自动回滚           : $([[ $ROLLBACK_MIN -gt 0 ]] && echo "开启(${ROLLBACK_MIN} 分钟)" || echo 关闭)"
  echo
  info "以上仅为预览。确认无误后，去掉 --dry-run 正式运行。"
}

#------------------------------- 自动回滚 --------------------------------------
write_rollback_script() {
  RB_SCRIPT="/root/harden-rollback-${TS}.sh"
  cat > "$RB_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# 由 vps-harden.sh 自动生成：把 SSH 与防火墙恢复到加固前的状态
BK="__BK__"
restore() { local f="$1"; if [[ -e "$BK$f" ]]; then cp -a "$BK$f" "$f"; else rm -f "$f"; fi; }
restore /etc/ssh/sshd_config.d/00-hardening.conf
[[ -e "$BK/etc/ssh/sshd_config" ]] && cp -a "$BK/etc/ssh/sshd_config" /etc/ssh/sshd_config
rm -f /etc/fail2ban/jail.d/99-hardening.local
command -v ufw >/dev/null 2>&1 && ufw --force disable >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1
if sshd -t 2>/dev/null; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
fi
logger -t vps-harden "自动回滚已执行：SSH 与防火墙已恢复到加固前状态"
echo "[rollback] SSH 与防火墙已恢复到加固前状态"
EOF
  sed -i "s|__BK__|${BACKUP_DIR}|g" "$RB_SCRIPT"
  chmod 700 "$RB_SCRIPT"
}

# arm_rollback 分钟数 —— 重复调用会重置倒计时
arm_rollback() {
  local minutes="${1:-$ROLLBACK_MIN}" unit="harden-rollback-${TS}"
  [[ $ROLLBACK_MIN -gt 0 ]] || return 0
  [[ -n "$RB_SCRIPT" && -f "$RB_SCRIPT" ]] || write_rollback_script
  systemctl stop "${unit}.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
  if systemd-run --quiet --unit="$unit" --on-active="${minutes}m" \
        --description="vps-harden auto rollback" /bin/bash "$RB_SCRIPT" >/dev/null 2>&1; then
    RB_ARMED=1
    ok "自动回滚已设置：${minutes} 分钟后恢复 SSH/防火墙(确认可用后执行 --confirm 取消)"
  else
    RB_ARMED=0
    warn "无法创建自动回滚定时器(缺少 systemd-run 或权限受限)，请务必保持当前会话并确认 VNC 控制台可用。"
  fi
}

list_rollback_timers() {
  systemctl list-units --all --plain --no-legend 'harden-rollback-*.timer' 2>/dev/null | awk '{print $1}'
}

do_confirm() {
  local u n=0
  for u in $(list_rollback_timers); do
    systemctl stop "$u" >/dev/null 2>&1 && n=$((n+1))
  done
  if (( n > 0 )); then
    ok "已取消自动回滚(${n} 个定时器)，加固配置将保持生效"
  else
    info "当前没有待执行的自动回滚定时器"
  fi
}

do_rollback_now() {
  local f
  f="$(ls -1t /root/harden-rollback-*.sh 2>/dev/null | head -n1)"
  [[ -n "$f" ]] || die "没有找到回滚脚本(/root/harden-rollback-*.sh)"
  warn "即将执行回滚: $f"
  confirm "确认立即回滚 SSH 与防火墙？" || die "已取消"
  bash "$f"
  do_confirm
}

#------------------------------- APT / 更新 ------------------------------------
apt_prepare() {
  step "更新软件源并安装基础工具"
  apt_run update >/dev/null 2>&1 || warn "apt update 失败，请检查网络/源"
  apt_install ca-certificates curl sudo lynis
}

lynis_score() {
  command -v lynis >/dev/null || return 0
  lynis audit system --quiet --no-colors >/dev/null 2>&1 || true
  awk -F= '/^hardening_index=/{print $2}' /var/log/lynis-report.dat 2>/dev/null | tail -n1
}

lynis_baseline() {
  [[ $SKIP_LYNIS -eq 1 ]] && return 0
  step "Lynis 基线评分(加固前)"
  SCORE_BEFORE="$(lynis_score)"
  info "加固前 Hardening index: ${SCORE_BEFORE:-未知}"
}

system_update() {
  step "系统更新"
  apt_run upgrade >/dev/null 2>&1 && ok "系统软件包已更新" || warn "系统更新出现问题，请稍后手动检查"
  if [[ -f /var/run/reboot-required ]]; then
    warn "内核等组件已更新，建议在脚本完成后择机重启(会短暂中断代理服务)。"
  fi
}

install_packages() {
  step "安装安全组件"
  apt_install "${PKGS[@]}"
  [[ $WITH_AIDE -eq 1 ]] && apt_install aide aide-common

  # needrestart 仅列出需要重启的服务，不自动重启(避免误重启代理进程)
  if [[ -d /etc/needrestart ]]; then
    mkdir -p /etc/needrestart/conf.d
    printf "\$nrconf{restart} = 'l';\n" | write_file /etc/needrestart/conf.d/90-hardening.conf 644
  fi
}

#------------------------------- 用户与密钥 ------------------------------------
home_of() { getent passwd "$1" | cut -d: -f6; }

install_pubkey() {
  local user="$1" key="$2" home tmp
  home="$(home_of "$user")"
  [[ -n "$home" && -d "$home" ]] || { warn "用户 $user 的家目录不存在"; return 1; }
  tmp="$(mktemp)"; printf '%s\n' "$key" > "$tmp"
  if ! ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"; warn "提供的公钥格式无效，已忽略"; return 1
  fi
  rm -f "$tmp"
  mkdir -p "$home/.ssh"; chmod 700 "$home/.ssh"
  touch "$home/.ssh/authorized_keys"
  backup "$home/.ssh/authorized_keys"
  grep -qxF "$key" "$home/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
  chmod 600 "$home/.ssh/authorized_keys"
  chown -R "$user":"$(id -gn "$user")" "$home/.ssh"
  ok "公钥已写入 $user"
}

user_has_valid_key() {
  local user="$1" home f
  home="$(home_of "$user")"; [[ -n "$home" ]] || return 1
  f="$home/.ssh/authorized_keys"
  [[ -s "$f" ]] || return 1
  grep -Ev '^\s*(#|$)' "$f" | grep -q . || return 1
  ssh-keygen -l -f "$f" >/dev/null 2>&1
}

grant_nopasswd_sudo() {
  local user="$1" f="/etc/sudoers.d/90-$1"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "$f"
  chmod 440 "$f"
  if ! visudo -cf "$f" >/dev/null 2>&1; then
    rm -f "$f"; warn "sudoers 校验失败，已撤销免密 sudo 配置"; return 1
  fi
  ok "$user 已获得 sudo 权限(免密，仅密钥登录)"
}

setup_user_and_keys() {
  step "用户与 SSH 公钥"
  if [[ -n "$NEW_USER" ]]; then
    if id "$NEW_USER" >/dev/null 2>&1; then
      info "用户 $NEW_USER 已存在"
    else
      adduser --disabled-password --gecos "" "$NEW_USER" >/dev/null && ok "已创建用户 $NEW_USER"
    fi
    usermod -aG sudo "$NEW_USER"

    if [[ $SUDO_PASSWORD -eq 1 ]]; then
      rm -f "/etc/sudoers.d/90-${NEW_USER}"
      if [[ $ASSUME_YES -eq 0 && -r /dev/tty ]]; then
        info "请为 $NEW_USER 设置 sudo 密码(仅用于 sudo，不能用于 SSH 登录)"
        passwd "$NEW_USER" </dev/tty || true
      fi
      if [[ "$(passwd -S "$NEW_USER" 2>/dev/null | awk '{print $2}')" == "P" ]]; then
        ok "$NEW_USER 的 sudo 将要求输入密码"
      else
        warn "未成功设置 sudo 密码，为避免失去管理权限，回退为免密 sudo。"
        grant_nopasswd_sudo "$NEW_USER" || true
      fi
    else
      grant_nopasswd_sudo "$NEW_USER" || true
    fi

    if [[ $COPY_ROOT_KEYS -eq 1 ]]; then
      if [[ -s /root/.ssh/authorized_keys ]]; then
        local line n=0
        while IFS= read -r line; do
          [[ -z "$line" || "$line" == \#* ]] && continue
          install_pubkey "$NEW_USER" "$line" && n=$((n+1))
        done < /root/.ssh/authorized_keys
        info "已从 root 复制 ${n} 个公钥到 $NEW_USER"
      else
        warn "root 没有 authorized_keys，--copy-root-keys 无内容可复制"
      fi
    fi
  fi

  if [[ -n "$PUBKEY" ]]; then
    install_pubkey "${NEW_USER:-root}" "$PUBKEY" || true
  fi

  HAVE_KEY=0
  if user_has_valid_key root || { [[ -n "$NEW_USER" ]] && user_has_valid_key "$NEW_USER"; }; then
    HAVE_KEY=1
    ok "检测到有效 SSH 公钥，将关闭密码登录"
  else
    warn "未检测到有效 SSH 公钥 —— 为避免锁死，本次不会关闭密码登录。"
    warn "请先添加公钥(--pubkey/--pubkey-file/--copy-root-keys)后重新运行本脚本。"
  fi
}

#------------------------------- SSH 加固 --------------------------------------
write_banner() {
  local text="Authorized access only. All activity may be monitored and logged. Unauthorized use is prohibited."
  printf '%s\n' "$text" | write_file /etc/issue 644
  printf '%s\n' "$text" | write_file /etc/issue.net 644
}

configure_ssh() {
  step "SSH 加固"
  command -v sshd >/dev/null || { warn "未安装 openssh-server，跳过"; return 0; }

  local main=/etc/ssh/sshd_config drop=/etc/ssh/sshd_config.d/00-hardening.conf
  mkdir -p /etc/ssh/sshd_config.d /run/sshd

  # 老系统(如 Ubuntu 20.04)主配置可能没有 Include
  if ! grep -Eqi '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$main"; then
    backup "$main"
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$main"
  fi

  local root_mode=""
  if [[ $NO_ROOT_LOGIN -eq 1 ]] && [[ -n "$NEW_USER" ]] && user_has_valid_key "$NEW_USER"; then
    root_mode="no"
  elif [[ $NO_ROOT_LOGIN -eq 1 ]]; then
    warn "新用户尚无有效公钥，为防锁死，root 暂不禁用(改为仅密钥)"
    root_mode="prohibit-password"
  elif [[ $HAVE_KEY -eq 1 ]]; then
    root_mode="prohibit-password"
  fi

  local kbd="KbdInteractiveAuthentication"
  sshd -T 2>/dev/null | grep -q '^kbdinteractiveauthentication' || kbd="ChallengeResponseAuthentication"

  local max_sessions=10
  [[ "$SSH_PROFILE" == "strict" ]] && max_sessions=2

  local tmp; tmp="$(mktemp)"
  {
    echo "# 由 vps-harden.sh ${SCRIPT_VERSION} 生成于 ${TS}(配置档: ${SSH_PROFILE})；文件名以 00 开头以确保优先生效"
    if [[ -n "$SSH_PORT_NEW" ]]; then
      local p; for p in "${SSH_PORTS[@]}"; do echo "Port $p"; done
    fi
    [[ -n "$root_mode" ]] && echo "PermitRootLogin $root_mode"
    if [[ $HAVE_KEY -eq 1 ]]; then
      echo "PasswordAuthentication no"
      echo "$kbd no"
    fi
    cat <<EOF
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions ${max_sessions}
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding $([[ $SSH_FORWARDING -eq 1 ]] && echo yes || echo no)
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
Compression no
UseDNS no
LogLevel VERBOSE
Banner /etc/issue.net
EOF
    if [[ "$SSH_PROFILE" == "strict" ]]; then
      cat <<'EOF'
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
    fi
  } > "$tmp"

  local had_drop=0
  [[ -f "$drop" ]] && had_drop=1 && backup "$drop"
  cp "$tmp" "$drop"; chmod 600 "$drop"; rm -f "$tmp"

  write_banner   # 先写好登录横幅，避免 Banner 指向不存在的文件

  local errf; errf="$(mktemp)"
  if ! sshd -t 2>"$errf"; then
    warn "sshd 配置校验失败，已回滚: $(cat "$errf")"; rm -f "$errf"
    if [[ $had_drop -eq 1 && -f "${BACKUP_DIR}${drop}" ]]; then cp -a "${BACKUP_DIR}${drop}" "$drop"; else rm -f "$drop"; fi
    return 1
  fi
  rm -f "$errf"
  ok "sshd 配置校验通过"

  # Ubuntu 22.10+/24.04 默认 socket 激活，Port 配置会被忽略，需要切换到常规服务
  if [[ -n "$SSH_PORT_NEW" ]] && systemctl is-enabled ssh.socket >/dev/null 2>&1; then
    info "检测到 ssh.socket，切换为 ssh.service 以使端口配置生效"
    systemctl disable --now ssh.socket >/dev/null 2>&1 || true
    systemctl enable --now ssh.service >/dev/null 2>&1 || true
  fi

  local svc=ssh; svc_exists ssh || svc=sshd
  if systemctl reload "$svc" 2>/dev/null || systemctl restart "$svc" 2>/dev/null; then
    ok "SSH 服务已重新加载(现有会话不受影响)"
  else
    warn "SSH 服务重载失败，请手动检查: systemctl status $svc"
  fi

  sleep 1
  local p
  for p in "${SSH_PORTS[@]}"; do
    if ss -H -tln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"; then
      ok "SSH 正在监听端口 $p"
    else
      warn "未检测到 SSH 监听端口 $p，请在断开会话前确认！"
    fi
  done
  info "生效配置: $(sshd -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin|maxauthtries|maxsessions) ' | tr '\n' ' ')"

  chmod 600 "$main" 2>/dev/null || true
}

#------------------------------- 服务清理 --------------------------------------
disable_unneeded_services() {
  step "停用不必要的服务"
  local s
  for s in avahi-daemon cups cups-browsed rpcbind bluetooth ModemManager; do
    if svc_exists "$s"; then
      systemctl disable --now "$s" >/dev/null 2>&1 && ok "已停用 $s" || true
    fi
  done
  systemctl disable --now rpcbind.socket >/dev/null 2>&1 || true
}

#------------------------------- 内核与网络 ------------------------------------
configure_sysctl() {
  step "内核与网络参数加固"
  write_file /etc/sysctl.d/99-hardening.conf 644 <<'EOF'
# 由 vps-harden.sh 生成
# --- 网络 ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
# --- 内核 ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.kexec_load_disabled = 1
dev.tty.ldisc_autoload = 0
vm.mmap_min_addr = 65536
# --- 文件系统 ---
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
  # -e: 忽略当前内核不支持的键，避免整体失败
  sysctl -e -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1 && ok "sysctl 已应用" || warn "部分 sysctl 项未能应用(容器或旧内核常见)"

  if [[ $ENABLE_BBR -eq 1 ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      write_file /etc/sysctl.d/99-bbr.conf 644 <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
      sysctl -e -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 && ok "已启用 BBR"
    else
      warn "内核不支持 BBR，已跳过"
    fi
  fi
}

configure_kernel_modules() {
  step "禁用冷门内核模块 / core dump"
  write_file /etc/modprobe.d/99-hardening.conf 644 <<'EOF'
# 由 vps-harden.sh 生成：禁用 VPS 上用不到且存在历史漏洞的模块
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install firewire-core /bin/false
install usb-storage /bin/false
EOF
  write_file /etc/security/limits.d/99-hardening.conf 644 <<'EOF'
* hard core 0
EOF
  write_file /etc/systemd/coredump.conf.d/99-hardening.conf 644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  ok "模块黑名单与 core dump 策略已写入"
}

#------------------------------- 账户与系统策略 --------------------------------
setdef() {
  local k="$1" v="$2" f=/etc/login.defs
  if grep -Eq "^\s*${k}\s" "$f"; then
    sed -i -E "s|^\s*${k}\s.*|${k}\t${v}|" "$f"
  else
    printf '%s\t%s\n' "$k" "$v" >> "$f"
  fi
}

configure_system_policies() {
  step "账户、口令与系统策略"
  backup /etc/login.defs
  setdef UMASK 027
  setdef PASS_MAX_DAYS 365
  setdef PASS_MIN_DAYS 1
  setdef PASS_WARN_AGE 7
  setdef LOG_OK_LOGINS yes
  setdef SHA_CRYPT_MIN_ROUNDS 100000
  setdef SHA_CRYPT_MAX_ROUNDS 100000
  ok "login.defs 已调整"

  if [[ -f /etc/security/pwquality.conf ]] && ! grep -q 'vps-harden' /etc/security/pwquality.conf; then
    backup /etc/security/pwquality.conf
    cat >> /etc/security/pwquality.conf <<'EOF'

# vps-harden
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    ok "口令复杂度策略已设置"
  fi

  # 关键文件权限
  chmod 700 /root 2>/dev/null || true
  chmod 600 /etc/crontab 2>/dev/null || true
  chmod -R go-rwx /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
  chmod 644 /etc/passwd /etc/group 2>/dev/null || true
  chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true

  # 日志持久化
  write_file /etc/systemd/journald.conf.d/99-hardening.conf 644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
ForwardToSyslog=no
EOF
  systemctl restart systemd-journald >/dev/null 2>&1 || true

  # sysstat / acct / chrony / rsyslog
  if [[ -f /etc/default/sysstat ]]; then
    sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
    systemctl enable --now sysstat >/dev/null 2>&1 || true
  fi
  svc_exists acct && systemctl enable --now acct >/dev/null 2>&1 || true
  svc_exists chrony && systemctl enable --now chrony >/dev/null 2>&1 || true
  svc_exists rsyslog && systemctl enable --now rsyslog >/dev/null 2>&1 || true

  # 主机名写入 /etc/hosts
  local hn; hn="$(hostname 2>/dev/null)"
  if [[ -n "$hn" ]] && ! grep -Eq "[[:space:]]${hn}([[:space:]]|\$)" /etc/hosts; then
    backup /etc/hosts
    printf '127.0.1.1\t%s\n' "$hn" >> /etc/hosts
  fi

  # 关闭 LLMNR / mDNS(不影响正常 DNS 解析)
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    write_file /etc/systemd/resolved.conf.d/99-hardening.conf 644 <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
EOF
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi

  # 清理无用依赖与已卸载包的残留配置
  apt_run autoremove --purge >/dev/null 2>&1 || true
  dpkg -l 2>/dev/null | awk '/^rc/{print $2}' | xargs -r dpkg --purge >/dev/null 2>&1 || true

  # 空口令账户检查(仅报告)
  local empty
  empty="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
  [[ -z "$empty" ]] || warn "发现空口令账户: $empty —— 请手动处理(passwd -l 账户名)"
}

#------------------------------- 防火墙 ----------------------------------------
detect_listening() {
  # 输出 "proto port 进程名"，忽略仅监听回环地址的服务
  ss -H -tulnp 2>/dev/null | awk '{
    proto=$1; addr=$5; proc="-"
    if (addr ~ /^127\./ || addr ~ /^\[::1\]/ || addr ~ /^::1/) next
    if (match($0, /users:\(\("[^"]+"/)) proc=substr($0, RSTART+9, RLENGTH-10)
    n=split(addr, a, ":"); port=a[n]
    if (port ~ /^[0-9]+$/) print proto, port, proc
  }' | sort -u
}

# 规则统一使用 ufw 要求的 "端口/协议" 格式，例如 443/tcp
build_fw_rules() {
  FW_RULES=(); FW_PROC=()
  declare -A seen=()
  local proto port proc s is_ssh p k
  load_eph_range

  if [[ $AUTO_ALLOW -eq 1 ]]; then
    while read -r proto port proc; do
      [[ -n "${port:-}" ]] || continue
      proto="${proto%%[0-9]*}"
      case "$proto" in tcp|udp) ;; *) continue ;; esac
      is_noise_port "$proto" "$port" && continue
      is_ssh=0
      for s in "${SSH_PORTS[@]}"; do [[ "$s" == "$port" && "$proto" == "tcp" ]] && is_ssh=1; done
      [[ $is_ssh -eq 1 ]] && continue
      [[ -n "${seen["$port/$proto"]:-}" ]] && continue

      if [[ "$proto" == "tcp" ]] && (( port >= EPH_LO && port <= EPH_HI )); then
        if [[ $ASSUME_YES -eq 1 ]] || ! confirm "检测到高位 TCP 端口 ${port}(进程: ${proc})，可能是管理面板，是否对公网放行？"; then
          info "未对公网放行 ${port}/tcp；如需访问，建议 --allow-from 你的IP,${port}/tcp，或确需公开时用 --allow-tcp ${port}"
          continue
        fi
      fi
      seen["$port/$proto"]=1
      FW_PROC["$port/$proto"]="$proc"
    done < <(detect_listening)
  fi

  if [[ -n "$ALLOW_TCP" ]]; then
    IFS=',' read -r -a _t <<< "$ALLOW_TCP"
    for p in "${_t[@]}"; do seen["$p/tcp"]=1; done
  fi
  if [[ -n "$ALLOW_UDP" ]]; then
    IFS=',' read -r -a _u <<< "$ALLOW_UDP"
    for p in "${_u[@]}"; do seen["$p/udp"]=1; done
  fi

  for k in "${!seen[@]}"; do FW_RULES+=("$k"); done
  if (( ${#FW_RULES[@]} > 0 )); then
    mapfile -t FW_RULES < <(printf '%s\n' "${FW_RULES[@]}" | sort -t/ -k1,1n -k2,2)
  fi
}

configure_firewall() {
  step "防火墙(ufw)"
  command -v ufw >/dev/null || { warn "ufw 未安装，跳过防火墙"; return 0; }
  build_fw_rules

  local p r who fail=0 e ip pp port proto
  echo "  将放行的入站端口:"
  for p in "${SSH_PORTS[@]}"; do printf '    %-14s %s\n' "${p}/tcp" "(SSH$([[ $UFW_LIMIT -eq 1 ]] && echo '，限速'))"; done
  for r in "${FW_RULES[@]:-}"; do
    [[ -n "$r" ]] || continue
    who="${FW_PROC[$r]:-手动指定}"
    printf '    %-14s %s\n' "$r" "(${who})"
  done
  for e in "${ALLOW_FROM[@]:-}"; do [[ -n "$e" ]] && printf '    %-14s %s\n' "$e" "(仅限该来源 IP)"; done
  echo "  其余入站连接将被拒绝。"
  if (( ${#FW_RULES[@]} == 0 )); then
    warn "除 SSH 外没有任何放行端口！如果这台机器运行着代理/网站服务，启用防火墙后将无法从外部访问。"
    warn "请用 --allow-tcp / --allow-udp 指定端口(例如 --allow-tcp 443 --allow-udp 443)。"
  fi
  if ! confirm "按此规则启用防火墙？"; then
    warn "已跳过防火墙配置"
    return 0
  fi

  [[ -f /etc/default/ufw ]] && { backup /etc/default/ufw; sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw; }

  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for p in "${SSH_PORTS[@]}"; do
    if [[ $UFW_LIMIT -eq 1 ]]; then
      ufw limit "${p}/tcp" comment 'SSH' >/dev/null 2>&1 || { warn "添加 SSH 规则失败: ${p}/tcp"; fail=1; }
    else
      ufw allow "${p}/tcp" comment 'SSH' >/dev/null 2>&1 || { warn "添加 SSH 规则失败: ${p}/tcp"; fail=1; }
    fi
  done
  for r in "${FW_RULES[@]:-}"; do
    [[ -n "$r" ]] || continue
    ufw allow "$r" >/dev/null 2>&1 || { warn "添加规则失败: $r"; fail=1; }
  done
  for e in "${ALLOW_FROM[@]:-}"; do
    [[ -n "$e" ]] || continue
    ip="${e%%,*}"; pp="${e#*,}"; port="${pp%%/*}"; proto="tcp"; [[ "$pp" == */* ]] && proto="${pp#*/}"
    ufw allow from "$ip" to any port "$port" proto "$proto" >/dev/null 2>&1 || { warn "添加来源限制规则失败: $e"; fail=1; }
  done
  ufw logging low >/dev/null

  # 启用前逐条核对：SSH 与所有计划放行的端口都必须已写入规则，否则绝不启用
  local added
  added="$(ufw show added 2>/dev/null)"
  for p in "${SSH_PORTS[@]}"; do
    grep -Eq "(allow|limit) ${p}/tcp" <<< "$added" || { warn "SSH 规则未生效: ${p}/tcp"; fail=1; }
  done
  for r in "${FW_RULES[@]:-}"; do
    [[ -n "$r" ]] || continue
    grep -Fq "allow ${r}" <<< "$added" || { warn "放行规则未生效: $r"; fail=1; }
  done
  for e in "${ALLOW_FROM[@]:-}"; do
    [[ -n "$e" ]] || continue
    ip="${e%%,*}"; pp="${e#*,}"; port="${pp%%/*}"; proto="tcp"; [[ "$pp" == */* ]] && proto="${pp#*/}"
    grep -Fq "allow from ${ip} to any port ${port} proto ${proto}" <<< "$added" || { warn "来源限制规则未生效: $e"; fail=1; }
  done
  if (( fail )); then
    warn "放行规则校验未通过，为避免锁死或中断服务，本次未启用防火墙。"
    return 1
  fi

  ufw --force enable >/dev/null && ok "ufw 已启用" || warn "ufw 启用失败"
  ufw status verbose | sed 's/^/    /'
  warn "提示：若使用 Docker，容器发布的端口会绕过 ufw，请用 DOCKER-USER 链或仅绑定 127.0.0.1。"
}

#------------------------------- fail2ban --------------------------------------
detect_client_ip() {
  local ip="${SSH_CLIENT:-}"
  ip="${ip%% *}"
  if [[ -z "$ip" ]]; then
    ip="$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')"
  fi
  if [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then echo "$ip"; return 0; fi
  return 1
}

configure_fail2ban() {
  step "fail2ban"
  command -v fail2ban-client >/dev/null || { warn "fail2ban 未安装，跳过"; return 0; }
  local ports client banact allports ignore v
  ports="$(IFS=,; echo "${SSH_PORTS[*]}")"
  client="$(detect_client_ip || true)"

  if ufw status 2>/dev/null | grep -q "Status: active"; then
    banact="ufw"; allports="ufw"
  elif command -v nft >/dev/null 2>&1; then
    banact="nftables"; allports="nftables[type=allports]"
  else
    banact="iptables-multiport"; allports="iptables-allports"
  fi

  ignore="127.0.0.1/8 ::1"
  [[ -n "$client" ]] && ignore+=" $client"
  for v in ${IGNORE_IPS//,/ }; do ignore+=" $v"; done

  write_file /etc/fail2ban/jail.d/99-hardening.local 644 <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 4
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w
banaction = ${banact}
banaction_allports = ${allports}
ignoreip = ${ignore}

[sshd]
enabled = true
port = ${ports}
backend = systemd
mode = aggressive
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  if systemctl restart fail2ban 2>/dev/null; then
    sleep 2
    if fail2ban-client status sshd >/dev/null 2>&1; then
      ok "fail2ban 已启用 sshd 防护(封禁动作: ${banact})"
      info "白名单: ${ignore}"
      [[ -n "$client" || -n "$IGNORE_IPS" ]] || warn "未能识别你的登录 IP，建议下次用 --ignore-ip 你的IP，避免输错密钥时把自己封掉。"
    else
      warn "fail2ban 已启动但 sshd jail 未就绪，请查看: journalctl -u fail2ban"
    fi
  else
    warn "fail2ban 启动失败，请查看: journalctl -u fail2ban"
  fi
}

#------------------------------- 审计 / 更新 / 完整性 --------------------------
configure_audit() {
  step "审计(auditd)"
  if ! command -v auditctl >/dev/null; then warn "auditd 未安装，跳过"; return 0; fi
  write_file /etc/audit/rules.d/99-hardening.rules 640 <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
EOF
  systemctl enable --now auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 && ok "审计规则已加载" || warn "审计规则加载失败(容器环境常见)，已写入配置文件"
}

configure_auto_updates() {
  step "自动安全更新"
  write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  write_file /etc/apt/apt.conf.d/52unattended-upgrades-hardening 644 <<'EOF'
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// 为避免意外中断代理服务，不自动重启；内核更新后请择机手动重启
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "已启用 unattended-upgrades"
}

configure_integrity() {
  step "完整性检查"
  if command -v rkhunter >/dev/null; then
    [[ -f /etc/default/rkhunter ]] && sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
    rkhunter --propupd >/dev/null 2>&1 && ok "rkhunter 基线已建立" || warn "rkhunter 基线建立失败"
  fi
  if [[ $WITH_AIDE -eq 1 ]] && command -v aideinit >/dev/null; then
    info "正在初始化 AIDE 数据库(可能需要数分钟)..."
    aideinit -y -f >/dev/null 2>&1 && ok "AIDE 数据库已初始化" || warn "AIDE 初始化失败"
  fi
}

#------------------------------- 只读自检 --------------------------------------
CK_FAIL=0
CK_WARN=0
ck_pass() { printf '[PASS]  %s\n' "$*"; }
ck_warn() { printf '[WARN]  %s\n' "$*"; CK_WARN=$((CK_WARN+1)); }
ck_fail() { printf '[FAIL]  %s\n' "$*"; CK_FAIL=$((CK_FAIL+1)); }

ck_sysctl() {
  local k="$1" want="$2" v
  v="$(sysctl -n "$k" 2>/dev/null || true)"
  [[ -n "$v" ]] || return 0
  if [[ "$v" == "$want" ]]; then ck_pass "sysctl $k = $v"; else ck_warn "sysctl $k = $v(期望 $want)"; fi
}

run_check() {
  [[ $EUID -eq 0 ]] || die "请使用 root 运行: sudo bash $0 --check"
  load_eph_range
  detect_ssh_ports

  step "SSH"
  local eff pa root pk mt
  eff="$(sshd -T 2>/dev/null || true)"
  if [[ -z "$eff" ]]; then
    ck_warn "无法读取 sshd 生效配置(未安装 openssh-server 或权限不足)"
    pa=""; root=""
  else
    pa="$(awk '$1=="passwordauthentication"{print $2}' <<<"$eff")"
    root="$(awk '$1=="permitrootlogin"{print $2}' <<<"$eff")"
    pk="$(awk '$1=="pubkeyauthentication"{print $2}' <<<"$eff")"
    mt="$(awk '$1=="maxauthtries"{print $2}' <<<"$eff")"
    ck_pass "SSH 监听端口: ${SSH_PORTS[*]}"
    [[ "$pa" == "no" ]] && ck_pass "密码登录已关闭" || ck_warn "密码登录仍开启(passwordauthentication=$pa)"
    case "$root" in
      no) ck_pass "root 登录已禁止" ;;
      without-password|prohibit-password) ck_pass "root 仅允许密钥登录" ;;
      *) ck_warn "root 允许密码登录(permitrootlogin=$root)" ;;
    esac
    [[ "$pk" == "yes" ]] && ck_pass "公钥认证已启用" || ck_warn "公钥认证未启用"
    [[ -n "$mt" && "$mt" -le 4 ]] 2>/dev/null && ck_pass "MaxAuthTries = $mt" || ck_warn "MaxAuthTries = ${mt:-?}"
  fi

  # 锁死风险：密码登录已关，却没有任何可用密钥的登录用户
  local u have_key=0
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    if user_has_valid_key "$u"; then
      if [[ "$u" == "root" && "$root" == "no" ]]; then continue; fi
      have_key=1; ck_pass "用户 $u 配有有效 SSH 公钥"
    fi
  done < <({ echo root; getent passwd | awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false)$/ {print $1}'; })
  if [[ "$pa" == "no" && $have_key -eq 0 ]]; then
    ck_fail "密码登录已关闭，但没有任何可用的密钥登录用户 —— 有被锁在门外的风险！请立即通过 VNC 控制台处理。"
  fi

  step "防火墙与端口"
  local ufw_state allowed listening line proto port proc tok
  if ! command -v ufw >/dev/null; then
    ck_warn "未安装 ufw"
  else
    ufw_state="$(ufw status 2>/dev/null || true)"
    if grep -q '^Status: active' <<<"$ufw_state"; then
      ck_pass "ufw 已启用"
      allowed="$(awk '/ALLOW|LIMIT/ && !/\(v6\)/ {print $1}' <<<"$ufw_state" | sort -u)"
      listening=""
      while read -r proto port proc; do
        [[ -n "${port:-}" ]] || continue
        proto="${proto%%[0-9]*}"
        case "$proto" in tcp|udp) ;; *) continue ;; esac
        is_noise_port "$proto" "$port" && continue
        listening+="${port}/${proto}"$'\n'
        if grep -Fxq "${port}/${proto}" <<<"$allowed" || grep -Fxq "$port" <<<"$allowed"; then
          ck_pass "端口 ${port}/${proto}(${proc})：正在监听且已放行"
        else
          ck_warn "端口 ${port}/${proto}(${proc})：正在监听，但防火墙未放行，外部无法访问"
        fi
      done < <(detect_listening)
      while IFS= read -r tok; do
        [[ "$tok" =~ ^[0-9]+/(tcp|udp)$ ]] || continue
        grep -Fxq "$tok" <<<"$listening" || info "规则 $tok 已放行，但当前没有服务在监听(可能是服务未启动，或规则已过时)"
      done <<<"$allowed"
    else
      ck_warn "ufw 未启用(防火墙未生效)"
    fi
  fi

  step "fail2ban"
  if command -v fail2ban-client >/dev/null && fail2ban-client status sshd >/dev/null 2>&1; then
    line="$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/[ \t]/,"",$2); print $2}')"
    ck_pass "fail2ban sshd 防护运行中(当前封禁 ${line:-0} 个 IP)"
  else
    ck_warn "fail2ban 的 sshd jail 未运行"
  fi

  step "内核参数(抽样)"
  ck_sysctl net.ipv4.tcp_syncookies 1
  ck_sysctl net.ipv4.conf.all.accept_redirects 0
  ck_sysctl kernel.kptr_restrict 2
  ck_sysctl kernel.dmesg_restrict 1
  ck_sysctl fs.protected_symlinks 1

  step "服务与状态"
  local s
  for s in auditd chrony rsyslog fail2ban; do
    if svc_exists "$s"; then
      systemctl is-active --quiet "$s" && ck_pass "$s 运行中" || ck_warn "$s 未运行"
    fi
  done
  systemctl is-enabled --quiet unattended-upgrades 2>/dev/null && ck_pass "自动安全更新已启用" || ck_warn "自动安全更新未启用"
  [[ -f /var/run/reboot-required ]] && ck_warn "系统需要重启以应用内核/库更新(重启前请确认代理服务已设置开机自启)"
  if [[ -n "$(list_rollback_timers)" ]]; then
    ck_warn "自动回滚定时器仍在倒计时！确认新配置可用后请执行: sudo bash $SELF --confirm"
  else
    ck_pass "没有待执行的自动回滚定时器"
  fi

  echo
  printf '检查完成：FAIL %d，WARN %d\n' "$CK_FAIL" "$CK_WARN"
  [[ $CK_FAIL -eq 0 ]]
}

#------------------------------- 收尾 ------------------------------------------
finalize() {
  step "完成"
  if [[ $SKIP_LYNIS -eq 0 ]]; then
    info "正在运行 Lynis 复评(约 1-2 分钟)..."
    SCORE_AFTER="$(lynis_score)"
  fi
  # 此时才给用户留出完整的测试时间：重置倒计时
  [[ $RB_ARMED -eq 1 ]] && arm_rollback "$ROLLBACK_MIN"

  cat <<EOF

  ------------------------------ 加固结果 ------------------------------
  Lynis Hardening index : ${SCORE_BEFORE:-N/A}  ->  ${SCORE_AFTER:-N/A}
  SSH 端口              : ${SSH_PORTS[*]}
  密码登录              : $([[ $HAVE_KEY -eq 1 && $SKIP_SSH -eq 0 ]] && echo 已关闭 || echo "未关闭")
  备份目录              : ${BACKUP_DIR}
  完整日志              : ${LOG_FILE}
  -----------------------------------------------------------------------
EOF

  if [[ $RB_ARMED -eq 1 ]]; then
    cat <<EOF

  【限时确认】自动回滚倒计时已开始：${ROLLBACK_MIN} 分钟
    若在此时间内没有执行确认，SSH 与防火墙会自动恢复到加固前状态(防止把你锁在门外)。
    请按顺序操作：
      1) 另开一个终端，用新用户 + 密钥登录：ssh -p ${SSH_PORTS[0]} ${NEW_USER:-root}@<服务器IP>
      2) 测试 sudo、测试代理端口是否可用
      3) 自检：  sudo bash ${SELF} --check
      4) 确认：  sudo bash ${SELF} --confirm      <-- 执行后加固才永久生效
EOF
  else
    cat <<EOF

  【请立即测试】
    1) 保持当前会话，另开终端登录：ssh -p ${SSH_PORTS[0]} ${NEW_USER:-root}@<服务器IP>
    2) 测试代理端口；然后运行自检：sudo bash ${SELF} --check
EOF
  fi

  cat <<EOF

  其他：
    - 若更换了 SSH 端口且新端口测试成功，再移除旧端口：
        编辑 /etc/ssh/sshd_config.d/00-hardening.conf 与 /etc/ssh/sshd_config 去掉旧 Port；
        ufw delete allow <旧端口>/tcp ; systemctl reload ssh
    - 如提示需要重启(内核更新)，确认代理服务开机自启后择机 reboot。
    - 手动回滚：sudo bash ${SELF} --rollback-now ；或把 ${BACKUP_DIR}/ 下的文件按原路径拷回。

EOF

  if [[ $HAVE_KEY -eq 0 && $SKIP_SSH -eq 0 ]]; then
    cat <<'EOF'
  【重要】当前仍允许密码登录(未检测到公钥)，这是最大的剩余风险。请：
    1) 在你自己的电脑生成密钥: ssh-keygen -t ed25519
    2) 把公钥(.pub)上传到服务器，例如 /root/id_ed25519.pub
    3) 重新运行: bash vps-harden.sh --user admin --pubkey-file /root/id_ed25519.pub \
                    --allow-tcp <代理TCP端口> --allow-udp <代理UDP端口>

EOF
  fi

  if [[ $SKIP_LYNIS -eq 0 && -f /var/log/lynis-report.dat ]]; then
    echo "  Lynis 仍建议的改进项(前 15 条，可据此继续加固):"
    grep '^suggestion\[\]=' /var/log/lynis-report.dat 2>/dev/null | head -n 15 | sed 's/^suggestion\[\]=/    - /; s/|/  /g'
  fi

  if [[ -n "$SCORE_AFTER" ]] && (( SCORE_AFTER < 90 )); then
    echo
    echo "  说明：Lynis 90 分在 VPS 上通常较难达到(无法拆分 /tmp、/var 等独立分区、"
    echo "  无法设置 GRUB 口令等)。分数只是参考，不等同于安全。请以上方建议逐项评估。"
  fi
}

#------------------------------- 主流程 ----------------------------------------
main() {
  parse_args "$@"
  [[ $EUID -eq 0 ]] || die "请使用 root 运行: sudo bash $0"

  case "$MODE" in
    confirm)  do_confirm; exit 0 ;;
    rollback) do_rollback_now; exit 0 ;;
    check)    run_check; exit $? ;;
    dry)      dry_run_report; exit 0 ;;
  esac

  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1

  info "vps-harden.sh v${SCRIPT_VERSION} 开始运行 ($(date '+%F %T'))"
  preflight
  show_plan
  apt_prepare
  lynis_baseline
  system_update
  install_packages
  setup_user_and_keys

  # 在改动 SSH/防火墙之前先布好"自动回滚"保险；初始倒计时多留 15 分钟覆盖脚本运行时间
  if (( ! SKIP_SSH || ! SKIP_FIREWALL )); then
    write_rollback_script
    arm_rollback $(( ROLLBACK_MIN + 15 ))
  fi

  (( SKIP_SSH )) || configure_ssh
  disable_unneeded_services
  if (( ! SKIP_SYSCTL )); then configure_sysctl; configure_kernel_modules; fi
  configure_system_policies
  (( SKIP_FIREWALL )) || configure_firewall
  (( SKIP_FAIL2BAN )) || configure_fail2ban
  (( SKIP_AUDIT )) || configure_audit
  configure_auto_updates
  (( SKIP_AUDIT )) || configure_integrity
  finalize
}

main "$@"
