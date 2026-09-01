#!/usr/bin/env bash
# ============================================================================
#  ZavetSec-Harden  ::  Ubuntu 26.04 LTS "Resolute Raccoon"  ::  DESKTOP
#
#  Переработка v1.5-ubuntu под 26.04 desktop. Основной принцип этой версии:
#  НИЧЕГО НЕ ЛОМАТЬ. Всё, что могло оставить пользователя без сети, без
#  печати, без входа, без USB или без DVD — убрано или переведено в opt-in.
#
#  Что УБРАНО по сравнению с v1.5 (и почему):
#    * ufw больше не включается сам — только с --enable-firewall
#    * cron.allow/at.allow allow-list — ломал cron обычным пользователям
#    * pam_faillock в PAM-стеке — риск полного локаута, вырезан целиком
#    * apt purge legacy-пакетов — теперь только предупреждение
#    * blacklist udf/hfs/hfsplus — ломал DVD/ISO и диски с macOS
#    * disable usb-storage — ломал флешки
#    * noexec на /tmp и /dev/shm — ломает Chrome/Electron/JVM/инсталляторы
#    * ptrace_scope=2 — ломает gdb/strace, на десктопе оставлен 1
#    * отключение avahi/cups/bluetooth/ModemManager — печать, BT, LTE
#    * ip_forward=0 — ломал Docker/libvirt/VM-сети (теперь opt-in + автодетект)
#    * rp_filter=1 strict — ломал split-tunnel VPN (теперь 2, loose)
#    * SSH_DISABLE_PASSWORD, MaxSessions 2, AllowTcpForwarding no
#    * перезапись /etc/issue (терялись escape-последовательности getty)
#    * audit -e 2 (immutable) — только через явный тюн
#
#  Что ПОЧИНЕНО под 26.04:
#    * детект SSH-порта при socket-activation (ss показывает systemd, не sshd)
#    * KexAlgorithms больше не выбрасывает mlkem768x25519-sha256 (PQC OpenSSH 10)
#    * sudo-rs: Defaults logfile не пишется (visudo-rs его отвергает)
#    * sysctl никогда не ПОНИЖАЕТ уже более строгое значение системы
#    * audit-правила b32 только на x86_64; путь sudo резолвится (sudo-rs симлинк)
#    * /var/run/utmp -> /run/utmp
#
#  Что ДОБАВЛЕНО (логирование):
#    * persistent journald + лимиты хранения и ретенция
#    * /etc/audit/auditd.conf: ротация и реакция на нехватку места
#    * расширенные audit-правила: pam, sshd_config, systemd, nsswitch, pkexec
#    * отчёт о состоянии логирования в audit-режиме
#
#  Использование:
#    sudo ./zavetsec-harden-2604-desktop.sh                # dry-run (по умолчанию)
#    sudo ./zavetsec-harden-2604-desktop.sh --audit        # только проверка + отчёт
#    sudo ./zavetsec-harden-2604-desktop.sh --apply        # применить
#    sudo ./zavetsec-harden-2604-desktop.sh --apply --enable-firewall
#    sudo ./zavetsec-harden-2604-desktop.sh --only journald,auditd --apply
#    sudo bash <state-dir>/rollback.sh                     # откатить прогон
# ============================================================================
set -uo pipefail

ZSVER="2.0-desktop-2604"

# printf в bash выравнивает поля по БАЙТАМ, а кириллица — 2 байта на символ,
# из-за чего таблицы разъезжались. Считаем длину в символах: для этого нужна
# UTF-8 локаль, и дальше выравниваем сами через _pad().
if [[ -z "${LC_ALL:-}" ]] && locale -a 2>/dev/null | grep -qix 'c.utf8'; then
    export LC_ALL=C.UTF-8
fi
_pad() {
    local w="$1" s="$2" n
    n=${#s}
    printf '%s' "$s"
    (( n < w )) && printf '%*s' $((w-n)) ''
    return 0
}

# --- Цвета ------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RST=$'\e[0m'; C_GRN=$'\e[38;5;48m'; C_RED=$'\e[38;5;203m'
    C_YEL=$'\e[38;5;221m'; C_CYN=$'\e[38;5;80m'; C_DIM=$'\e[2m'; C_BLD=$'\e[1m'
else
    C_RST=''; C_GRN=''; C_RED=''; C_YEL=''; C_CYN=''; C_DIM=''; C_BLD=''
fi

# --- Состояние --------------------------------------------------------------
MODE="dryrun"
ONLY=""; SKIP=""; DETECT_ONLY=0; FORCE=0; WANT_FW=0
REPORT_DIR="."; FMT="both"
RUN_TS="$(date +%Y%m%d-%H%M%S)"
STATE_DIR="/var/log/zavetsec-harden/${RUN_TS}"

MODULES=(sysctl-kernel sysctl-network journald auditd ssh auth \
         filesystem services extras apparmor misc firewall)

# ============================================================================
#  ЛОГ / СОСТОЯНИЕ
# ============================================================================
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
CURMOD="core"
LOG_FILE="/dev/null"; CHANGES="/dev/null"; ROLLBACK="/dev/null"; BACKUP_DIR=""

log() {
    local lvl="$1"; shift; local col tag
    case "$lvl" in
        OK)   col="$C_GRN"; tag="OK  ";; INFO) col="$C_CYN"; tag="INFO";;
        WARN) col="$C_YEL"; tag="WARN";; ERR)  col="$C_RED"; tag="ERR ";;
        DRY)  col="$C_DIM"; tag="DRY ";; *)    col="$C_RST"; tag="$lvl";;
    esac
    printf '%s[%s]%s %s%s%s %s\n' "$col" "$tag" "$C_RST" "$C_DIM" "$CURMOD:" "$C_RST" "$*"
    printf '%s [%s] %s: %s\n' "$(_ts)" "$tag" "$CURMOD" "$*" >> "$LOG_FILE" 2>/dev/null || true
}
die()  { log ERR "$*"; exit 1; }
risk() { local l="$1"; shift; case "$l" in
    HIGH) log WARN "РИСК[ВЫС] $*";; MED) log INFO "РИСК[СРЕД] $*";; *) log INFO "РИСК[НИЗ] $*";; esac; }
record()   { printf '%s\t%s\t%s\n' "$CURMOD" "$(_ts)" "$*" >> "$CHANGES" 2>/dev/null || true; }
is_apply() { [[ "$MODE" == "apply" ]]; }

run()   { if is_apply; then "$@"; else log DRY "выполнил бы: $*"; return 0; fi; }
run_q() { if is_apply; then "$@" >/dev/null 2>&1; else log DRY "выполнил бы: $*"; return 0; fi; }
add_rollback() { is_apply || return 0; printf '%s\n' "$*" >> "$ROLLBACK"; }

backup() {
    local f="$1"; [[ -e "$f" ]] || return 0; is_apply || return 0
    local dest="${BACKUP_DIR}${f}"
    if [[ ! -e "$dest" ]]; then
        mkdir -p "$(dirname "$dest")"
        cp -a --preserve=all "$f" "$dest" 2>/dev/null || cp -p "$f" "$dest"
        printf 'cp -a --preserve=all "%s" "%s" && echo "restored %s"\n' "$dest" "$f" "$f" >> "$ROLLBACK"
        log INFO "бэкап: $f"
    fi
}
backup_created() { is_apply || return 0; printf 'rm -f "%s" && echo "removed %s"\n' "$1" "$1" >> "$ROLLBACK"; }

# ============================================================================
#  ИДЕМПОТЕНТНЫЕ ПРАВКИ КОНФИГОВ
# ============================================================================
set_kv() { # set_kv FILE KEY VALUE [SEP]
    local file="$1" key="$2" val="$3" sep="${4:- }" want d=$'\x01'
    want="${key}${sep}${val}"
    if [[ -f "$file" ]] && grep -Eq "^[[:space:]]*${key}([[:space:]]|=)" "$file"; then
        local cur; cur="$(grep -E "^[[:space:]]*${key}([[:space:]]|=)" "$file" | tail -1)"
        [[ "$cur" == "$want" ]] && { log OK "$file: ${key} уже=${val}"; return 0; }
        backup "$file"
        if is_apply; then
            sed -ri "s${d}^[[:space:]]*${key}([[:space:]]|=).*${d}${want//&/\\&}${d}" "$file"
            grep -Fxq "$want" "$file" || { log ERR "$file: НЕ УДАЛОСЬ выставить ${key}=${val}"; return 1; }
        fi
        log OK "$file: ${key} -> ${val}"; record "$file: ${key}->${val}"
    else
        backup "$file"
        if is_apply; then
            [[ -f "$file" ]] || { mkdir -p "$(dirname "$file")"; : >"$file"; backup_created "$file"; }
            printf '%s\n' "$want" >>"$file"
            grep -Fxq "$want" "$file" || { log ERR "$file: НЕ УДАЛОСЬ дописать ${key}"; return 1; }
        fi
        log OK "$file: +${key}${sep}${val}"; record "$file: +${key} ${val}"
    fi
}
ensure_line() {
    local file="$1" line="$2"
    if [[ -f "$file" ]] && grep -Fxq "$line" "$file"; then log OK "$file: строка есть"; return 0; fi
    backup "$file"
    if is_apply; then [[ -f "$file" ]] || { : >"$file"; backup_created "$file"; }; printf '%s\n' "$line" >>"$file"; fi
    log OK "$file: + ${line}"; record "$file: +line"
}
write_managed() { # содержимое на stdin
    local file="$1" content; content="$(cat)"
    if [[ -f "$file" ]] && [[ "$(cat "$file")" == "$content" ]]; then log OK "$file: актуален"; return 0; fi
    if [[ -e "$file" ]]; then backup "$file"; else backup_created "$file"; fi
    if is_apply; then mkdir -p "$(dirname "$file")"; printf '%s\n' "$content" >"$file"; fi
    log OK "$file: записан"; record "$file: managed"
}

SYSCTL_FILE="/etc/sysctl.d/99-zavetsec-harden.conf"
set_sysctl() { set_kv "$SYSCTL_FILE" "$1" "$2" " = "; }

# Никогда не понижаем то, что система уже настроила строже.
# Ubuntu 26.04 сама ставит kptr_restrict/perf_event_paranoid/unprivileged_bpf
# в значения, которые старый скрипт молча ОСЛАБЛЯЛ.
set_sysctl_max() {
    local key="$1" want="$2" cur
    cur="$(sysctl -n "$key" 2>/dev/null)"
    if [[ "${cur:-}" =~ ^[0-9]+$ && "$want" =~ ^[0-9]+$ && "$cur" -gt "$want" ]]; then
        log INFO "$key: система строже (${cur} > ${want}) — фиксирую ${cur}, не понижаю"
        set_sysctl "$key" "$cur"; return 0
    fi
    set_sysctl "$key" "$want"
}
apply_sysctl() { run_q sysctl --system || log WARN "sysctl --system отработал с замечаниями"; }

disable_module() {
    local mod="$1" f="/etc/modprobe.d/zavetsec-harden.conf"
    if [[ -f "$f" ]] && grep -q "install ${mod} /bin/true" "$f"; then log OK "модуль $mod уже отключён"; return 0; fi
    [[ -e "$f" ]] || backup_created "$f"; backup "$f"
    is_apply && { echo "install ${mod} /bin/true"; echo "blacklist ${mod}"; } >>"$f"
    log OK "отключён модуль ядра: $mod"; record "modprobe disable $mod"
}

svc_active()  { systemctl is-active  --quiet "$1" 2>/dev/null; }
svc_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
svc_exists()  { [[ -n "$(systemctl list-unit-files "${1}*" 2>/dev/null | grep -F -- "$1")" ]]; }
mask_service() {
    local svc="$1"; run_q systemctl mask --now "$svc"
    is_apply && log OK "замаскирован: $svc"
    record "svc mask $svc"; add_rollback "systemctl unmask \"$svc\" 2>/dev/null; echo \"unmasked $svc\""
}

APT_UPDATED=0
apt_installed() { dpkg -s "$1" >/dev/null 2>&1; }
apt_install() {
    apt_installed "$1" && { log OK "пакет $1 установлен"; return 0; }
    if ! is_apply; then log DRY "установил бы: $1"; return 0; fi
    if env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" >/dev/null 2>&1; then
        log OK "установлен: $1"; record "apt install $1"; return 0
    fi
    if [[ "$APT_UPDATED" == "0" ]]; then
        log INFO "apt-get update (списки пакетов устарели)"
        apt-get update >/dev/null 2>&1; APT_UPDATED=1
        env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" >/dev/null 2>&1 \
            && { log OK "установлен: $1"; record "apt install $1"; return 0; }
    fi
    log WARN "не удалось установить $1 — пропускаю"
}

enabled() { local v="ZS_ENABLE_${1}"; [[ "${!v:-1}" == "1" ]]; }
tune()    { local v="ZS_TUNE_${1}"; printf '%s' "${!v:-$2}"; }

# ============================================================================
#  ДВИЖОК АУДИТА (read-only)
# ============================================================================
AUDIT_RESULTS=(); A_PASS=0; A_FAIL=0; A_WARN=0; A_SKIP=0; SSHD_EFFECTIVE=""
he() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }
chk() {
    # значения могут прийти многострочными (findmnt, grep -c) — схлопываем,
    # иначе таблица и HTML-отчёт разъезжаются
    local ex ac
    ex="$(printf '%s' "$5" | tr '\n|' '  ' | tr -s ' ')"
    ac="$(printf '%s' "$6" | tr '\n|' '  ' | tr -s ' ')"
    set -- "$1" "$2" "$3" "$4" "$ex" "$ac" "${7:-}"
    AUDIT_RESULTS+=("$1|$2|$3|$4|$5|$6|${7:-}")
    case "$1" in PASS) A_PASS=$((A_PASS+1));; FAIL) A_FAIL=$((A_FAIL+1));;
        WARN) A_WARN=$((A_WARN+1));; SKIP) A_SKIP=$((A_SKIP+1));; esac
    if [[ "${MODE:-}" == "audit" ]]; then
        local col; case "$1" in PASS) col="$C_GRN";; FAIL) col="$C_RED";; WARN) col="$C_YEL";; *) col="$C_DIM";; esac
        printf '  %s%-4s%s ' "$col" "$1" "$C_RST"
        _pad 11 "[$3]"; printf ' '; _pad 42 "$4"
        printf ' %s\n' "${C_DIM}ожид=${5} факт=${6}${C_RST}"
    fi
}
_cmp() { if [[ "$4" == "$5" ]]; then chk PASS "$1" "$2" "$3" "$4" "$5" "${6:-}"; else chk FAIL "$1" "$2" "$3" "$4" "$5" "${6:-}"; fi; }
# точное сравнение — для ключей, где строже = МЕНЬШЕ (redirects, source_route...)
a_sysctl() {
    local v; v="$(sysctl -n "$2" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/ *$//')"
    [[ -z "$v" ]] && { chk SKIP "$1" sysctl "$2" "$3" "n/a" "ключа нет"; return; }
    _cmp "$1" sysctl "$2" "$3" "$v"
}
# «не ниже чем» — только для ключей, где строже = БОЛЬШЕ (kptr_restrict,
# ptrace_scope, unprivileged_bpf_disabled и т.п.). Совпадает с set_sysctl_max.
a_sysctl_min() {
    local v; v="$(sysctl -n "$2" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/ *$//')"
    [[ -z "$v" ]] && { chk SKIP "$1" sysctl "$2" ">=$3" "n/a" "ключа нет"; return; }
    if [[ "$v" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$v" -ge "$3" ]]; then
        chk PASS "$1" sysctl "$2" ">=$3" "$v"
    else
        chk FAIL "$1" sysctl "$2" ">=$3" "$v"
    fi
}
a_file_mode()  { [[ -e "$2" ]] || { chk SKIP "$1" perms "$2 режим" "$3" нет; return; }
    _cmp "$1" perms "$2 режим" "$3" "$(stat -c '%a' "$2" 2>/dev/null)"; }
a_file_owner() { [[ -e "$2" ]] || { chk SKIP "$1" perms "$2 владелец" "$3" нет; return; }
    _cmp "$1" perms "$2 владелец" "$3" "$(stat -c '%U:%G' "$2" 2>/dev/null)"; }
a_svc_on()  {
    if ! svc_exists "$2"; then chk WARN "$1" services "$2 активен" on отсутствует; return; fi
    svc_active "$2" && chk PASS "$1" services "$2 активен" on active || chk FAIL "$1" services "$2 активен" on inactive
}
a_pkg_present() { apt_installed "$2" && chk PASS "$1" packages "$2" есть есть || chk FAIL "$1" packages "$2" есть нет; }
a_kv() {
    [[ -f "$2" ]] || { chk SKIP "$1" config "$3" "$4" "файла нет"; return; }
    local line val
    line="$(grep -E "^[[:space:]]*${3}[[:space:]=]" "$2" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1)"
    [[ -z "$line" ]] && { chk FAIL "$1" config "$3" "$4" "не задан" "${2##*/}"; return; }
    val="$(echo "$line" | sed -E "s/^[[:space:]]*${3}[[:space:]]*=?[[:space:]]*//" | sed 's/#.*//; s/[[:space:]]*$//')"
    _cmp "$1" config "$3" "$4" "$val" "${2##*/}"
}
a_sshd_init() { [[ "$(id -u)" -eq 0 ]] && command -v sshd >/dev/null 2>&1 && SSHD_EFFECTIVE="$(sshd -T 2>/dev/null)"; }
a_sshd() {
    command -v sshd >/dev/null 2>&1 || { chk SKIP "$1" ssh "$2" "$3" "sshd нет"; return; }
    [[ -z "$SSHD_EFFECTIVE" ]] && { chk SKIP "$1" ssh "$2" "$3" "нужен root"; return; }
    local v got want
    v="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk -v k="$2" '$1==k{$1="";sub(/^ /,"");print;exit}')"
    [[ -z "$v" ]] && { chk SKIP "$1" ssh "$2" "$3" "нет в sshd -T"; return; }
    got="$v"; want="$3"
    [[ "$want" == "prohibit-password" ]] && want="without-password"
    [[ "$got"  == "prohibit-password" ]] && got="without-password"
    if [[ "$got" == "$want" ]]; then chk PASS "$1" ssh "$2" "$3" "$v"; else chk FAIL "$1" ssh "$2" "$3" "$v"; fi
}

# ============================================================================
#  ДЕТЕКТ
# ============================================================================
detect() {
    UB_ID="unknown"; UB_VER=""; UB_PRETTY=""; UB_CODENAME=""; UB_LIKE=""
    if [[ -r /etc/os-release ]]; then . /etc/os-release
        UB_ID="${ID:-unknown}"; UB_VER="${VERSION_ID:-}"; UB_PRETTY="${PRETTY_NAME:-}"
        UB_CODENAME="${VERSION_CODENAME:-}"; UB_LIKE="${ID_LIKE:-}"
    fi
    IS_UBUNTU="no"
    [[ "$UB_ID" == "ubuntu" ]] && IS_UBUNTU="yes"
    [[ " ${UB_LIKE:-} " == *" ubuntu "* ]] && IS_UBUNTU="derivative"
    UB_MAJOR="${UB_VER%%.*}"; [[ "$UB_MAJOR" =~ ^[0-9]+$ ]] || UB_MAJOR=0

    IS_CONTAINER="no"
    { [[ -f /.dockerenv || -f /run/.containerenv ]] || \
      { command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container >/dev/null 2>&1; }; } \
      && IS_CONTAINER="yes"

    # реализация sudo: 26.04 по умолчанию — sudo-rs
    SUDO_IMPL="none"
    if command -v sudo >/dev/null 2>&1; then
        if sudo -V 2>/dev/null | grep -qi 'sudo-rs'; then SUDO_IMPL="sudo-rs"; else SUDO_IMPL="sudo.ws"; fi
    fi

    # coreutils: 26.04 по умолчанию uutils (кроме cp/mv/rm)
    COREUTILS="gnu"
    ls --version 2>/dev/null | grep -qi 'uutils' && COREUTILS="uutils"

    FW="none"
    if command -v ufw >/dev/null 2>&1; then
        if [[ -n "$(ufw status 2>/dev/null | grep -i 'Status: active')" ]]; then FW="ufw-active"; else FW="ufw"; fi
    elif command -v nft >/dev/null 2>&1; then FW="nftables"; fi

    AA="none"
    { command -v aa-status >/dev/null 2>&1 || [[ -d /sys/kernel/security/apparmor ]]; } && AA="apparmor"

    HAS_GUI="no"
    { systemctl get-default 2>/dev/null | grep -q graphical; } && HAS_GUI="yes"
    { apt_installed ubuntu-desktop || apt_installed ubuntu-desktop-minimal; } && HAS_GUI="yes"
    [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && HAS_GUI="yes"

    # виртуализация/контейнеры на хосте — важно для ip_forward
    HAS_VIRT="no"
    { command -v dockerd >/dev/null 2>&1 || command -v libvirtd >/dev/null 2>&1 || \
      command -v podman  >/dev/null 2>&1 || command -v lxc     >/dev/null 2>&1 || \
      [[ -d /sys/class/net/docker0 || -d /sys/class/net/virbr0 ]]; } && HAS_VIRT="yes"

    RSYSLOG="no"; apt_installed rsyslog && RSYSLOG="yes"

    # --- SSH: юнит и порты -------------------------------------------------
    HAS_SSHD="no"; command -v sshd >/dev/null 2>&1 && HAS_SSHD="yes"
    SSH_SOCKET="no"
    svc_exists ssh.socket && svc_enabled ssh.socket && SSH_SOCKET="yes"

    # ИСПРАВЛЕНО: при socket-activation слушателем владеет systemd (pid 1),
    # старый фильтр /sshd/ в ss не находил ничего и порт молча падал в 22.
    local ports=""
    if [[ "$SSH_SOCKET" == "yes" ]]; then
        # единственный достоверный источник при сокет-активации
        ports="$(systemctl show ssh.socket -p Listen --value 2>/dev/null \
                 | grep -oE '[0-9]+ \(Stream\)' | awk '{print $1}')"
    fi
    if [[ -r /etc/ssh/sshd_config ]]; then
        ports="$ports $(grep -hiE '^[[:space:]]*Port[[:space:]]+[0-9]+' \
                        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}')"
    fi
    command -v ss >/dev/null 2>&1 && \
        ports="$ports $(ss -tlnp 2>/dev/null | awk '/"sshd"/{n=split($4,a,":"); if(a[n] ~ /^[0-9]+$/) print a[n]}')"
    SSH_PORTS="$(echo "$ports" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u | tr '\n' ' ' | xargs)"
    [[ -z "$SSH_PORTS" && "$HAS_SSHD" == "yes" ]] && SSH_PORTS="22"
}

_drow() { printf '  '; _pad 18 "$1"; printf ' %s\n' "$2"; }
print_detect() {
    printf '%s\n' "${C_BLD}${C_GRN}  ДЕТЕКТ${C_RST}"
    _drow "Дистрибутив:"    "${UB_PRETTY:-?} (${UB_ID} ${UB_VER} ${UB_CODENAME})"
    _drow "sudo:"           "${SUDO_IMPL}"
    _drow "coreutils:"      "${COREUTILS}"
    _drow "Firewall:"       "${FW}"
    _drow "MAC:"            "${AA}"
    _drow "rsyslog:"        "${RSYSLOG}"
    _drow "GUI:"            "${HAS_GUI}"
    _drow "Контейнер:"      "${IS_CONTAINER}"
    _drow "Docker/libvirt:" "${HAS_VIRT}"
    _drow "sshd:"           "${HAS_SSHD} (socket-activation: ${SSH_SOCKET})"
    _drow "SSH порт(ы):"    "${SSH_PORTS:-—}"
    _drow "Режим:"          "${C_CYN}${MODE}${C_RST}"
    echo
}

# ============================================================================
#  ПРОФИЛЬ (один: desktop-2604)
# ============================================================================
# shellcheck disable=SC2034
load_profile() {
    ZS_ENABLE_SYSCTL_KERNEL=1; ZS_ENABLE_SYSCTL_NETWORK=1; ZS_ENABLE_JOURNALD=1
    ZS_ENABLE_AUDITD=1; ZS_ENABLE_SSH=1; ZS_ENABLE_AUTH=1
    ZS_ENABLE_FILESYSTEM=1; ZS_ENABLE_SERVICES=1; ZS_ENABLE_EXTRAS=1
    ZS_ENABLE_APPARMOR=1; ZS_ENABLE_MISC=1
    ZS_ENABLE_FIREWALL="$WANT_FW"        # ВЫКЛЮЧЕН, пока не передан --enable-firewall

    # --- ядро: мягкие десктопные значения ---
    ZS_TUNE_PTRACE_SCOPE=1               # 2 ломает gdb/strace/отладку
    ZS_TUNE_SYSRQ=176                    # дефолт Ubuntu; 0 убивает аварийный REISUB
    ZS_TUNE_DISABLE_BPF_UNPRIV=1         # но только через set_sysctl_max
    ZS_TUNE_DISABLE_IPV6=0               # никогда не выключаем IPv6 на десктопе
    ZS_TUNE_RP_FILTER=2                  # loose: не ломает split-tunnel VPN
    ZS_TUNE_IP_FORWARD=""                # "" = не трогать (автодетект Docker/libvirt)

    # --- ФС: без noexec, без udf/hfs, без блокировки флешек ---
    ZS_TUNE_FS_BLACKLIST="cramfs freevxfs jffs2"   # udf/hfs/hfsplus НЕ трогаем: DVD и диски Mac
    ZS_TUNE_NET_PROTO_BLACKLIST="dccp rds tipc"    # sctp оставлен: WebRTC/телеком-софт
    ZS_TUNE_SHM_NOEXEC=0
    ZS_TUNE_DISABLE_USB_STORAGE=0

    # --- пароли ---
    ZS_TUNE_PASS_MAX_DAYS=365; ZS_TUNE_PASS_MIN_DAYS=0; ZS_TUNE_PASS_WARN_AGE=14
    ZS_TUNE_UMASK=022                    # 027 ломает привычные права в ~ на десктопе
    ZS_TUNE_PWQ_MINLEN=12; ZS_TUNE_PWQ_MINCLASS=3
    ZS_TUNE_FAILLOCK_DENY=10; ZS_TUNE_FAILLOCK_UNLOCK=600

    # --- SSH (применяется только если sshd установлен) ---
    ZS_TUNE_SSH_PERMIT_ROOT="prohibit-password"
    ZS_TUNE_SSH_MAXAUTH=4; ZS_TUNE_SSH_GRACE=60
    ZS_TUNE_SSH_ALIVE_INTERVAL=300; ZS_TUNE_SSH_ALIVE_COUNT=3
    ZS_TUNE_SSH_ALLOW_TCP_FWD="yes"      # десктоп: ssh -L/-D нужны

    # --- логирование ---
    ZS_TUNE_JOURNAL_MAXUSE="2G"; ZS_TUNE_JOURNAL_RETENTION="90day"
    ZS_TUNE_JOURNAL_MAXFILE="128M"
    ZS_TUNE_AUDIT_MAXFILE=64; ZS_TUNE_AUDIT_NUMLOGS=10
    ZS_TUNE_AUDIT_VERBOSE=0              # 1 = + perm_mod/access/delete/execve (много шума)
    ZS_TUNE_AUDIT_IMMUTABLE=0            # -e 2 только осознанно
    ZS_TUNE_UFW_LOGLEVEL="medium"

    # --- прочее ---
    ZS_TUNE_DISABLE_APPORT=0             # на десктопе apport оставляем
    ZS_TUNE_EXTRA_PKGS="debsums needrestart acct sysstat"
    ZS_TUNE_AUTO_UPGRADES=1
    ZS_TUNE_COREDUMP_OFF=1
    ZS_TUNE_MASK_CAD=1
}

# ============================================================================
#  МОДУЛИ
# ============================================================================
mod_sysctl-kernel() {
    enabled SYSCTL_KERNEL || { log INFO "отключён профилем"; return 0; }
    set_sysctl_max kernel.kptr_restrict 2
    set_sysctl_max kernel.dmesg_restrict 1
    set_sysctl_max kernel.perf_event_paranoid 3
    set_sysctl_max kernel.randomize_va_space 2
    set_sysctl kernel.kexec_load_disabled 1
    set_sysctl kernel.core_uses_pid 1
    set_sysctl dev.tty.ldisc_autoload 0
    set_sysctl_max fs.protected_hardlinks 1
    set_sysctl_max fs.protected_symlinks 1
    set_sysctl_max fs.protected_fifos 2
    set_sysctl_max fs.protected_regular 2

    # sysrq: 0 отбирает аварийное разблокирование/размонтирование с клавиатуры
    local sq; sq="$(tune SYSRQ 176)"
    [[ "$sq" == "0" ]] && risk MED "kernel.sysrq=0 — аварийный REISUB перестанет работать"
    set_sysctl kernel.sysrq "$sq"

    set_sysctl_max kernel.yama.ptrace_scope "$(tune PTRACE_SCOPE 1)"

    if [[ "$(tune DISABLE_BPF_UNPRIV 1)" == "1" ]]; then
        set_sysctl_max kernel.unprivileged_bpf_disabled 1
    else log INFO "непривилегированный eBPF оставлен включённым"; fi
    set_sysctl_max net.core.bpf_jit_harden 2

    # apport на десктопе включён и на каждой загрузке ставит fs.suid_dumpable=2.
    # Прописывать 0 под живым apport — самообман до первой перезагрузки.
    if [[ "$(tune DISABLE_APPORT 0)" == "1" ]]; then
        set_sysctl fs.suid_dumpable 0
    else
        log INFO "fs.suid_dumpable оставлен apport'у (он выставит 2 при загрузке)"
    fi
    apply_sysctl
}

mod_sysctl-network() {
    enabled SYSCTL_NETWORK || { log INFO "отключён профилем"; return 0; }
    # rp_filter=2 (loose), а не 1 (strict): strict рвёт split-tunnel VPN,
    # WireGuard/Tailscale и мультихоминг на десктопе.
    local rpf; rpf="$(tune RP_FILTER 2)"
    set_sysctl net.ipv4.conf.all.rp_filter "$rpf"
    set_sysctl net.ipv4.conf.default.rp_filter "$rpf"

    set_sysctl net.ipv4.conf.all.accept_redirects 0
    set_sysctl net.ipv4.conf.default.accept_redirects 0
    set_sysctl net.ipv4.conf.all.secure_redirects 0
    set_sysctl net.ipv4.conf.default.secure_redirects 0
    set_sysctl net.ipv4.conf.all.send_redirects 0
    set_sysctl net.ipv4.conf.default.send_redirects 0
    set_sysctl net.ipv4.conf.all.accept_source_route 0
    set_sysctl net.ipv4.conf.default.accept_source_route 0
    set_sysctl net.ipv4.conf.all.log_martians 1
    set_sysctl net.ipv4.conf.default.log_martians 1
    set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    set_sysctl net.ipv4.tcp_syncookies 1
    set_sysctl net.ipv4.tcp_rfc1337 1
    set_sysctl net.ipv6.conf.all.accept_redirects 0
    set_sysctl net.ipv6.conf.default.accept_redirects 0
    set_sysctl net.ipv6.conf.all.accept_source_route 0
    set_sysctl net.ipv6.conf.default.accept_source_route 0

    # IPv6 RA не трогаем — на десктопе это SLAAC и единственный способ
    # получить адрес в большинстве домашних/офисных сетей.
    log INFO "IPv6 RA оставлен по умолчанию (SLAAC), IPv6 не отключается"

    # ip_forward: по умолчанию НЕ трогаем. forwarding=0 обрывает сети
    # docker0/virbr0 и ломает контейнеры и VM.
    local ipf; ipf="$(tune IP_FORWARD "")"
    if [[ -z "$ipf" ]]; then
        if [[ "$HAS_VIRT" == "yes" ]]; then
            log INFO "обнаружены Docker/libvirt — ip_forward не трогаю (иначе сети VM/контейнеров лягут)"
        else
            log INFO "ip_forward не трогаю (десктопный дефолт; задайте ZS_TUNE_IP_FORWARD=0 осознанно)"
        fi
    else
        set_sysctl net.ipv4.ip_forward "$ipf"
    fi

    local pr; for pr in $(tune NET_PROTO_BLACKLIST "dccp rds tipc"); do disable_module "$pr"; done
    log INFO "sctp НЕ блокируется (используется WebRTC и телеком-софтом)"
    apply_sysctl
}

mod_journald() {
    enabled JOURNALD || { log INFO "отключён профилем"; return 0; }
    # Главный пробел исходного скрипта: journald по умолчанию volatile
    # (/run/log/journal) — вся история логов терялась при перезагрузке.
    if [[ ! -d /var/log/journal ]]; then
        run mkdir -p /var/log/journal
        run_q systemd-tmpfiles --create --prefix /var/log/journal
        backup_created /var/log/journal
        log OK "создан /var/log/journal (журнал станет persistent)"
        record "mkdir /var/log/journal"
    else log OK "/var/log/journal уже есть"; fi

    local FWD="no"; [[ "$RSYSLOG" == "yes" ]] && FWD="yes"
    write_managed /etc/systemd/journald.conf.d/99-zavetsec.conf <<EOF
# Managed by ZavetSec-Harden (26.04 desktop). Do not edit by hand.
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=$(tune JOURNAL_MAXUSE 2G)
SystemMaxFileSize=$(tune JOURNAL_MAXFILE 128M)
SystemKeepFree=1G
MaxRetentionSec=$(tune JOURNAL_RETENTION 90day)
MaxLevelStore=info
ForwardToSyslog=${FWD}
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF
    if is_apply; then
        systemctl restart systemd-journald 2>/dev/null \
            && log OK "systemd-journald перезапущен (persistent)" \
            || log WARN "перезапустите systemd-journald вручную"
    else log DRY "перезапустил бы systemd-journald"; fi

    if [[ "$RSYSLOG" == "yes" ]]; then
        log OK "rsyslog установлен — текстовые логи в /var/log сохраняются"
    else
        log INFO "rsyslog не установлен — вся история только в journal (это нормально для 26.04)"
    fi
}

mod_auditd() {
    enabled AUDITD || { log INFO "отключён профилем"; return 0; }
    [[ "$IS_CONTAINER" == "yes" ]] && { log WARN "контейнер — подсистема аудита принадлежит хосту, пропуск"; return 0; }
    apt_install auditd; apt_install audispd-plugins
    local RD=/etc/audit/rules.d
    [[ -d "$RD" ]] || { log WARN "$RD отсутствует — auditd не установлен, пропуск"; return 0; }

    # ---- ротация и поведение при нехватке места (исходник это не трогал:
    # дефолт 8 МБ x 5 = 40 МБ, улики стирались за часы) ----
    local AC=/etc/audit/auditd.conf
    if [[ -f "$AC" ]]; then
        set_kv "$AC" max_log_file "$(tune AUDIT_MAXFILE 64)" " = "
        set_kv "$AC" num_logs     "$(tune AUDIT_NUMLOGS 10)" " = "
        set_kv "$AC" max_log_file_action KEEP_LOGS " = "
        set_kv "$AC" space_left 512 " = "
        set_kv "$AC" space_left_action SYSLOG " = "
        set_kv "$AC" admin_space_left 256 " = "
        set_kv "$AC" admin_space_left_action SYSLOG " = "   # НЕ single: не роняем десктоп в single-user
        set_kv "$AC" disk_full_action SYSLOG " = "
        set_kv "$AC" disk_error_action SYSLOG " = "
        set_kv "$AC" flush INCREMENTAL_ASYNC " = "
        set_kv "$AC" local_events yes " = "
        log OK "auditd.conf: ретенция $(tune AUDIT_MAXFILE 64)МБ x $(tune AUDIT_NUMLOGS 10)"
    fi

    # sudo на 26.04 — это симлинк на бинарь sudo-rs; audit не ходит по симлинкам,
    # поэтому путь резолвим.
    local SUDO_PATH SU_PATH PASSWD_PATH PKEXEC_PATH
    SUDO_PATH="$(readlink -f "$(command -v sudo 2>/dev/null)" 2>/dev/null || echo /usr/bin/sudo)"
    SU_PATH="$(readlink -f "$(command -v su 2>/dev/null)" 2>/dev/null || echo /usr/bin/su)"
    PASSWD_PATH="$(readlink -f "$(command -v passwd 2>/dev/null)" 2>/dev/null || echo /usr/bin/passwd)"
    PKEXEC_PATH="$(readlink -f "$(command -v pkexec 2>/dev/null)" 2>/dev/null || echo /usr/bin/pkexec)"

    local ARCH32=""; [[ "$(uname -m)" == "x86_64" ]] && ARCH32="yes"   # на arm64 b32-правил нет
    local E=1; [[ "$(tune AUDIT_IMMUTABLE 0)" == "1" ]] && E=2
    local RF="${RD}/99-zavetsec.rules"

    {
    cat <<EOF
## ZavetSec-Harden :: Ubuntu 26.04 desktop :: базовые правила аудита
-D
-b 8192
-f 1
--backlog_wait_time 60000

## конфигурация самого аудита
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig

## учётные записи и привилегии
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam
-w /etc/nsswitch.conf -p wa -k nss
-w /etc/polkit-1/ -p wa -k polkit

## удалённый доступ и служебная конфигурация
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/systemd/ -p wa -k systemd-config
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## сеть и время
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale

## сессии и входы
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

## модули ядра
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /usr/bin/kmod -p x -k modules

## повышение привилегий
-a always,exit -F path=${SUDO_PATH} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=${SU_PATH} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=${PASSWD_PATH} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
EOF
    [[ -x "$PKEXEC_PATH" ]] && \
      echo "-a always,exit -F path=${PKEXEC_PATH} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"

    if [[ -n "$ARCH32" ]]; then
        cat <<'EOF'

## 32-битные варианты (только x86_64)
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules
EOF
    fi

    if [[ "$(tune AUDIT_VERBOSE 0)" == "1" ]]; then
        cat <<'EOF'

## подробный режим (ZS_TUNE_AUDIT_VERBOSE=1) — заметный объём логов
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root-cmd
EOF
    fi

    printf '\n-e %s\n' "$E"
    } | write_managed "$RF"

    if is_apply; then
        run_q systemctl enable auditd
        if command -v augenrules >/dev/null 2>&1; then
            if augenrules --load 2>"${STATE_DIR}/augenrules.err"; then log OK "правила аудита загружены"
            else log WARN "augenrules отработал с ошибками — см. ${STATE_DIR}/augenrules.err"; fi
        fi
        systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || log WARN "перезапустите auditd вручную"
        local n; n="$(auditctl -l 2>/dev/null | grep -c . )"; n="${n:-0}"
        log OK "активных правил аудита: ${n}"
        [[ "$E" == "2" ]] && risk MED "аудит immutable (-e 2): изменить правила можно будет только после перезагрузки"
    else
        log DRY "установил бы auditd, записал ${RF}, augenrules --load, перезапустил auditd (-e ${E})"
    fi
}

mod_ssh() {
    enabled SSH || { log INFO "отключён профилем"; return 0; }
    [[ "$HAS_SSHD" == "yes" ]] || { log INFO "sshd не установлен (обычно для десктопа) — пропуск"; return 0; }

    local MAIN="/etc/ssh/sshd_config" DIR="/etc/ssh/sshd_config.d"
    local DROPIN="${DIR}/00-zavetsec-harden.conf" LEGACY="${DIR}/99-zavetsec-harden.conf"
    if [[ -e "$LEGACY" ]]; then backup "$LEGACY"; run rm -f "$LEGACY"; log INFO "убран старый 99- drop-in"; fi

    _filter() { local q="$1"; shift; local sup out=""; sup="$(ssh -Q "$q" 2>/dev/null)" || { echo "$*"; return; }
        local a; for a in "$@"; do grep -qx "$a" <<<"$sup" && out+="${out:+,}$a"; done; echo "$out"; }

    # ИСПРАВЛЕНО: mlkem768x25519-sha256 идёт ПЕРВЫМ. В OpenSSH 10.x это
    # постквантовый дефолт; старый список его вычёркивал и понижал защиту.
    local KEX CIPH MACS
    KEX="$(_filter kex mlkem768x25519-sha256 sntrup761x25519-sha512@openssh.com \
           curve25519-sha256 curve25519-sha256@libssh.org \
           diffie-hellman-group16-sha512 diffie-hellman-group18-sha512)"
    CIPH="$(_filter cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com \
            aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)"
    MACS="$(_filter mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com \
            umac-128-etm@openssh.com)"

    local PR MA GR AI AC TF
    PR="$(tune SSH_PERMIT_ROOT prohibit-password)"; MA="$(tune SSH_MAXAUTH 4)"
    GR="$(tune SSH_GRACE 60)"; AI="$(tune SSH_ALIVE_INTERVAL 300)"; AC="$(tune SSH_ALIVE_COUNT 3)"
    TF="$(tune SSH_ALLOW_TCP_FWD yes)"

    run mkdir -p "$DIR"
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$MAIN" 2>/dev/null; then
        risk MED "в sshd_config нет Include для sshd_config.d — добавляю в начало"
        if is_apply; then backup "$MAIN"
            printf 'Include /etc/ssh/sshd_config.d/*.conf\n%s\n' "$(cat "$MAIN")" >"${MAIN}.zsnew" && mv "${MAIN}.zsnew" "$MAIN"
        fi
        record "sshd_config +Include"
    fi

    # ВАЖНО: PasswordAuthentication НЕ трогаем. Отключение паролей без
    # проверенного ключа — самый частый способ отрезать себе доступ.
    { cat <<EOF
# Managed by ZavetSec-Harden (26.04 desktop). Do not edit by hand.
# Generated: $(_ts)
PermitRootLogin ${PR}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
MaxAuthTries ${MA}
LoginGraceTime ${GR}
ClientAliveInterval ${AI}
ClientAliveCountMax ${AC}
X11Forwarding no
AllowTcpForwarding ${TF}
AllowAgentForwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
PermitTunnel no
LogLevel VERBOSE
Banner /etc/issue.net
EOF
    [[ -n "$KEX"  ]] && echo "KexAlgorithms ${KEX}"
    [[ -n "$CIPH" ]] && echo "Ciphers ${CIPH}"
    [[ -n "$MACS" ]] && echo "MACs ${MACS}"; } | write_managed "$DROPIN"

    # баннер для сети — /etc/issue (консольный) НЕ трогаем, там escape-коды getty
    write_managed /etc/issue.net <<'EOF'
Authorized access only. All activity is monitored and logged.
EOF

    if is_apply; then
        local SSHD_ERR="${STATE_DIR}/sshd_t.err"
        if sshd -t 2>"$SSHD_ERR"; then
            log OK "sshd -t прошёл"
            if [[ "$SSH_SOCKET" == "yes" ]]; then
                systemctl daemon-reload 2>/dev/null
                systemctl restart ssh.socket 2>/dev/null \
                    && log OK "ssh.socket перезапущен (активные сессии не тронуты)" \
                    || log WARN "перезапустите ssh.socket вручную"
            else
                systemctl reload ssh 2>/dev/null && log OK "ssh перезагружен" || log WARN "перезагрузите ssh вручную"
            fi
        else
            log ERR "sshd -t НЕ ПРОШЁЛ — откатываю drop-in:"
            while read -r l; do log ERR "  $l"; done <"$SSHD_ERR"
            local bkp="${BACKUP_DIR}${DROPIN}"
            if [[ -f "$bkp" ]]; then cp -a "$bkp" "$DROPIN"; log WARN "восстановлен прежний drop-in"
            else rm -f "$DROPIN"; log WARN "drop-in удалён, sshd остался рабочим"; fi
        fi
    else log DRY "проверил бы sshd -t и перезапустил ssh.socket"; fi
}

mod_auth() {
    enabled AUTH || { log INFO "отключён профилем"; return 0; }
    local LD=/etc/login.defs
    if [[ -f "$LD" ]]; then
        set_kv "$LD" PASS_MAX_DAYS "$(tune PASS_MAX_DAYS 365)" $'\t'
        set_kv "$LD" PASS_MIN_DAYS "$(tune PASS_MIN_DAYS 0)"   $'\t'
        set_kv "$LD" PASS_WARN_AGE "$(tune PASS_WARN_AGE 14)"  $'\t'
        set_kv "$LD" UMASK         "$(tune UMASK 022)"         $'\t'
        set_kv "$LD" ENCRYPT_METHOD YESCRYPT                   $'\t'
        set_kv "$LD" YESCRYPT_COST_FACTOR "$(tune YESCRYPT_COST 8)" $'\t'
        set_kv "$LD" FAILLOG_ENAB  yes                         $'\t'
    fi

    apt_install libpam-pwquality
    local PWQ=/etc/security/pwquality.conf
    set_kv "$PWQ" minlen    "$(tune PWQ_MINLEN 12)"  " = "
    set_kv "$PWQ" minclass  "$(tune PWQ_MINCLASS 3)" " = "
    set_kv "$PWQ" maxrepeat 3 " = "
    set_kv "$PWQ" enforcing 1 " = "
    log INFO "dcredit/ucredit/ocredit не задаются: minclass делает то же самое без конфликтов"

    # faillock: пишем ТОЛЬКО конфиг. Вплетение pam_faillock в common-auth
    # через pam-auth-update удалено полностью — это был главный источник
    # риска полного локаута, а на десктопе ценность околонулевая.
    local FL=/etc/security/faillock.conf
    if compgen -G "/usr/lib/*/security/pam_faillock.so" >/dev/null 2>&1; then
        set_kv "$FL" deny          "$(tune FAILLOCK_DENY 10)"    " = "
        set_kv "$FL" unlock_time   "$(tune FAILLOCK_UNLOCK 600)" " = "
        set_kv "$FL" fail_interval 900 " = "
        ensure_line "$FL" "audit"
        log OK "faillock.conf записан (в PAM-стек НЕ вплетается — так безопаснее)"
    else
        log INFO "pam_faillock.so не найден — пропуск"
    fi
}

mod_filesystem() {
    enabled FILESYSTEM || { log INFO "отключён профилем"; return 0; }
    # /dev/shm: nodev,nosuid — да. noexec — НЕТ по умолчанию: он ломает
    # Chrome/Electron, часть JVM и некоторые инсталляторы.
    local OPTS="defaults,nodev,nosuid"
    if [[ "$(tune SHM_NOEXEC 0)" == "1" ]]; then
        OPTS="${OPTS},noexec"; risk MED "noexec на /dev/shm может сломать Chrome/Electron/JVM"
    fi
    if findmnt -rn /dev/shm >/dev/null 2>&1; then
        if grep -qE '[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
            log WARN "/dev/shm уже описан в fstab — не трогаю, проверьте опции вручную"
        else
            backup /etc/fstab
            ensure_line /etc/fstab "tmpfs   /dev/shm   tmpfs   ${OPTS}   0 0"
            if is_apply; then
                if mount -o "remount,${OPTS#defaults,}" /dev/shm >/dev/null 2>&1; then
                    log OK "/dev/shm перемонтирован (${OPTS})"
                else
                    log WARN "перемонтировать /dev/shm сейчас не вышло — опции применятся при загрузке"
                fi
            else
                log DRY "выполнил бы: mount -o remount,${OPTS#defaults,} /dev/shm"
            fi
        fi
    fi

    log INFO "/tmp не трогаю: noexec на /tmp ломает установщики apt/snap и сборку"

    # udf/hfs/hfsplus СОЗНАТЕЛЬНО не блокируются: udf = DVD и ISO-образы,
    # hfs/hfsplus = диски и флешки, отформатированные на macOS.
    local fs; for fs in $(tune FS_BLACKLIST "cramfs freevxfs jffs2"); do disable_module "$fs"; done
    log INFO "udf/hfs/hfsplus оставлены (DVD, ISO, диски macOS)"

    if [[ "$(tune DISABLE_USB_STORAGE 0)" == "1" ]]; then
        risk HIGH "отключаю usb-storage — флешки и внешние диски перестанут монтироваться"
        disable_module usb-storage
    else log INFO "usb-storage оставлен включённым"; fi
}

mod_services() {
    enabled SERVICES || { log INFO "отключён профилем"; return 0; }
    # На десктопе НИЧЕГО не отключаем автоматически: avahi = сетевые принтеры
    # и .local, cups = печать, bluetooth = мышь/наушники, ModemManager = LTE.
    log INFO "avahi/cups/bluetooth/ModemManager намеренно не трогаются на десктопе"

    # Легаси-пакеты: только предупреждаем. apt purge на живой системе —
    # операция с непредсказуемыми зависимостями, автоматом её не делаем.
    local LEG="telnetd telnet-server rsh-server rsh-redone-server talk talkd tftpd-hpa xinetd nis"
    local p found=0
    for p in $LEG; do
        if apt_installed "$p"; then
            found=1; risk MED "установлен устаревший небезопасный пакет: ${p} — удалите вручную: sudo apt purge ${p}"
        fi
    done
    [[ "$found" == "0" ]] && log OK "устаревших сетевых пакетов не найдено"

    local u; for u in telnet.socket rsh.socket rlogin.socket rexec.socket; do
        svc_exists "$u" && mask_service "$u"; done

    # Информативно: что слушает наружу
    if command -v ss >/dev/null 2>&1; then
        local listen; listen="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sort -u | tr '\n' ' ')"
        [[ -n "$listen" ]] && log INFO "слушают не только localhost: ${listen}"
    fi
    return 0
}

mod_extras() {
    enabled EXTRAS || { log INFO "отключён профилем"; return 0; }
    # apt-listchanges убран: умеет становиться интерактивным и подвешивать apt.
    # libpam-tmpdir убран: на десктопе даёт неочевидные поломки GUI-сессий.
    local p; for p in $(tune EXTRA_PKGS "debsums needrestart acct sysstat"); do apt_install "$p"; done

    # fail2ban ставим ТОЛЬКО если есть sshd — иначе он бесполезен и шумит
    if [[ "$HAS_SSHD" == "yes" ]]; then
        local had=0; apt_installed fail2ban && had=1
        apt_install fail2ban
        if is_apply && apt_installed fail2ban; then
            svc_active fail2ban || { run_q systemctl enable --now fail2ban; log OK "fail2ban включён"; record "enable fail2ban"; }
            [[ "$had" == "0" ]] && add_rollback "systemctl disable --now fail2ban 2>/dev/null; env DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban >/dev/null 2>&1; echo \"fail2ban удалён\""
        fi
        local JL=/etc/fail2ban/jail.local
        if [[ -f "$JL" ]] && ! grep -q "Managed by ZavetSec" "$JL" 2>/dev/null; then
            log INFO "jail.local существует и управляется вами — не трогаю"
        else
            write_managed "$JL" <<EOF
# Managed by ZavetSec-Harden (26.04 desktop). Do not edit by hand.
[DEFAULT]
bantime  = $(tune F2B_BANTIME 1h)
findtime = $(tune F2B_FINDTIME 10m)
maxretry = $(tune F2B_MAXRETRY 5)

[sshd]
enabled = true
EOF
            is_apply && svc_active fail2ban && run_q systemctl reload fail2ban
        fi
    else
        log INFO "sshd нет — fail2ban не ставлю (нечего защищать)"
    fi

    if apt_installed sysstat; then
        set_kv /etc/default/sysstat ENABLED '"true"' "="
        is_apply && ! svc_enabled sysstat && { run_q systemctl enable --now sysstat; record "enable sysstat"; }
    fi
    apt_installed acct && is_apply && ! svc_enabled acct && run_q systemctl enable --now acct

    if [[ "$(tune AUTO_UPGRADES 1)" == "1" ]]; then
        apt_install unattended-upgrades
        write_managed /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        log OK "автообновления безопасности включены (перезагрузка НЕ автоматическая)"
    else log INFO "автообновления отключены тюном"; fi
    return 0
}

mod_apparmor() {
    enabled APPARMOR || { log INFO "отключён профилем"; return 0; }
    [[ "$IS_CONTAINER" == "yes" ]] && { log INFO "контейнер — AppArmor на стороне хоста, пропуск"; return 0; }
    apt_install apparmor; apt_install apparmor-utils
    if ! svc_enabled apparmor; then
        run_q systemctl enable --now apparmor; is_apply && log OK "AppArmor включён"; record "enable apparmor"
    else log OK "AppArmor уже включён"; fi
    if command -v aa-status >/dev/null 2>&1; then
        local loaded comp
        loaded="$(aa-status --profiled 2>/dev/null || echo '?')"
        comp="$(aa-status --complaining 2>/dev/null || echo '?')"
        log INFO "профилей загружено=${loaded}, в complain-режиме=${comp}"
        # aa-enforce массово НЕ делаем: на десктопе это стабильно ломает snap-приложения
        [[ "$comp" =~ ^[1-9] ]] && log INFO "профили в complain оставлены как есть (массовый aa-enforce ломает snap)"
    fi
}

mod_misc() {
    enabled MISC || { log INFO "отключён профилем"; return 0; }

    if [[ "$(tune COREDUMP_OFF 1)" == "1" ]]; then
        write_managed /etc/security/limits.d/99-zavetsec-coredump.conf <<'EOF'
* hard core 0
root hard core 0
EOF
        write_managed /etc/systemd/coredump.conf.d/99-zavetsec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
        log OK "core dumps отключены"
    fi

    # apport на десктопе оставляем: это штатный сборщик падений Ubuntu
    if [[ "$(tune DISABLE_APPORT 0)" == "1" ]]; then
        svc_exists apport && { run_q systemctl disable --now apport; add_rollback "systemctl enable --now apport 2>/dev/null; echo apport re-enabled"; }
        [[ -f /etc/default/apport ]] && set_kv /etc/default/apport enabled 0 "="
        log OK "apport отключён"
    else log INFO "apport оставлен включённым (десктопный дефолт)"; fi

    # УДАЛЕНО: allow-list cron.allow/at.allow. В исходнике он создавал ПУСТЫЕ
    # файлы, что мгновенно отбирало cron и at у всех непривилегированных
    # пользователей. Ограничиваемся правами на каталоги cron.
    local d
    for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -e "$d" ]] && { backup "$d" 2>/dev/null; run chmod -R go-rwx "$d" 2>/dev/null || true; }
    done
    log OK "права на cron-каталоги ужесточены (allow-list НЕ создаётся)"

    if [[ "$(tune MASK_CAD 1)" == "1" ]]; then
        run_q systemctl mask ctrl-alt-del.target
        add_rollback "systemctl unmask ctrl-alt-del.target 2>/dev/null; echo \"C-A-D unmasked\""
        is_apply && log OK "ctrl-alt-del.target замаскирован"
    fi

    # ---- sudo: 26.04 по умолчанию sudo-rs ----
    # sudo-rs не реализует Defaults logfile (и log_input/log_output) и отвергает
    # такой файл через visudo -c. Старый скрипт из-за этого молча не настраивал
    # НИЧЕГО. use_pty в sudo-rs включён по умолчанию, отдельный drop-in не нужен.
    if [[ "$SUDO_IMPL" == "sudo-rs" ]]; then
        log OK "sudo-rs: use_pty включён по умолчанию, все вызовы логируются в journald"
        log INFO "Defaults logfile не пишу — sudo-rs его не поддерживает и отверг бы файл"
    elif [[ "$SUDO_IMPL" == "sudo.ws" ]]; then
        local SUDOF=/etc/sudoers.d/99-zavetsec-hardening
        write_managed "$SUDOF" <<'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
        if is_apply && [[ -f "$SUDOF" ]]; then
            chmod 440 "$SUDOF"
            if visudo -cqf "$SUDOF" 2>/dev/null && visudo -cq 2>/dev/null; then
                log OK "sudoers-хардненинг применён (use_pty, logfile)"
            else
                rm -f "$SUDOF"; log ERR "visudo отверг ${SUDOF} — файл удалён, sudo не тронут"
            fi
        fi
    else log INFO "sudo не установлен — пропуск"; fi

    if [[ -d /etc/sudoers.d ]]; then
        local sm; sm="$(stat -c '%a' /etc/sudoers.d 2>/dev/null)"
        if [[ "$sm" != "750" ]]; then
            run chmod 750 /etc/sudoers.d
            add_rollback "chmod ${sm:-755} /etc/sudoers.d; echo \"/etc/sudoers.d -> ${sm:-755}\""
            is_apply && log OK "/etc/sudoers.d -> 750 (было ${sm:-?})"
            record "chmod 750 /etc/sudoers.d"
        else log OK "/etc/sudoers.d уже 750"; fi
    fi

    run chmod 644 /etc/passwd 2>/dev/null; run chmod 644 /etc/group 2>/dev/null
    [[ -f /etc/ssh/sshd_config ]] && run chmod 600 /etc/ssh/sshd_config 2>/dev/null
    local f
    for f in /etc/shadow /etc/gshadow; do
        [[ -e "$f" ]] || continue
        run chown root:shadow "$f" 2>/dev/null; run chmod 640 "$f" 2>/dev/null
        log OK "права 640 root:shadow на $f"
    done
}

mod_firewall() {
    if ! enabled FIREWALL; then
        log INFO "ufw НЕ трогается (по умолчанию выключен в этой версии)"
        log INFO "включить осознанно: --enable-firewall"
        return 0
    fi
    risk HIGH "включаю ufw с default deny incoming. Держите открытой вторую сессию."
    apt_install ufw
    command -v ufw >/dev/null 2>&1 || { log WARN "ufw недоступен — модуль прерван"; return 0; }

    if [[ "$FW" == "ufw-active" ]]; then
        if is_apply; then
            mkdir -p "${BACKUP_DIR}/etc-ufw-pre"; cp -a /etc/ufw/. "${BACKUP_DIR}/etc-ufw-pre/" 2>/dev/null || true
        fi
        add_rollback "cp -a \"${BACKUP_DIR}/etc-ufw-pre/.\" /etc/ufw/ 2>/dev/null && ufw reload >/dev/null 2>&1; echo \"правила ufw восстановлены\""
    else
        add_rollback "ufw --force disable; echo \"ufw выключен (до прогона был неактивен)\""
    fi

    if [[ "$HAS_SSHD" == "yes" && -n "$SSH_PORTS" ]]; then
        log INFO "оставляю открытыми SSH-порт(ы): $SSH_PORTS"
        local p; for p in $SSH_PORTS; do run_q ufw allow "${p}/tcp"; done
    else
        log INFO "sshd не установлен — SSH-правила не добавляю"
    fi

    run_q ufw default deny incoming
    run_q ufw default allow outgoing
    run_q ufw logging "$(tune UFW_LOGLEVEL medium)"

    # ufw применяет собственный /etc/ufw/sysctl.conf ПОСЛЕ sysctl.d и гасит
    # log_martians. Чиним значения на месте.
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        local UFS=/etc/ufw/sysctl.conf k d=$'\x01'
        for k in net/ipv4/conf/all/log_martians net/ipv4/conf/default/log_martians; do
            if grep -q "^${k}=1$" "$UFS" && ! grep -Eq "^${k}=0" "$UFS"; then
                log OK "$UFS: ${k}=1 уже"
            else
                backup "$UFS"
                if is_apply; then
                    sed -ri "s${d}^${k}=[0-9]+${d}${k}=1${d}" "$UFS"
                    grep -q "^${k}=1$" "$UFS" || printf '%s=1\n' "$k" >>"$UFS"
                fi
                log OK "$UFS: ${k} -> 1"; record "ufw sysctl ${k}=1"
            fi
        done
    fi

    run_q ufw --force enable
    is_apply && apply_sysctl        # ufw при старте перекрывает sysctl.d
    is_apply && log OK "ufw: deny incoming, allow outgoing, логирование $(tune UFW_LOGLEVEL medium)"
    record "ufw enabled"
    [[ "$HAS_VIRT" == "yes" ]] && risk MED "Docker обходит ufw через собственные цепочки nftables — опубликованные порты контейнеров он НЕ закроет"
}

# ============================================================================
#  АУДИТ-МОДУЛИ
# ============================================================================
audit_sysctl-kernel() {
    a_sysctl_min HIGH kernel.kptr_restrict 2
    a_sysctl_min MED  kernel.dmesg_restrict 1
    a_sysctl_min MED  kernel.perf_event_paranoid 3
    a_sysctl_min HIGH kernel.randomize_va_space 2
    a_sysctl_min MED  kernel.yama.ptrace_scope 1
    a_sysctl_min MED  kernel.unprivileged_bpf_disabled 1
    a_sysctl_min LOW  net.core.bpf_jit_harden 2
    a_sysctl_min MED  fs.protected_hardlinks 1
    a_sysctl_min MED  fs.protected_symlinks 1
    a_sysctl_min LOW  fs.protected_fifos 2
    a_sysctl_min LOW  fs.protected_regular 2
}
audit_sysctl-network() {
    a_sysctl HIGH net.ipv4.conf.all.accept_redirects 0
    a_sysctl HIGH net.ipv4.conf.all.accept_source_route 0
    a_sysctl MED  net.ipv4.conf.all.send_redirects 0
    a_sysctl_min MED  net.ipv4.conf.all.log_martians 1
    a_sysctl_min MED  net.ipv4.tcp_syncookies 1
    a_sysctl_min LOW  net.ipv4.icmp_echo_ignore_broadcasts 1
    a_sysctl MED  net.ipv6.conf.all.accept_redirects 0
}
audit_journald() {
    if [[ -d /var/log/journal ]]; then chk PASS HIGH logging "journal persistent" есть есть
    else chk FAIL HIGH logging "journal persistent" есть "нет (логи теряются при перезагрузке)"; fi
    a_kv MED /etc/systemd/journald.conf.d/99-zavetsec.conf Storage persistent
    a_kv LOW /etc/systemd/journald.conf.d/99-zavetsec.conf SystemMaxUse "$(tune JOURNAL_MAXUSE 2G)"
    a_kv LOW /etc/systemd/journald.conf.d/99-zavetsec.conf MaxRetentionSec "$(tune JOURNAL_RETENTION 90day)"
    local boots; boots="$(journalctl --list-boots 2>/dev/null | grep -c . )"; boots="${boots:-0}"
    if [[ "$boots" -gt 1 ]]; then chk PASS MED logging "история загрузок" ">1" "$boots"
    else chk WARN MED logging "история загрузок" ">1" "$boots"; fi
}
audit_auditd() {
    a_pkg_present HIGH auditd
    a_svc_on HIGH auditd
    if [[ -f /etc/audit/rules.d/99-zavetsec.rules ]]; then chk PASS HIGH logging "правила ZavetSec" есть есть
    else chk FAIL HIGH logging "правила ZavetSec" есть нет; fi
    a_kv MED /etc/audit/auditd.conf max_log_file "$(tune AUDIT_MAXFILE 64)"
    a_kv MED /etc/audit/auditd.conf num_logs "$(tune AUDIT_NUMLOGS 10)"
    a_kv MED /etc/audit/auditd.conf max_log_file_action KEEP_LOGS
    if [[ "$(id -u)" -eq 0 ]] && command -v auditctl >/dev/null 2>&1; then
        local n; n="$(auditctl -l 2>/dev/null | grep -c . )"; n="${n:-0}"
        if [[ "$n" -gt 10 ]]; then chk PASS HIGH logging "загруженных правил" ">10" "$n"
        else chk FAIL HIGH logging "загруженных правил" ">10" "$n"; fi
    else chk SKIP HIGH logging "загруженных правил" ">10" "нужен root"; fi
}
audit_ssh() {
    [[ "$HAS_SSHD" == "yes" ]] || { chk SKIP LOW ssh "sshd" "не установлен" "ок для десктопа"; return; }
    a_sshd HIGH permitrootlogin "$(tune SSH_PERMIT_ROOT prohibit-password)"
    a_sshd HIGH permitemptypasswords no
    a_sshd MED  loglevel VERBOSE
    a_sshd MED  x11forwarding no
    a_sshd LOW  maxauthtries "$(tune SSH_MAXAUTH 4)"
    if [[ -n "$SSHD_EFFECTIVE" ]]; then
        if printf '%s\n' "$SSHD_EFFECTIVE" | grep -qi 'mlkem768x25519'; then
            chk PASS HIGH ssh "постквантовый KEX" mlkem768 есть
        else chk FAIL HIGH ssh "постквантовый KEX" mlkem768 отсутствует; fi
    else chk SKIP HIGH ssh "постквантовый KEX" mlkem768 "нужен root"; fi
}
audit_auth() {
    a_kv MED /etc/login.defs ENCRYPT_METHOD YESCRYPT
    a_kv LOW /etc/login.defs PASS_MAX_DAYS "$(tune PASS_MAX_DAYS 365)"
    a_kv LOW /etc/login.defs FAILLOG_ENAB yes
    a_pkg_present MED libpam-pwquality
    a_kv MED /etc/security/pwquality.conf minlen "$(tune PWQ_MINLEN 12)"
}
audit_filesystem() {
    local m; m="$(findmnt -no OPTIONS /dev/shm 2>/dev/null | head -1)"
    if [[ "$m" == *nosuid* && "$m" == *nodev* ]]; then chk PASS MED fs "/dev/shm nodev,nosuid" да да
    else chk FAIL MED fs "/dev/shm nodev,nosuid" да "${m:-?}"; fi
    local f; for f in cramfs freevxfs jffs2; do
        if grep -rqs "install ${f} /bin/true" /etc/modprobe.d/; then chk PASS LOW fs "${f} отключён" да да
        else chk FAIL LOW fs "${f} отключён" да нет; fi
    done
}
audit_services() {
    local p
    for p in telnetd rsh-server xinetd nis tftpd-hpa; do
        apt_installed "$p" && chk FAIL MED packages "$p не установлен" нет есть \
                           || chk PASS MED packages "$p не установлен" нет нет
    done
}
audit_extras() {
    a_pkg_present LOW debsums; a_pkg_present LOW sysstat; a_pkg_present LOW acct
    a_pkg_present MED unattended-upgrades
    a_kv MED /etc/apt/apt.conf.d/20auto-upgrades 'APT::Periodic::Unattended-Upgrade' '"1";'
    if [[ "$HAS_SSHD" == "yes" ]]; then a_pkg_present MED fail2ban; a_svc_on MED fail2ban
    else chk SKIP LOW packages "fail2ban" "не нужен" "sshd нет"; fi
}
audit_apparmor() {
    a_svc_on HIGH apparmor
    if command -v aa-status >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
        local n; n="$(aa-status --profiled 2>/dev/null | head -1)"; n="${n:-0}"
        if [[ "${n:-0}" -gt 0 ]]; then chk PASS HIGH mac "профилей AppArmor" ">0" "$n"
        else chk FAIL HIGH mac "профилей AppArmor" ">0" "$n"; fi
    else chk SKIP HIGH mac "профилей AppArmor" ">0" "нужен root"; fi
}
audit_misc() {
    a_file_mode HIGH /etc/shadow 640
    a_file_owner HIGH /etc/shadow root:shadow
    a_file_mode MED /etc/sudoers.d 750
    a_file_mode LOW /etc/passwd 644
    if [[ "$SUDO_IMPL" == "sudo-rs" ]]; then
        chk PASS MED logging "логирование sudo" "journald" "sudo-rs пишет в journald"
    elif [[ -f /etc/sudoers.d/99-zavetsec-hardening ]]; then
        chk PASS MED logging "логирование sudo" logfile настроено
    else chk WARN MED logging "логирование sudo" logfile "не настроено"; fi
    if [[ -f /etc/cron.allow ]] && [[ ! -s /etc/cron.allow ]]; then
        chk WARN MED misc "пустой /etc/cron.allow" "нет файла" "есть — cron отобран у пользователей"
    else chk PASS MED misc "cron доступен пользователям" да да; fi
}
audit_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then chk SKIP LOW firewall "ufw" "—" "не установлен"; return; fi
    if [[ "$(id -u)" -ne 0 ]]; then chk SKIP LOW firewall "ufw" "—" "нужен root"; return; fi
    if ufw status 2>/dev/null | grep -qi 'Status: active'; then
        chk PASS LOW firewall "ufw активен" "—" активен
    else
        chk WARN LOW firewall "ufw активен" "—" "неактивен (ожидаемо: выключен по умолчанию)"
    fi
}

# ============================================================================
#  ОТЧЁТЫ
# ============================================================================
report_txt() {
    local out="$1" r
    {
    printf 'ZavetSec-Harden %s — отчёт аудита\n' "$ZSVER"
    printf 'Хост: %s   Дата: %s\n' "$(hostname 2>/dev/null)" "$(_ts)"
    printf 'Система: %s\n' "${UB_PRETTY:-?}"
    printf 'sudo: %s   coreutils: %s   sshd: %s   rsyslog: %s\n\n' "$SUDO_IMPL" "$COREUTILS" "$HAS_SSHD" "$RSYSLOG"
    [[ "$(id -u)" -ne 0 ]] && printf '!! ЗАПУЩЕНО НЕ ОТ ROOT — часть проверок пропущена, оценка занижена\n\n'
    _pad 7 "СТАТУС"; _pad 6 "ВАЖН"; _pad 11 "КАТЕГ"; _pad 43 "ПРОВЕРКА"; _pad 23 "ОЖИДАЕТСЯ"; printf 'ФАКТ\n'
    printf '%s\n' "$(printf '%.0s-' {1..112})"
    for r in "${AUDIT_RESULTS[@]}"; do
        IFS='|' read -r st sv ct ck ex ac _ <<<"$r"
        _pad 7 "$st"; _pad 6 "$sv"; _pad 11 "$ct"; _pad 43 "$ck"; _pad 23 "$ex"; printf '%s\n' "$ac"
    done
    local total=$((A_PASS+A_FAIL)) score=0
    [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    printf '\nИТОГ: %s%%  (PASS %s / FAIL %s / WARN %s / SKIP %s)\n' "$score" "$A_PASS" "$A_FAIL" "$A_WARN" "$A_SKIP"
    } > "$out"
}
report_html() {
    local out="$1" r total=$((A_PASS+A_FAIL)) score=0
    [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    {
    cat <<HEAD
<!doctype html><html lang="ru"><meta charset="utf-8">
<title>ZavetSec audit — $(he "$(hostname 2>/dev/null)")</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;background:#0f1115;color:#d8dee9}
h1{font-size:1.4rem} .score{font-size:2rem;font-weight:700}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{padding:.4rem .6rem;border-bottom:1px solid #232833;text-align:left;font-size:13px}
th{color:#8fa1b3;font-weight:600}
.PASS{color:#7ddc9a}.FAIL{color:#e06c75}.WARN{color:#e5c07b}.SKIP{color:#5c6570}
.meta{color:#8fa1b3;font-size:13px}
</style>
<h1>ZavetSec-Harden ${ZSVER} — аудит</h1>
<p class="meta">$(he "${UB_PRETTY:-?}") · хост $(he "$(hostname 2>/dev/null)") · $(he "$(_ts)")<br>
sudo: $(he "$SUDO_IMPL") · coreutils: $(he "$COREUTILS") · sshd: $(he "$HAS_SSHD") · rsyslog: $(he "$RSYSLOG")</p>
<p class="score">${score}%</p>
<p class="meta">PASS ${A_PASS} · FAIL ${A_FAIL} · WARN ${A_WARN} · SKIP ${A_SKIP}</p>
HEAD
    [[ "$(id -u)" -ne 0 ]] && echo '<p class="WARN">Запущено не от root — часть проверок пропущена, оценка занижена.</p>'
    echo '<table><thead><tr><th>Статус</th><th>Важн.</th><th>Категория</th><th>Проверка</th><th>Ожидается</th><th>Факт</th></tr></thead><tbody>'
    for r in "${AUDIT_RESULTS[@]}"; do
        IFS='|' read -r st sv ct ck ex ac _ <<<"$r"
        printf '<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "$(he "$st")" "$(he "$st")" "$(he "$sv")" "$(he "$ct")" "$(he "$ck")" "$(he "$ex")" "$(he "$ac")"
    done
    echo '</tbody></table></html>'
    } > "$out"
}

# ============================================================================
#  MAIN
# ============================================================================
banner() {
cat <<EOF
${C_GRN}${C_BLD}
  ╔══════════════════════════════════════════════════════════╗
  ║   ZavetSec-Harden  v${ZSVER}                  ║
  ║   Ubuntu 26.04 LTS · DESKTOP                             ║
  ║   dry-run по умолчанию · ufw выключен · бэкап+откат       ║
  ╚══════════════════════════════════════════════════════════╝${C_RST}
EOF
}
usage() { awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; }
in_csv() { [[ ",$2," == *",$1,"* ]]; }

while [[ $# -gt 0 ]]; do case "$1" in
    --apply) MODE="apply";; --dry-run) MODE="dryrun";; --check|--audit) MODE="audit";;
    --enable-firewall) WANT_FW=1;;
    --report-dir) REPORT_DIR="$2"; shift;; --report-dir=*) REPORT_DIR="${1#*=}";;
    --format) FMT="$2"; shift;; --format=*) FMT="${1#*=}";;
    --only) ONLY="$2"; shift;; --only=*) ONLY="${1#*=}";;
    --skip) SKIP="$2"; shift;; --skip=*) SKIP="${1#*=}";;
    --state-dir) STATE_DIR="$2"; shift;; --state-dir=*) STATE_DIR="${1#*=}";;
    --detect-only) DETECT_ONLY=1;; --force) FORCE=1;;
    --list) printf '%s\n' "${MODULES[@]}"; exit 0;;
    --no-color) export NO_COLOR=1;;
    -h|--help) banner; usage; exit 0;; --version) echo "$ZSVER"; exit 0;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2;;
esac; shift; done

if [[ "$MODE" == "apply" ]]; then
    if ! mkdir -p "${STATE_DIR}/backup" 2>/dev/null; then
        STATE_DIR="${TMPDIR:-/tmp}/zavetsec-harden/${RUN_TS}"
        mkdir -p "${STATE_DIR}/backup" 2>/dev/null || { echo "ОШИБКА: не создать каталог состояния" >&2; exit 1; }
        STATE_DIR_FALLBACK=1
    fi
    BACKUP_DIR="${STATE_DIR}/backup"; LOG_FILE="${STATE_DIR}/harden.log"
    CHANGES="${STATE_DIR}/changes.log"; ROLLBACK="${STATE_DIR}/rollback.sh"
    printf '#!/usr/bin/env bash\n# Автооткат прогона %s\nset -u\n' "$RUN_TS" > "$ROLLBACK"
else
    BACKUP_DIR=""; LOG_FILE="/dev/null"; ROLLBACK="/dev/null"
    CHANGES="$(mktemp /tmp/zs-changes.XXXXXX)"
    trap 'rm -f "$CHANGES"' EXIT
fi

banner
[[ "${STATE_DIR_FALLBACK:-0}" == "1" ]] && log INFO "каталог состояния: ${STATE_DIR} (в /var/log нет прав)"
[[ "$MODE" == "apply" && "$(id -u)" -ne 0 ]] && die "режим --apply требует root. Запустите через sudo."
[[ "$(id -u)" -ne 0 ]] && log WARN "не root — детект работает, часть проверок будет пропущена"

detect

if [[ "$IS_UBUNTU" == "no" ]]; then
    log WARN "это не Ubuntu (id=${UB_ID})"
    [[ "$FORCE" == "1" ]] || die "отказываюсь работать не на Ubuntu. Обход: --force (не рекомендуется)."
fi
if [[ "$UB_MAJOR" -ne 26 ]]; then
    log WARN "эта версия рассчитана на Ubuntu 26.04, обнаружено: ${UB_VER:-?}"
    [[ "$FORCE" == "1" ]] || die "для других выпусков используйте общую версию скрипта, либо --force."
fi
[[ "$HAS_GUI" == "no" ]] && log WARN "GUI не обнаружен — это desktop-профиль, на сервере он даст более мягкие настройки"

print_detect
[[ "$DETECT_ONLY" == "1" ]] && { log INFO "только детект — выход."; exit 0; }

load_profile
log INFO "профиль: ${C_YEL}desktop-2604${C_RST}   ufw: ${C_YEL}$([[ "$WANT_FW" == "1" ]] && echo "будет включён" || echo "не трогается")${C_RST}"
echo

if [[ "$MODE" == "audit" ]]; then
    log INFO "РЕЖИМ АУДИТА — только чтение, изменений не будет"
    [[ "$(id -u)" -ne 0 ]] && log WARN "не root — проверки sshd -T / auditctl / прав файлов будут пропущены"
    echo
    a_sshd_init
    for m in "${MODULES[@]}"; do
        [[ -n "$ONLY" ]] && ! in_csv "$m" "$ONLY" && continue
        [[ -n "$SKIP" ]] &&   in_csv "$m" "$SKIP" && continue
        CURMOD="$m"
        printf '%s──[ %s ]%s\n' "$C_DIM" "$m" "$C_RST"
        "audit_${m}" 2>/dev/null || log INFO "нет проверок для ${m}"
    done
    CURMOD="core"; echo

    total=$((A_PASS+A_FAIL)); score=0; [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    scol="$C_GRN"; [[ $score -lt 90 ]] && scol="$C_YEL"; [[ $score -lt 70 ]] && scol="$C_RED"
    printf '%s\n' "${C_BLD}${C_GRN}  ИТОГИ АУДИТА${C_RST}"
    printf '  Соответствие: %s%s%%%s  (%sPASS %s%s %sFAIL %s%s %sWARN %s%s %sSKIP %s%s)\n' \
        "$scol" "$score" "$C_RST" "$C_GRN" "$A_PASS" "$C_RST" "$C_RED" "$A_FAIL" "$C_RST" \
        "$C_YEL" "$A_WARN" "$C_RST" "$C_DIM" "$A_SKIP" "$C_RST"
    echo
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp"
    host="$(hostname 2>/dev/null || echo host)"
    base="${REPORT_DIR%/}/zavetsec-audit-${host}-${RUN_TS}"
    case "$FMT" in
        txt)  report_txt "${base}.txt";  log OK "TXT-отчёт:  ${base}.txt";;
        html) report_html "${base}.html"; log OK "HTML-отчёт: ${base}.html";;
        both|*) report_txt "${base}.txt"; report_html "${base}.html"
                log OK "TXT-отчёт:  ${base}.txt"; log OK "HTML-отчёт: ${base}.html";;
    esac
    [[ $A_FAIL -gt 0 ]] && log WARN "${A_FAIL} проваленных проверок — исправить: sudo $0 --apply"
    echo
    exit 0
fi

if [[ "$MODE" == "apply" ]]; then
    log WARN "РЕЖИМ ПРИМЕНЕНИЯ. Бэкапы: ${BACKUP_DIR}"
    if [[ -t 0 ]]; then
        read -r -p "  Продолжить? [введите YES]: " a
        [[ "$a" == "YES" ]] || die "отменено."
    fi
    echo
fi

rc=0
for m in "${MODULES[@]}"; do
    [[ -n "$ONLY" ]] && ! in_csv "$m" "$ONLY" && continue
    [[ -n "$SKIP" ]] &&   in_csv "$m" "$SKIP" && { log INFO "пропуск $m"; continue; }
    CURMOD="$m"
    printf '%s──[ %s ]%s\n' "$C_DIM" "$m" "$C_RST"
    "mod_${m}" || { log WARN "модуль $m вернул rc=$?"; rc=$((rc+1)); }
    echo
done
CURMOD="core"

if [[ "$MODE" == "apply" ]]; then
    cat >>"$ROLLBACK" <<'RBEOF'
# --- финал ---
sysctl --system >/dev/null 2>&1 || true
systemctl restart systemd-journald >/dev/null 2>&1 || true
command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 || true
echo
echo "Откат ЭТОГО прогона завершён."
echo "ЗАМЕЧАНИЯ:"
echo " * параметры ядра и загруженные правила аудита сохранят текущие значения"
echo "   до ПЕРЕЗАГРУЗКИ — перезагрузитесь, чтобы завершить откат"
echo " * установленные пакеты (auditd, sysstat, unattended-upgrades...) остаются"
echo " * /var/log/journal не удаляется: там уже лежат ваши логи"
echo " * откат ПОПРОГОННЫЙ: если применяли несколько раз, запускайте rollback.sh"
echo "   от новых к старым"
RBEOF
    chmod +x "$ROLLBACK" 2>/dev/null || true
fi

printf '%s\n' "${C_BLD}${C_GRN}  ИТОГ${C_RST}"
n=0; [[ -f "$CHANGES" ]] && n="$(wc -l <"$CHANGES" | tr -d ' ')"
printf '  Зафиксировано действий: %s\n' "$n"
if [[ "$MODE" == "apply" ]]; then
    printf '  Бэкапы: %s\n  Откат:  %s\n  Лог:    %s\n' "$BACKUP_DIR" "$ROLLBACK" "$LOG_FILE"
    printf '\n  %sОткатить этот прогон:%s sudo bash %s\n' "$C_YEL" "$C_RST" "$ROLLBACK"
    printf '  %sПроверить результат:%s  sudo %s --audit\n' "$C_CYN" "$C_RST" "$0"
else
    printf '  %sDry-run — ничего не изменено.%s Для применения: --apply\n' "$C_DIM" "$C_RST"
    rm -f "$CHANGES" 2>/dev/null
fi
[[ $rc -gt 0 ]] && log WARN "$rc модуль(ей) вернули ненулевой код — проверьте лог."
echo
exit 0
