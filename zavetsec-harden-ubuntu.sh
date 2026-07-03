#!/usr/bin/env bash
# ============================================================================
#  ZavetSec-Harden-Ubuntu  ::  single-file security baseline for Ubuntu
#  Target: Ubuntu Server/Desktop 20.04 / 22.04 / 24.04 LTS (systemd).
#
#  Ubuntu-specific by design:
#    * apt / dpkg directly              * ufw as primary firewall
#    * AppArmor (never SELinux)         * ssh.socket aware (24.04+)
#    * pam-auth-update for faillock     * apport / snap / squashfs handled
#    * shadow perms fixed 640 root:shadow
#
#  SAFE BY DEFAULT: dry-run unless --apply. Every change is backed up and a
#  rollback script is generated. Anti-lockout guards on ssh & firewall.
#
#  Usage:
#    sudo ./zavetsec-harden-ubuntu.sh                  # detect + dry-run
#    sudo ./zavetsec-harden-ubuntu.sh --detect-only
#    sudo ./zavetsec-harden-ubuntu.sh --apply          # enforce (auto profile)
#    sudo ./zavetsec-harden-ubuntu.sh --apply --profile server
#    sudo ./zavetsec-harden-ubuntu.sh --apply --role container-host
#    sudo ./zavetsec-harden-ubuntu.sh --audit                     # audit only, no changes -> TXT+HTML report
#    sudo ./zavetsec-harden-ubuntu.sh --audit --profile server --format html
#    sudo ./zavetsec-harden-ubuntu.sh --audit --report-dir /var/log/zs-audit
#    sudo ./zavetsec-harden-ubuntu.sh --only ssh,firewall --apply
#    sudo ./zavetsec-harden-ubuntu.sh --skip firewall --apply
#    sudo ./zavetsec-harden-ubuntu.sh --list
#    sudo bash <state-dir>/rollback.sh                 # revert a run
# ============================================================================
set -uo pipefail

ZSVER="1.5-ubuntu"
# v1.5 = merge of two divergent v1.4 branches:
#   * ufw log_martians clobber root-caused (confirmed on 24.04): ufw ships
#     ACTIVE net/ipv4/conf/{all,default}/log_martians=0 in its own
#     /etc/ufw/sysctl.conf and applies it on start, after sysctl.d. The old
#     append-a-=1-line pin was insufficient — the =0 lines are now fixed IN
#     PLACE, and sysctl --system re-runs after `ufw enable` so sysctl.d wins
#     immediately, not just at next boot.
# v1.4 additions (lynis round 2 + earlier review items):
#   * auth: hashing cost pinned — YESCRYPT_COST_FACTOR (jammy+) or
#     SHA_CRYPT_MIN/MAX_ROUNDS (focal)                         [AUTH-9230]
#   * extras: unattended-upgrades installed + 20auto-upgrades enforced
#     (security patching beats half the sysctls combined; opt-out via
#     ZS_TUNE_AUTO_UPGRADES=0)
#   * extras: fail2ban jail.local written (survives package updates);
#     existing user-managed jail.local is left untouched        [DEB-0880]
#   * extras: acct + sysstat installed and enabled     [ACCT-9622/9626]
#   * misc: sudoers hardening (use_pty, logfile) — validated with
#     visudo -c, auto-removed if rejected               [AUTH-9252 adj.]
#   * audit reports (TXT+HTML) now show a prominent warning when run
#     without root (sshd/ufw/AppArmor checks skip => score misleading)
# v1.3 fixes:
#   * set_kv: sed used '|' as delimiter while the pattern contains a '|'
#     alternation -> sed errored on EVERY in-place edit of a pre-existing
#     key, yet the function logged OK. Silently broken since v1.0 for:
#     login.defs (PASS_MAX_DAYS/PASS_MIN_DAYS/UMASK/ENCRYPT_METHOD),
#     pwquality.conf, faillock.conf, coredump.conf, /etc/default/apport.
#     Files created from scratch (sysctl.d, sshd drop-in) were unaffected
#     because they take the append path.                       [CRITICAL]
#   * set_kv now VERIFIES every write and logs ERR on failure
#   * set_kv no longer rewrites commented lines (used to clobber doc
#     comments like "#  PASS_MAX_DAYS  Maximum number of days...");
#     commented-only keys get an appended line (last value wins)
# v1.2 (lynis-driven additions):
#   * new module `extras`: fail2ban, debsums, apt-listchanges, needrestart,
#     libpam-tmpdir; fail2ban enabled (Ubuntu default sshd jail)
#                                   [DEB-0280/0810/0811/0831/0880, PKGS-7370]
#   * blacklist uncommon net protocols dccp/sctp/rds/tipc      [NETW-3200]
#   * sysctl: dev.tty.ldisc_autoload=0, kernel.core_uses_pid=1;
#     net.core.bpf_jit_harden=2 now set unconditionally        [KRNL-6000]
#   * pin log_martians in /etc/ufw/sysctl.conf + post-apply verify (ufw
#     re-applies its own sysctl on start and can clobber sysctl.d values)
#   * sshd: TCPKeepAlive no; MaxAuthTries default 4->3; MaxSessions now
#     tunable (server profile: 2)                              [SSH-7408]
#   * /etc/sudoers.d tightened to 750                          [AUTH-9252]
# v1.1 fixes:
#   * sshd drop-in renamed 99- -> 00- (sshd is first-match-wins; 99- lost to
#     50-cloud-init.conf and friends)                     [CRITICAL]
#   * run with >/dev/null used to swallow DRY output -> run_q added; dry-run
#     now shows every firewall/service action             [CRITICAL]
#   * pam_faillock profile priorities were inverted (authfail ran BEFORE
#     pam_unix => counted successful logins as failures) -> rewritten as
#     preauth(1025)/authfail(0)/authsucc(Additional)      [CRITICAL]
#   * ENCRYPT_METHOD YESCRYPT gated to 22.04+ (focal shadow lacks yescrypt)
#   * SSH port scrape could pick "1" out of [::1]:22 -> proper awk parsing
#   * rollback no longer force-disables ufw that was active BEFORE the run
#   * failed sshd -t now restores previous drop-in from backup, not rm
#   * rollback/backup writes gated to apply mode; state dir falls back to
#     /tmp when /var/log is not writable; b32 audit rules added; misc.

# --- Colors -----------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RST=$'\e[0m'; C_GRN=$'\e[38;5;48m'; C_RED=$'\e[38;5;203m'
    C_YEL=$'\e[38;5;221m'; C_CYN=$'\e[38;5;80m'; C_DIM=$'\e[2m'; C_BLD=$'\e[1m'
else
    C_RST=''; C_GRN=''; C_RED=''; C_YEL=''; C_CYN=''; C_DIM=''; C_BLD=''
fi

# --- Runtime state ----------------------------------------------------------
MODE="dryrun"                 # apply | dryrun | check
PROFILE=""                    # auto from role if empty
ROLE_OVERRIDE=""
ONLY=""; SKIP=""; DETECT_ONLY=0; FORCE=0
REPORT_DIR="."; FMT="both"           # audit report output dir & format (txt|html|both)
RUN_TS="$(date +%Y%m%d-%H%M%S)"
STATE_DIR="/var/log/zavetsec-harden/${RUN_TS}"

# module run order (key -> function). Edit here to add modules.
MODULES=(sysctl-kernel sysctl-network ssh auth firewall auditd \
         filesystem services extras apparmor misc)

# ============================================================================
#  LOGGING / STATE
# ============================================================================
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
CURMOD="core"

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
die() { log ERR "$*"; exit 1; }
risk() { local l="$1"; shift; case "$l" in
    HIGH) log WARN "RISK[HIGH] $*";; MED) log INFO "RISK[MED]  $*";; *) log INFO "RISK[LOW]  $*";; esac; }

record() { printf '%s\t%s\t%s\n' "$CURMOD" "$(_ts)" "$*" >> "$CHANGES" 2>/dev/null || true; }
is_apply() { [[ "$MODE" == "apply" ]]; }

run() { # execute only in apply mode
    if is_apply; then "$@"; else log DRY "would run: $*"; return 0; fi
}
run_q() { # like run, but silences the command itself; DRY line always visible
    if is_apply; then "$@" >/dev/null 2>&1; else log DRY "would run: $*"; return 0; fi
}
add_rollback() { # append a rollback line (apply mode only)
    is_apply || return 0
    printf '%s\n' "$*" >> "$ROLLBACK"
}

backup() {
    local f="$1"; [[ -e "$f" ]] || return 0
    is_apply || return 0
    local dest="${BACKUP_DIR}${f}"
    if [[ ! -e "$dest" ]]; then
        mkdir -p "$(dirname "$dest")"
        cp -a --preserve=all "$f" "$dest" 2>/dev/null || cp -p "$f" "$dest"
        printf 'cp -a --preserve=all "%s" "%s" && echo "restored %s"\n' "$dest" "$f" "$f" >> "$ROLLBACK"
        log INFO "backup: $f"
    fi
}
backup_created() { is_apply || return 0; printf 'rm -f "%s" && echo "removed %s"\n' "$1" "$1" >> "$ROLLBACK"; }

# ============================================================================
#  IDEMPOTENT CONFIG HELPERS
# ============================================================================
set_kv() { # set_kv FILE KEY VALUE [SEP]
    # v1.3: sed delimiter is \x01 — the old '|' delimiter collided with the
    # '|' alternation inside the pattern, sed errored out silently and the
    # function still logged OK. Also: commented-out keys are no longer
    # "uncommented" in place (that also rewrote doc-comment lines like
    # "#  PASS_MAX_DAYS  Maximum number of days...") — we append instead,
    # and last value wins in login.defs/sysctl/pwquality/systemd configs.
    # Every write is now verified; failures log ERR instead of lying.
    local file="$1" key="$2" val="$3" sep="${4:- }" want d=$'\x01'
    want="${key}${sep}${val}"
    if [[ -f "$file" ]] && grep -Eq "^[[:space:]]*${key}([[:space:]]|=)" "$file"; then
        local cur; cur="$(grep -E "^[[:space:]]*${key}([[:space:]]|=)" "$file" | tail -1)"
        [[ "$cur" == "$want" ]] && { log OK "$file: ${key} already=${val}"; return 0; }
        backup "$file"
        if is_apply; then
            sed -ri "s${d}^[[:space:]]*${key}([[:space:]]|=).*${d}${want//&/\\&}${d}" "$file"
            grep -Fxq "$want" "$file" || { log ERR "$file: FAILED to set ${key}=${val} (sed/verify)"; return 1; }
        fi
        log OK "$file: ${key} -> ${val}"; record "$file: ${key}->${val}"
    else
        backup "$file"
        if is_apply; then
            [[ -f "$file" ]] || { : >"$file"; backup_created "$file"; }
            printf '%s\n' "$want" >>"$file"
            grep -Fxq "$want" "$file" || { log ERR "$file: FAILED to append ${key}"; return 1; }
        fi
        log OK "$file: +${key} ${sep} ${val}"; record "$file: +${key} ${val}"
    fi
}
ensure_line() { # ensure_line FILE "line"
    local file="$1" line="$2"
    if [[ -f "$file" ]] && grep -Fxq "$line" "$file"; then log OK "$file: line present"; return 0; fi
    backup "$file"
    if is_apply; then [[ -f "$file" ]] || { : >"$file"; backup_created "$file"; }; printf '%s\n' "$line" >>"$file"; fi
    log OK "$file: + ${line}"; record "$file: +line"
}
write_managed() { # write_managed FILE   (content on stdin)
    local file="$1" content; content="$(cat)"
    if [[ -f "$file" ]] && [[ "$(cat "$file")" == "$content" ]]; then log OK "$file: current"; return 0; fi
    [[ -e "$file" ]] && backup "$file" || backup_created "$file"
    if is_apply; then mkdir -p "$(dirname "$file")"; printf '%s\n' "$content" >"$file"; fi
    log OK "$file: written"; record "$file: managed"
}

SYSCTL_FILE="/etc/sysctl.d/99-zavetsec-harden.conf"
set_sysctl() { set_kv "$SYSCTL_FILE" "$1" "$2" " = "; }
apply_sysctl() { run_q sysctl --system || log WARN "sysctl reload issues"; }

disable_module() { # blacklist kernel module
    local mod="$1" f="/etc/modprobe.d/zavetsec-harden.conf"
    if [[ -f "$f" ]] && grep -q "install ${mod} /bin/true" "$f"; then log OK "module $mod already off"; return 0; fi
    [[ -e "$f" ]] || backup_created "$f"; backup "$f"
    is_apply && { echo "install ${mod} /bin/true"; echo "blacklist ${mod}"; } >>"$f"
    log OK "disable kernel module: $mod"; record "modprobe disable $mod"
}

svc_active()  { systemctl is-active  --quiet "$1" 2>/dev/null; }
svc_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
# NOTE: never `bigcmd | grep -q` under pipefail — grep -q exits on first match,
# bigcmd dies with SIGPIPE (141) and the pipeline goes false despite the match.
# Capture via $() with a full-stream grep instead (reproduced: intermittent
# "auditd/apparmor absent" audit WARNs on real hosts).
svc_exists()  { [[ -n "$(systemctl list-unit-files "${1}*" 2>/dev/null | grep -F -- "$1")" ]]; }
disable_service() {
    local svc="$1"; svc_exists "$svc" || { log INFO "service $svc absent"; return 0; }
    if ! svc_enabled "$svc" && ! svc_active "$svc"; then log OK "service $svc already off"; return 0; fi
    run_q systemctl disable --now "$svc"
    is_apply && log OK "disabled service: $svc"
    record "svc disable $svc"
    add_rollback "systemctl enable --now \"$svc\" 2>/dev/null; echo \"re-enabled $svc\""
}
mask_service() {
    local svc="$1"; run_q systemctl mask --now "$svc"
    is_apply && log OK "masked service: $svc"
    record "svc mask $svc"
    add_rollback "systemctl unmask \"$svc\" 2>/dev/null; echo \"unmasked $svc\""
}

apt_installed() { dpkg -s "$1" >/dev/null 2>&1; }
apt_install() {
    apt_installed "$1" && { log OK "pkg $1 present"; return 0; }
    if ! is_apply; then log DRY "would install: $1"; return 0; fi
    env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" >/dev/null 2>&1 \
        && { log OK "installed: $1"; record "apt install $1"; } \
        || log WARN "could not install $1 (apt update / network?)"
}
apt_remove() {
    apt_installed "$1" || { log OK "pkg $1 absent"; return 0; }
    run_q env DEBIAN_FRONTEND=noninteractive apt-get purge -y "$1"
    log WARN "purged: $1"; record "apt purge $1"
}

enabled() { local v="ZS_ENABLE_${1}"; [[ "${!v:-1}" == "1" ]]; }
tune() { local v="ZS_TUNE_${1}"; printf '%s' "${!v:-$2}"; }

# ============================================================================
#  AUDIT ENGINE  (read-only; compares live state vs profile baseline)
# ============================================================================
AUDIT_RESULTS=()        # entry: STATUS|SEV|CATEGORY|CHECK|EXPECTED|ACTUAL|NOTE
A_PASS=0; A_FAIL=0; A_WARN=0; A_SKIP=0
SSHD_EFFECTIVE=""

he() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }

chk() { # chk STATUS SEV CATEGORY CHECK EXPECTED ACTUAL [NOTE]
    AUDIT_RESULTS+=("$1|$2|$3|$4|$5|$6|${7:-}")
    case "$1" in PASS) A_PASS=$((A_PASS+1));; FAIL) A_FAIL=$((A_FAIL+1));;
        WARN) A_WARN=$((A_WARN+1));; SKIP) A_SKIP=$((A_SKIP+1));; esac
    if [[ "${MODE:-}" == "audit" ]]; then
        local col; case "$1" in PASS) col="$C_GRN";; FAIL) col="$C_RED";; WARN) col="$C_YEL";; *) col="$C_DIM";; esac
        printf '  %s%-4s%s %-9s %-40s %s\n' "$col" "$1" "$C_RST" "[$3]" "$4" "${C_DIM}exp=${5} got=${6}${C_RST}"
    fi
}
_cmp() { if [[ "$4" == "$5" ]]; then chk PASS "$1" "$2" "$3" "$4" "$5" "${6:-}"; else chk FAIL "$1" "$2" "$3" "$4" "$5" "${6:-}"; fi; }

a_sysctl() { # SEV KEY EXPECTED
    local v; v="$(sysctl -n "$2" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/ *$//')"
    [[ -z "$v" ]] && { chk SKIP "$1" sysctl "$2" "$3" "n/a" "key not present"; return; }
    _cmp "$1" sysctl "$2" "$3" "$v"
}
a_file_mode() { [[ -e "$2" ]] || { chk SKIP "$1" perms "$2 mode" "$3" absent; return; }
    _cmp "$1" perms "$2 mode" "$3" "$(stat -c '%a' "$2" 2>/dev/null)"; }
a_file_owner() { [[ -e "$2" ]] || { chk SKIP "$1" perms "$2 owner" "$3" absent; return; }
    _cmp "$1" perms "$2 owner" "$3" "$(stat -c '%U:%G' "$2" 2>/dev/null)"; }
a_svc_off() {
    if ! svc_exists "$2"; then chk PASS "$1" services "$2 disabled" off absent; return; fi
    local st en; svc_active "$2" && st=active || st=inactive; svc_enabled "$2" && en=enabled || en=disabled
    if [[ "$st" == inactive && "$en" == disabled ]]; then chk PASS "$1" services "$2 disabled" off "$en/$st"
    else chk FAIL "$1" services "$2 disabled" off "$en/$st"; fi
}
a_svc_on() {
    if ! svc_exists "$2"; then chk WARN "$1" services "$2 active" on absent; return; fi
    svc_active "$2" && chk PASS "$1" services "$2 active" on active || chk FAIL "$1" services "$2 active" on inactive
}
a_pkg_absent() { apt_installed "$2" && chk FAIL "$1" packages "$2 removed" absent installed || chk PASS "$1" packages "$2 removed" absent absent; }
a_pkg_present() { apt_installed "$2" && chk PASS "$1" packages "$2 installed" present present || chk FAIL "$1" packages "$2 installed" present absent; }
a_kv() { # SEV FILE KEY EXPECTED   (accepts "key value" or "key = value")
    [[ -f "$2" ]] || { chk SKIP "$1" config "$3" "$4" "file absent"; return; }
    local line val
    line="$(grep -E "^[[:space:]]*${3}[[:space:]=]" "$2" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1)"
    [[ -z "$line" ]] && { chk FAIL "$1" config "$3" "$4" unset "${2##*/}"; return; }
    val="$(echo "$line" | sed -E "s/^[[:space:]]*${3}[[:space:]]*=?[[:space:]]*//" | sed 's/#.*//; s/[[:space:]]*$//')"
    _cmp "$1" config "$3" "$4" "$val" "${2##*/}"
}
a_sshd_init() { [[ "$(id -u)" -eq 0 ]] && command -v sshd >/dev/null 2>&1 && SSHD_EFFECTIVE="$(sshd -T 2>/dev/null)"; }
a_sshd() { # SEV KEY(lowercase) EXPECTED
    command -v sshd >/dev/null 2>&1 || { chk SKIP "$1" ssh "$2" "$3" "sshd absent"; return; }
    [[ -z "$SSHD_EFFECTIVE" ]] && { chk SKIP "$1" ssh "$2" "$3" "needs root (sshd -T)"; return; }
    local v; v="$(echo "$SSHD_EFFECTIVE" | awk -v k="$2" '$1==k{$1="";sub(/^ /,"");print;exit}')"
    [[ -z "$v" ]] && { chk WARN "$1" ssh "$2" "$3" "not reported"; return; }
    # sshd -T normalizes prohibit-password to its legacy synonym without-password
    local want="${3,,}" got="${v,,}"
    [[ "$want" == "prohibit-password" ]] && want="without-password"
    [[ "$got"  == "prohibit-password" ]] && got="without-password"
    if [[ "$got" == "$want" ]]; then chk PASS "$1" ssh "$2" "$3" "$v"; else chk FAIL "$1" ssh "$2" "$3" "$v"; fi
}

# ============================================================================
#  DETECT (Ubuntu-focused)
# ============================================================================
detect() {
    UB_ID="unknown"; UB_VER=""; UB_PRETTY=""; UB_CODENAME=""
    if [[ -r /etc/os-release ]]; then . /etc/os-release
        UB_ID="${ID:-unknown}"; UB_VER="${VERSION_ID:-}"; UB_PRETTY="${PRETTY_NAME:-}"
        UB_CODENAME="${VERSION_CODENAME:-}"; UB_LIKE="${ID_LIKE:-}"
    fi
    # Ubuntu or Ubuntu-derivative?
    IS_UBUNTU="no"
    [[ "$UB_ID" == "ubuntu" ]] && IS_UBUNTU="yes"
    [[ " ${UB_LIKE:-} " == *" ubuntu "* ]] && IS_UBUNTU="derivative"

    INIT="unknown"
    if [[ -d /run/systemd/system ]]; then INIT="systemd"
    else INIT="$(ps -p 1 -o comm= 2>/dev/null)"; fi

    IS_CONTAINER="no"
    { [[ -f /.dockerenv || -f /run/.containerenv ]] || \
      { command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container >/dev/null 2>&1; } || \
      grep -qaE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; } && IS_CONTAINER="yes"

    # firewall: ufw preferred on Ubuntu
    FW="none"
    if command -v ufw >/dev/null 2>&1; then
        if [[ -n "$(ufw status 2>/dev/null | grep -i 'Status: active')" ]]; then FW="ufw-active"; else FW="ufw"; fi
    elif systemctl is-active --quiet nftables 2>/dev/null; then FW="nftables"
    elif command -v nft >/dev/null 2>&1; then FW="nftables"
    elif command -v iptables >/dev/null 2>&1; then FW="iptables"; fi

    # AppArmor (Ubuntu MAC)
    AA="none"
    if command -v aa-status >/dev/null 2>&1 || [[ -d /sys/kernel/security/apparmor ]]; then AA="apparmor"; fi

    # GUI / desktop?
    HAS_GUI="no"
    { systemctl get-default 2>/dev/null | grep -q graphical; } && HAS_GUI="yes"
    apt_installed ubuntu-desktop 2>/dev/null && HAS_GUI="yes"
    [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && HAS_GUI="yes"

    # ssh unit style (24.04 uses ssh.socket)
    SSH_UNIT="ssh.service"; SSH_SOCKET="no"
    if svc_exists ssh.socket && svc_enabled ssh.socket; then SSH_SOCKET="yes"; fi

    # role
    if [[ -n "$ROLE_OVERRIDE" ]]; then ROLE="$ROLE_OVERRIDE"
    elif [[ "$IS_CONTAINER" == "yes" ]]; then ROLE="container-host"
    elif [[ "$HAS_GUI" == "yes" ]]; then ROLE="workstation"
    else ROLE="server"; fi
    if [[ "$IS_CONTAINER" != "yes" ]] && { command -v dockerd >/dev/null 2>&1 || command -v kubelet >/dev/null 2>&1; }; then
        [[ "$ROLE" == "server" ]] && ROLE="container-host"
    fi

    # ssh port(s)
    local ports=""
    if [[ -r /etc/ssh/sshd_config ]]; then
        ports="$(grep -hiE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}')"
    fi
    # take the LAST colon-field of the Local Address column — safe for [::]:22 / [::1]:2222
    command -v ss >/dev/null 2>&1 && \
        ports="$ports $(ss -tlnp 2>/dev/null | awk '/sshd/{n=split($4,a,":"); if(a[n] ~ /^[0-9]+$/) print a[n]}')"
    SSH_PORTS="$(echo "$ports" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u | tr '\n' ' ' | xargs)"
    [[ -z "$SSH_PORTS" ]] && SSH_PORTS="22"
}

print_detect() {
    printf '%s\n' "${C_BLD}${C_GRN}  DETECTION${C_RST}"
    printf '  %-16s %s\n' "Distro:"    "${UB_PRETTY:-?} (id=${UB_ID}, ver=${UB_VER}, ${UB_CODENAME})"
    printf '  %-16s %s\n' "Is Ubuntu:"  "${IS_UBUNTU}"
    printf '  %-16s %s\n' "Init:"       "${INIT}"
    printf '  %-16s %s\n' "Firewall:"   "${FW}"
    printf '  %-16s %s\n' "MAC:"        "${AA}"
    printf '  %-16s %s\n' "Container:"  "${IS_CONTAINER}"
    printf '  %-16s %s\n' "GUI:"        "${HAS_GUI}"
    printf '  %-16s %s (socket-activated: %s)\n' "SSH:" "${SSH_UNIT}" "${SSH_SOCKET}"
    printf '  %-16s %s\n' "SSH port(s):" "${SSH_PORTS}"
    printf '  %-16s %s%s%s\n' "Role:"   "$C_YEL" "${ROLE}" "$C_RST"
    printf '  %-16s %s%s%s\n' "Mode:"   "$C_CYN" "${MODE}" "$C_RST"
    echo
}

# ============================================================================
#  PROFILES (inline; defaults + delta per role)
# ============================================================================
# shellcheck disable=SC2034  # ZS_* vars are read indirectly via ${!v} in enabled()/tune()
load_profile() {
    # ---- defaults ----
    ZS_ENABLE_SYSCTL_KERNEL=1; ZS_ENABLE_SYSCTL_NETWORK=1; ZS_ENABLE_SSH=1
    ZS_ENABLE_AUTH=1; ZS_ENABLE_FIREWALL=0; ZS_ENABLE_AUDITD=1
    ZS_ENABLE_FILESYSTEM=1; ZS_ENABLE_SERVICES=1; ZS_ENABLE_APPARMOR=1; ZS_ENABLE_MISC=1
    ZS_ENABLE_EXTRAS=1

    ZS_TUNE_PASS_MAX_DAYS=365; ZS_TUNE_PASS_MIN_DAYS=1; ZS_TUNE_PASS_WARN_AGE=14
    ZS_TUNE_UMASK=027; ZS_TUNE_PWQ_MINLEN=14; ZS_TUNE_PWQ_MINCLASS=4
    ZS_TUNE_FAILLOCK_DENY=5; ZS_TUNE_FAILLOCK_UNLOCK=900
    ZS_TUNE_ENABLE_FAILLOCK_PAM=0            # wire faillock into PAM (lockout risk)
    ZS_TUNE_SSH_PERMIT_ROOT="prohibit-password"
    ZS_TUNE_SSH_DISABLE_PASSWORD=0
    ZS_TUNE_SSH_MAXAUTH=3; ZS_TUNE_SSH_GRACE=30
    ZS_TUNE_SSH_MAXSESSIONS=4      # lynis wants 2; 2 breaks ControlMaster / VS Code Remote
    ZS_TUNE_SSH_ALIVE_INTERVAL=300; ZS_TUNE_SSH_ALIVE_COUNT=2
    ZS_TUNE_SSH_ALLOW_TCP_FWD="no"; ZS_TUNE_SSH_X11="no"; ZS_TUNE_SSH_TCP_KEEPALIVE="no"
    ZS_TUNE_NET_FORWARDING=0; ZS_TUNE_PTRACE_SCOPE=1
    ZS_TUNE_DISABLE_BPF_UNPRIV=1; ZS_TUNE_DISABLE_USB_STORAGE=0
    ZS_TUNE_DISABLE_IPV6=0; ZS_TUNE_TMP_NOEXEC=0; ZS_TUNE_AUDIT_IMMUTABLE=0
    ZS_TUNE_DISABLE_APPORT=1                 # crash reporter: off on servers by default
    ZS_TUNE_FS_BLACKLIST="cramfs freevxfs jffs2 hfs hfsplus udf"   # squashfs kept (snap)
    ZS_TUNE_NET_PROTO_BLACKLIST="dccp sctp rds tipc"               # lynis NETW-3200
    ZS_TUNE_EXTRA_PKGS="fail2ban debsums apt-listchanges needrestart libpam-tmpdir acct sysstat"
    ZS_TUNE_DISABLE_SERVICES="avahi-daemon rpcbind"

    # ---- delta per profile ----
    case "$PROFILE" in
        server)
            ZS_ENABLE_FIREWALL=1; ZS_TUNE_SSH_PERMIT_ROOT="no"; ZS_TUNE_SSH_ALIVE_COUNT=0
            ZS_TUNE_SSH_MAXSESSIONS=2
            ZS_TUNE_PTRACE_SCOPE=2; ZS_TUNE_DISABLE_USB_STORAGE=1
            ZS_TUNE_DISABLE_SERVICES="avahi-daemon rpcbind cups cups-browsed bluetooth ModemManager" ;;
        workstation)
            ZS_ENABLE_FIREWALL=1; ZS_TUNE_SSH_PERMIT_ROOT="no"; ZS_TUNE_PTRACE_SCOPE=1
            ZS_TUNE_DISABLE_BPF_UNPRIV=0; ZS_TUNE_DISABLE_USB_STORAGE=0; ZS_TUNE_UMASK=022
            ZS_TUNE_DISABLE_APPORT=0; ZS_TUNE_DISABLE_SERVICES="rpcbind" ;;   # keep cups/avahi/apport on desktop
        container-host)
            ZS_ENABLE_FIREWALL=0; ZS_TUNE_NET_FORWARDING=1; ZS_TUNE_DISABLE_BPF_UNPRIV=0
            ZS_ENABLE_FILESYSTEM=0; ZS_TUNE_SSH_PERMIT_ROOT="no"; ZS_TUNE_PTRACE_SCOPE=1
            ZS_TUNE_DISABLE_USB_STORAGE=1
            ZS_TUNE_DISABLE_SERVICES="avahi-daemon rpcbind cups bluetooth" ;;
        defaults) : ;;
        *) log WARN "unknown profile '$PROFILE' — using defaults"; PROFILE="defaults" ;;
    esac
}

# ============================================================================
#  MODULES
# ============================================================================
mod_sysctl-kernel() {
    enabled SYSCTL_KERNEL || { log INFO "disabled by profile"; return 0; }
    set_sysctl kernel.kptr_restrict 2
    set_sysctl kernel.dmesg_restrict 1
    set_sysctl kernel.printk "3 3 3 3"
    set_sysctl kernel.kexec_load_disabled 1
    set_sysctl kernel.sysrq 0
    set_sysctl kernel.perf_event_paranoid 3
    set_sysctl kernel.randomize_va_space 2
    local p; p="$(tune PTRACE_SCOPE 1)"
    [[ "$p" == "2" ]] && risk MED "ptrace_scope=2 — local gdb/strace on running procs needs root"
    set_sysctl kernel.yama.ptrace_scope "$p"
    if [[ "$(tune DISABLE_BPF_UNPRIV 1)" == "1" ]]; then
        risk MED "unprivileged_bpf_disabled=1 — some eBPF tooling needs root/CAP_BPF"
        set_sysctl kernel.unprivileged_bpf_disabled 1
    else log INFO "unprivileged eBPF left enabled (profile)"; fi
    set_sysctl net.core.bpf_jit_harden 2       # safe even with unpriv BPF on
    set_sysctl dev.tty.ldisc_autoload 0
    set_sysctl kernel.core_uses_pid 1
    set_sysctl fs.protected_hardlinks 1
    set_sysctl fs.protected_symlinks 1
    set_sysctl fs.protected_fifos 2
    set_sysctl fs.protected_regular 2
    # apport (kept on workstation profile) re-sets fs.suid_dumpable=2 on every
    # boot — it needs it to intercept suid crashes. Setting 0 under a live
    # apport is a lie that lasts until reboot; only enforce when apport is off.
    if [[ "$(tune DISABLE_APPORT 1)" == "1" ]]; then
        set_sysctl fs.suid_dumpable 0
    else
        log INFO "fs.suid_dumpable left to apport (enabled by profile) — it sets 2 at boot"
    fi
    apply_sysctl
    # note: user namespaces intentionally NOT disabled (snap/rootless/browser sandbox)
}

mod_sysctl-network() {
    enabled SYSCTL_NETWORK || { log INFO "disabled by profile"; return 0; }
    set_sysctl net.ipv4.conf.all.rp_filter 1
    set_sysctl net.ipv4.conf.default.rp_filter 1
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
    if [[ "$ROLE" == "workstation" ]]; then log INFO "workstation: leaving IPv6 RA at default (SLAAC)"
    else set_sysctl net.ipv6.conf.all.accept_ra 0; set_sysctl net.ipv6.conf.default.accept_ra 0; fi
    if [[ "$(tune NET_FORWARDING 0)" == "1" ]]; then
        log INFO "forwarding kept ON (role=$ROLE — container/router networking)"
        set_sysctl net.ipv4.ip_forward 1
    else
        set_sysctl net.ipv4.ip_forward 0
        set_sysctl net.ipv6.conf.all.forwarding 0
        set_sysctl net.ipv6.conf.default.forwarding 0
    fi
    if [[ "$(tune DISABLE_IPV6 0)" == "1" ]]; then
        risk MED "disabling IPv6 entirely — verify nothing binds v6 first"
        set_sysctl net.ipv6.conf.all.disable_ipv6 1
        set_sysctl net.ipv6.conf.default.disable_ipv6 1
    fi
    log INFO "blacklisting uncommon net protocols (dccp/sctp/rds/tipc)"
    local pr; for pr in $(tune NET_PROTO_BLACKLIST "dccp sctp rds tipc"); do disable_module "$pr"; done
    apply_sysctl
    # detect external sysctl clobber (seen in the wild: value reverted after apply)
    if is_apply; then
        local lm; lm="$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)"
        [[ "$lm" == "1" ]] || log WARN "log_martians is '${lm}' right after apply — something overrides sysctl.d (check /etc/ufw/sysctl.conf, NetworkManager)"
    fi
}

mod_ssh() {
    enabled SSH || { log INFO "disabled by profile"; return 0; }
    command -v sshd >/dev/null 2>&1 || { log INFO "sshd not installed — skipping"; return 0; }
    local MAIN="/etc/ssh/sshd_config" DIR="/etc/ssh/sshd_config.d" DROPIN LEGACY
    # sshd is FIRST-match-wins and the Include sits at the top of sshd_config:
    # among drop-ins the lexicographically FIRST file wins. 00- guarantees our
    # settings beat 50-cloud-init.conf etc. (99- silently lost to them).
    DROPIN="${DIR}/00-zavetsec-harden.conf"
    LEGACY="${DIR}/99-zavetsec-harden.conf"
    if [[ -e "$LEGACY" ]]; then
        backup "$LEGACY"; run rm -f "$LEGACY"
        log INFO "migrating legacy drop-in: 99-zavetsec-harden.conf -> 00-"
    fi

    _filter() { local q="$1"; shift; local sup out=""; sup="$(ssh -Q "$q" 2>/dev/null)" || { echo "$*"; return; }
        local a; for a in "$@"; do grep -qx "$a" <<<"$sup" && out+="${out:+,}$a"; done; echo "$out"; }
    local KEX CIPH MACS
    KEX="$(_filter kex sntrup761x25519-sha512@openssh.com curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group16-sha512 diffie-hellman-group18-sha512)"
    CIPH="$(_filter cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)"
    MACS="$(_filter mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)"

    local DIS_PW; DIS_PW="$(tune SSH_DISABLE_PASSWORD 0)"; local KEYS=0
    [[ -s /root/.ssh/authorized_keys ]] && KEYS=1
    while IFS=: read -r _u _x _uid _g _c home _s; do [[ -s "${home}/.ssh/authorized_keys" ]] && KEYS=1; done \
        < <(getent passwd 2>/dev/null | awk -F: '$3>=1000 && $3<65534')
    local PWLINE="PasswordAuthentication yes   # kept: no SSH keys found (lockout guard)"
    if [[ "$DIS_PW" == "1" ]]; then
        if [[ "$KEYS" == "1" ]]; then PWLINE="PasswordAuthentication no"; log OK "keys present — enforcing key-only"
        else risk HIGH "SSH_DISABLE_PASSWORD=1 but NO authorized_keys — NOT disabling passwords"; fi
    fi
    local PR MA MS GR AI AC TF X11 TKA
    PR="$(tune SSH_PERMIT_ROOT prohibit-password)"; MA="$(tune SSH_MAXAUTH 3)"; MS="$(tune SSH_MAXSESSIONS 4)"
    GR="$(tune SSH_GRACE 30)"; AI="$(tune SSH_ALIVE_INTERVAL 300)"; AC="$(tune SSH_ALIVE_COUNT 2)"
    TF="$(tune SSH_ALLOW_TCP_FWD no)"; X11="$(tune SSH_X11 no)"; TKA="$(tune SSH_TCP_KEEPALIVE no)"

    run mkdir -p "$DIR"
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$MAIN" 2>/dev/null; then
        risk MED "sshd_config lacks Include for sshd_config.d — adding at top"
        if is_apply; then backup "$MAIN"; printf 'Include /etc/ssh/sshd_config.d/*.conf\n%s\n' "$(cat "$MAIN")" >"${MAIN}.zsnew" && mv "${MAIN}.zsnew" "$MAIN"; fi
        record "sshd_config +Include"
    fi

    # OpenSSH 8.7 renamed ChallengeResponseAuthentication -> KbdInteractiveAuthentication.
    # focal ships 8.2 which rejects the new name (sshd -t would fail and self-revert).
    local KBDLINE="KbdInteractiveAuthentication no"
    [[ "${UB_VER%%.*}" =~ ^[0-9]+$ && "${UB_VER%%.*}" -lt 22 ]] && KBDLINE="ChallengeResponseAuthentication no"

    { cat <<EOF
# Managed by ZavetSec-Harden-Ubuntu. Do not edit by hand.
# Generated: $(_ts)
PermitRootLogin ${PR}
${PWLINE}
PermitEmptyPasswords no
${KBDLINE}
MaxAuthTries ${MA}
MaxSessions ${MS}
LoginGraceTime ${GR}
ClientAliveInterval ${AI}
ClientAliveCountMax ${AC}
TCPKeepAlive ${TKA}
X11Forwarding ${X11}
AllowTcpForwarding ${TF}
AllowAgentForwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
PermitTunnel no
Compression no
LogLevel VERBOSE
Banner /etc/issue.net
EOF
    [[ -n "$KEX"  ]] && echo "KexAlgorithms ${KEX}"
    [[ -n "$CIPH" ]] && echo "Ciphers ${CIPH}"
    [[ -n "$MACS" ]] && echo "MACs ${MACS}"; } | write_managed "$DROPIN"

    if is_apply; then
        local SSHD_ERR="${STATE_DIR}/sshd_t.err"
        if sshd -t 2>"$SSHD_ERR"; then
            log OK "sshd -t passed"
            # 24.04 socket-activation aware
            if [[ "$SSH_SOCKET" == "yes" ]]; then
                systemctl daemon-reload 2>/dev/null
                systemctl restart ssh.socket 2>/dev/null && log OK "ssh.socket restarted" || log WARN "restart ssh.socket manually"
            fi
            systemctl reload ssh 2>/dev/null || systemctl reload ssh.service 2>/dev/null \
                && log OK "ssh reloaded (sessions untouched)" || log WARN "reload ssh manually"
        else
            log ERR "sshd -t FAILED — reverting drop-in:"; sed 's/^/    /' "$SSHD_ERR" | while read -r l; do log ERR "$l"; done
            local bkp="${BACKUP_DIR}${DROPIN}"
            if [[ -f "$bkp" ]]; then
                cp -a "$bkp" "$DROPIN"; log WARN "previous drop-in restored from backup; sshd left working"
            else
                rm -f "$DROPIN"; log WARN "drop-in removed; sshd left working"
            fi
        fi
    else log DRY "would validate 'sshd -t' then reload ssh (socket-aware)"; fi
}

mod_auth() {
    enabled AUTH || { log INFO "disabled by profile"; return 0; }
    local LD=/etc/login.defs
    if [[ -f "$LD" ]]; then
        set_kv "$LD" PASS_MAX_DAYS "$(tune PASS_MAX_DAYS 365)" $'\t'
        set_kv "$LD" PASS_MIN_DAYS "$(tune PASS_MIN_DAYS 1)"   $'\t'
        set_kv "$LD" PASS_WARN_AGE "$(tune PASS_WARN_AGE 14)"  $'\t'
        set_kv "$LD" UMASK         "$(tune UMASK 027)"          $'\t'
        # yescrypt is supported from 22.04 (jammy); focal shadow/libcrypt lacks it
        local EM=SHA512
        [[ "${UB_VER%%.*}" =~ ^[0-9]+$ && "${UB_VER%%.*}" -ge 22 ]] && EM=YESCRYPT
        set_kv "$LD" ENCRYPT_METHOD "$EM"                       $'\t'
        # AUTH-9230: pin hashing cost, not just the algorithm
        if [[ "$EM" == "YESCRYPT" ]]; then
            set_kv "$LD" YESCRYPT_COST_FACTOR "$(tune YESCRYPT_COST 8)" $'\t'
        else
            set_kv "$LD" SHA_CRYPT_MIN_ROUNDS "$(tune SHA_ROUNDS 10000)" $'\t'
            set_kv "$LD" SHA_CRYPT_MAX_ROUNDS "$(tune SHA_ROUNDS 10000)" $'\t'
        fi
        set_kv "$LD" FAILLOG_ENAB  yes                          $'\t'
    fi
    apt_install libpam-pwquality
    local PWQ=/etc/security/pwquality.conf
    set_kv "$PWQ" minlen   "$(tune PWQ_MINLEN 14)"  " = "
    set_kv "$PWQ" minclass "$(tune PWQ_MINCLASS 4)" " = "
    set_kv "$PWQ" dcredit -1 " = "; set_kv "$PWQ" ucredit -1 " = "
    set_kv "$PWQ" ocredit -1 " = "; set_kv "$PWQ" lcredit -1 " = "
    set_kv "$PWQ" maxrepeat 3 " = "; set_kv "$PWQ" enforcing 1 " = "

    # pam_faillock requires Linux-PAM >= 1.4 (jammy+). focal (PAM 1.3.1) does
    # NOT ship it — wiring it there writes a broken auth stack => total lockout.
    local HAVE_FAILLOCK=0
    compgen -G "/usr/lib/*/security/pam_faillock.so" >/dev/null 2>&1 && HAVE_FAILLOCK=1
    compgen -G "/lib/*/security/pam_faillock.so"     >/dev/null 2>&1 && HAVE_FAILLOCK=1

    if [[ "$HAVE_FAILLOCK" == "1" ]]; then
        local FL=/etc/security/faillock.conf
        set_kv "$FL" deny        "$(tune FAILLOCK_DENY 5)"    " = "
        set_kv "$FL" unlock_time "$(tune FAILLOCK_UNLOCK 900)" " = "
        set_kv "$FL" fail_interval 900 " = "
        ensure_line "$FL" "audit"
        log OK "faillock.conf written"
    else
        log WARN "pam_faillock not available on this release (PAM < 1.4, e.g. 20.04) — skipping faillock entirely"
    fi

    # PAM wiring via pam-auth-update (Ubuntu-native). OPT-IN (lockout risk).
    #
    # Priority layout (pam_unix profile is Primary, Priority 256):
    #   preauth  1025  Primary    — runs BEFORE pam_unix: refuses locked users
    #   authfail    0  Primary    — runs AFTER pam_unix fails: counts the failure
    #   authsucc  256  Additional — runs on the success path (pam_unix's
    #                               [success=end] jumps PAST remaining Primary
    #                               into Additional): resets the counter
    # Putting authfail ABOVE pam_unix (old 1024) made it fire on EVERY attempt,
    # incl. successful logins — guaranteed lockout after `deny` logins.
    if [[ "$(tune ENABLE_FAILLOCK_PAM 0)" == "1" && "$HAVE_FAILLOCK" != "1" ]]; then
        risk HIGH "ZS_TUNE_ENABLE_FAILLOCK_PAM=1 requested but pam_faillock.so is ABSENT — refusing (would break auth)"
    elif [[ "$(tune ENABLE_FAILLOCK_PAM 0)" == "1" ]]; then
        risk HIGH "wiring pam_faillock into common-auth via pam-auth-update. KEEP a second root session open."
        write_managed /usr/share/pam-configs/zavetsec-faillock-preauth <<'EOF'
Name: ZavetSec faillock — refuse locked-out accounts (preauth)
Default: yes
Priority: 1025
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Auth-Initial:
	requisite	pam_faillock.so preauth
EOF
        write_managed /usr/share/pam-configs/zavetsec-faillock-authfail <<'EOF'
Name: ZavetSec faillock — count failed attempts (authfail)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
Auth-Initial:
	[default=die]	pam_faillock.so authfail
EOF
        write_managed /usr/share/pam-configs/zavetsec-faillock-authsucc <<'EOF'
Name: ZavetSec faillock — reset counter on success (authsucc)
Default: yes
Priority: 256
Auth-Type: Additional
Auth:
	required	pam_faillock.so authsucc
Auth-Initial:
	required	pam_faillock.so authsucc
EOF
        if run_q env DEBIAN_FRONTEND=noninteractive pam-auth-update --enable \
                zavetsec-faillock-preauth zavetsec-faillock-authfail zavetsec-faillock-authsucc; then
            is_apply && log OK "pam-auth-update: faillock wired (preauth/authfail/authsucc)"
        else
            log WARN "pam-auth-update failed — review manually"
        fi
        record "pam-auth-update enable faillock"
        add_rollback "pam-auth-update --disable zavetsec-faillock-preauth zavetsec-faillock-authfail zavetsec-faillock-authsucc 2>/dev/null; echo \"faillock PAM disabled\""
        is_apply && risk HIGH "verify NOW from a SECOND session: 3 wrong passwords must lock, correct password must still work for others"
    else
        risk MED "faillock PAM wiring is OPT-IN (ZS_TUNE_ENABLE_FAILLOCK_PAM=1). Config written; PAM stack untouched."
    fi
}

mod_firewall() {
    enabled FIREWALL || { log INFO "disabled by profile (expected on container-host)"; return 0; }
    local P="$SSH_PORTS"
    log INFO "will keep SSH port(s) open: $P"
    risk HIGH "applying default-deny inbound via ufw. SSH/lo/established preserved."
    apt_install ufw
    command -v ufw >/dev/null 2>&1 || { log WARN "ufw unavailable — aborting firewall module"; return 0; }
    # snapshot pre-run ufw ruleset so rollback restores it instead of killing
    # a firewall the admin had active BEFORE this tool ran
    if [[ "$FW" == "ufw-active" ]]; then
        if is_apply; then
            mkdir -p "${BACKUP_DIR}/etc-ufw-pre"
            cp -a /etc/ufw/. "${BACKUP_DIR}/etc-ufw-pre/" 2>/dev/null || true
        fi
        add_rollback "cp -a \"${BACKUP_DIR}/etc-ufw-pre/.\" /etc/ufw/ 2>/dev/null && ufw reload >/dev/null 2>&1; echo \"ufw rules restored (was active pre-run)\""
    else
        add_rollback "ufw --force disable; echo \"ufw disabled (rollback: was inactive pre-run)\""
    fi
    local p; for p in $P; do run_q ufw allow "${p}/tcp"; done
    run_q ufw default deny incoming
    run_q ufw default allow outgoing
    run_q ufw logging on
    # noble ships ACTIVE log_martians=0 in /etc/ufw/sysctl.conf and ufw applies
    # that file on start, AFTER sysctl.d — fix the lines IN PLACE (the old pin
    # only appended =1 at the end, leaving the =0 lines standing)
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        local UFS=/etc/ufw/sysctl.conf k d=$'\x01'
        for k in net/ipv4/conf/all/log_martians net/ipv4/conf/default/log_martians; do
            if grep -q "^${k}=1$" "$UFS" && ! grep -Eq "^${k}=0" "$UFS"; then
                log OK "$UFS: ${k}=1 already"
            else
                backup "$UFS"
                if is_apply; then
                    sed -ri "s${d}^${k}=[0-9]+${d}${k}=1${d}" "$UFS"
                    grep -q "^${k}=1$" "$UFS" || printf '%s=1\n' "$k" >>"$UFS"
                    grep -Eq "^${k}=0" "$UFS" && log ERR "$UFS: ${k}=0 still present"
                fi
                log OK "$UFS: ${k} -> 1"; record "ufw sysctl ${k}=1"
            fi
        done
    fi
    run_q ufw --force enable
    # ufw start (re)applies its own sysctl.conf — make /etc/sysctl.d win NOW,
    # not only at next boot
    is_apply && apply_sysctl
    is_apply && log OK "ufw: default-deny incoming, ssh allowed, enabled"
    record "ufw default-deny (ssh:$P)"
    [[ "$ROLE" == "container-host" ]] && risk HIGH "NOTE: Docker bypasses ufw via its own nftables chains — ufw will NOT filter container-published ports."
}

mod_auditd() {
    enabled AUDITD || { log INFO "disabled by profile"; return 0; }
    if [[ "$IS_CONTAINER" == "yes" ]]; then log WARN "container — audit subsystem host-owned; skipping"; return 0; fi
    apt_install auditd; apt_install audispd-plugins
    local RD=/etc/audit/rules.d RF
    [[ -d "$RD" ]] || { log WARN "$RD missing — auditd installed? skipping"; return 0; }
    RF="${RD}/99-zavetsec.rules"
    local E=1; [[ "$(tune AUDIT_IMMUTABLE 0)" == "1" ]] && E=2
    write_managed "$RF" <<EOF
## ZavetSec-Harden-Ubuntu auditd baseline (CIS/STIG-aligned)
-D
-b 8192
-f 1
--backlog_wait_time 60000
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules
-a always,exit -F arch=b32 -S init_module,delete_module,finit_module -k modules
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-e ${E}
EOF
    if is_apply; then
        run_q systemctl enable auditd
        command -v augenrules >/dev/null 2>&1 && { augenrules --load 2>"${STATE_DIR}/augenrules.err" && log OK "audit rules loaded" || log WARN "augenrules issues (see ${STATE_DIR}/augenrules.err)"; }
        systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || log WARN "restart auditd manually"
        [[ "$E" == "2" ]] && risk MED "audit immutable (-e 2): REBOOT needed before rules change again"
    else log DRY "would install auditd, write ${RF}, augenrules --load, restart auditd (-e ${E})"; fi
}

mod_filesystem() {
    enabled FILESYSTEM || { log INFO "disabled by profile"; return 0; }
    local NOEXEC; NOEXEC="$(tune TMP_NOEXEC 0)"
    if findmnt -rn /dev/shm >/dev/null 2>&1; then
        if grep -qE '[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
            log WARN "/dev/shm in fstab — ensure opts: nodev,nosuid,noexec"
        else
            backup /etc/fstab
            ensure_line /etc/fstab "tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0"
            if run_q mount -o remount,nodev,nosuid,noexec /dev/shm; then
                is_apply && log OK "/dev/shm remounted hardened"
            else log WARN "/dev/shm hardened at next boot"; fi
        fi
    fi
    local TO="nodev,nosuid"; [[ "$NOEXEC" == "1" ]] && { TO="$TO,noexec"; risk MED "noexec /tmp can break apt/snap installers — verify"; }
    findmnt -rn /tmp >/dev/null 2>&1 && log WARN "/tmp is separate — ensure opts: $TO" || log INFO "/tmp not separate — skipping"
    log INFO "blacklisting rare filesystems (squashfs kept for snap)"
    local fs; for fs in $(tune FS_BLACKLIST "cramfs freevxfs jffs2 hfs hfsplus udf"); do disable_module "$fs"; done
    if [[ "$(tune DISABLE_USB_STORAGE 0)" == "1" ]]; then risk MED "disabling usb-storage — USB drives won't mount"; disable_module usb-storage
    else log INFO "usb-storage kept (profile)"; fi
}

mod_services() {
    enabled SERVICES || { log INFO "disabled by profile"; return 0; }
    local svc; for svc in $(tune DISABLE_SERVICES "avahi-daemon rpcbind"); do disable_service "$svc"; done
    local LEG="telnetd telnet-server rsh-server rsh-redone-server talk talkd tftpd-hpa xinetd nis"
    local p; for p in $LEG; do apt_installed "$p" && { risk MED "legacy pkg present: $p — purging"; apt_remove "$p"; }; done
    local u; for u in telnet.socket rsh.socket rlogin.socket rexec.socket; do svc_exists "$u" && mask_service "$u"; done
    return 0
}

mod_extras() {
    enabled EXTRAS || { log INFO "disabled by profile"; return 0; }
    # lynis-recommended hygiene packages. fail2ban's Ubuntu package ships an
    # sshd jail enabled by default (jail.d/defaults-debian.conf) — safe out of
    # the box: it only bans repeated auth failures, never established sessions.
    local had_f2b=0; apt_installed fail2ban && had_f2b=1
    local p; for p in $(tune EXTRA_PKGS "fail2ban debsums apt-listchanges needrestart libpam-tmpdir acct sysstat"); do
        apt_install "$p"
    done
    if is_apply && apt_installed fail2ban; then
        if svc_active fail2ban; then log OK "fail2ban already active"
        else
            run_q systemctl enable --now fail2ban
            log OK "fail2ban enabled (default sshd jail active)"
            record "enable fail2ban"
        fi
        [[ "$had_f2b" == "0" ]] && add_rollback "systemctl disable --now fail2ban 2>/dev/null; env DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban >/dev/null 2>&1; echo \"fail2ban removed (was installed by this run)\""
    elif ! is_apply; then
        log DRY "would enable fail2ban after install"
    fi

    # DEB-0880: jail.conf is overwritten by package updates — persist our
    # settings in jail.local. NEVER clobber a user-managed jail.local.
    local JL=/etc/fail2ban/jail.local
    if [[ -f "$JL" ]] && ! grep -q "Managed by ZavetSec" "$JL" 2>/dev/null; then
        log INFO "fail2ban jail.local exists (user-managed) — leaving untouched"
    elif apt_installed fail2ban || ! is_apply; then
        write_managed "$JL" <<EOF
# Managed by ZavetSec-Harden-Ubuntu. Do not edit by hand.
[DEFAULT]
bantime  = $(tune F2B_BANTIME 1h)
findtime = $(tune F2B_FINDTIME 10m)
maxretry = $(tune F2B_MAXRETRY 5)

[sshd]
enabled = true
EOF
        is_apply && svc_active fail2ban && run_q systemctl reload fail2ban
    fi

    # ACCT-9622/9626: process accounting + sysstat collection
    if apt_installed sysstat; then
        set_kv /etc/default/sysstat ENABLED '"true"' "="
        is_apply && ! svc_enabled sysstat && { run_q systemctl enable --now sysstat; record "enable sysstat"; }
    fi
    apt_installed acct && is_apply && ! svc_enabled acct && run_q systemctl enable --now acct

    # Unattended security upgrades — patching beats most other controls.
    # Opt-out: ZS_TUNE_AUTO_UPGRADES=0
    if [[ "$(tune AUTO_UPGRADES 1)" == "1" ]]; then
        apt_install unattended-upgrades
        write_managed /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    else
        log INFO "auto-upgrades disabled by tune"
    fi
    return 0
}

mod_apparmor() {
    enabled APPARMOR || { log INFO "disabled by profile"; return 0; }
    [[ "$IS_CONTAINER" == "yes" ]] && { log INFO "container — AppArmor host-managed; skipping"; return 0; }
    apt_install apparmor; apt_install apparmor-utils
    if ! svc_enabled apparmor; then run_q systemctl enable --now apparmor; is_apply && log OK "AppArmor enabled"; record "enable apparmor"
    else log OK "AppArmor already enabled"; fi
    if command -v aa-status >/dev/null 2>&1; then
        local loaded comp; loaded="$(aa-status --profiled 2>/dev/null || echo '?')"; comp="$(aa-status --complaining 2>/dev/null || echo '?')"
        log INFO "AppArmor profiles loaded=${loaded}, complain=${comp}"
        [[ "$comp" =~ ^[1-9] ]] && risk MED "some profiles in complain mode — review before aa-enforce"
    fi
}

mod_misc() {
    enabled MISC || { log INFO "disabled by profile"; return 0; }
    write_managed /etc/security/limits.d/99-zavetsec-coredump.conf <<'EOF'
* hard core 0
root hard core 0
EOF
    local CD=/etc/systemd/coredump.conf
    set_kv "$CD" Storage none "="; set_kv "$CD" ProcessSizeMax 0 "="
    # Ubuntu apport (crash reporter) — off on servers by default
    if [[ "$(tune DISABLE_APPORT 1)" == "1" ]]; then
        svc_exists apport && disable_service apport
        [[ -f /etc/default/apport ]] && set_kv /etc/default/apport enabled 0 "="
        log OK "apport crash reporter disabled"
    else log INFO "apport kept (workstation)"; fi

    local BANNER='Authorized access only. All activity is monitored and logged.
Disconnect IMMEDIATELY if you are not an authorized user.'
    local f; for f in /etc/issue /etc/issue.net; do write_managed "$f" <<<"$BANNER"; done

    for a in /etc/cron.allow /etc/at.allow; do [[ -e "$a" ]] || { run touch "$a"; backup_created "$a"; }; run chmod 600 "$a" 2>/dev/null || true; done
    for d in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -e "$d" ]] && { backup "$d" 2>/dev/null; run chmod -R go-rwx "$d" 2>/dev/null || true; }; done
    for x in /etc/cron.deny /etc/at.deny; do [[ -e "$x" ]] && { backup "$x"; run rm -f "$x"; }; done
    risk MED "empty cron.allow/at.allow = allow-list: non-root users LOSE cron/at until explicitly added"
    log OK "cron/at restricted to allow-list"

    run_q systemctl mask ctrl-alt-del.target
    add_rollback "systemctl unmask ctrl-alt-del.target 2>/dev/null; echo \"C-A-D unmasked\""
    is_apply && log OK "ctrl-alt-del masked"

    # sudo hardening: use_pty defeats terminal-injection tricks, logfile gives
    # an audit trail independent of syslog. Validated with visudo; a rejected
    # file is removed immediately so sudo can never be bricked by this.
    if [[ "$(tune SUDO_HARDEN 1)" == "1" ]]; then
        if ! command -v visudo >/dev/null 2>&1; then
            log INFO "visudo not found (sudo not installed?) — skipping sudo hardening"
        else
        local SUDOF=/etc/sudoers.d/99-zavetsec-hardening
        write_managed "$SUDOF" <<'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
        if is_apply && [[ -f "$SUDOF" ]]; then
            chmod 440 "$SUDOF"
            if visudo -cq -f "$SUDOF" 2>/dev/null && visudo -cq 2>/dev/null; then
                log OK "sudoers hardening valid (use_pty, logfile)"
            else
                rm -f "$SUDOF"
                log ERR "visudo rejected ${SUDOF} — removed, sudo left untouched"
            fi
        fi
        fi
    fi

    # sudoers.d: Ubuntu ships 755; lynis (AUTH-9252) wants it tighter
    if [[ -d /etc/sudoers.d ]]; then
        local sm; sm="$(stat -c '%a' /etc/sudoers.d 2>/dev/null)"
        if [[ "$sm" != "750" ]]; then
            run chmod 750 /etc/sudoers.d
            add_rollback "chmod ${sm:-755} /etc/sudoers.d; echo \"/etc/sudoers.d mode restored to ${sm:-755}\""
            is_apply && log OK "/etc/sudoers.d -> 750 (was ${sm:-?})"
            record "chmod 750 /etc/sudoers.d"
        else log OK "/etc/sudoers.d already 750"; fi
    fi

    # Ubuntu shadow perms: 640 root:shadow (fixed)
    run chmod 644 /etc/passwd 2>/dev/null; run chmod 644 /etc/group 2>/dev/null
    run chmod 600 /etc/ssh/sshd_config 2>/dev/null
    for f in /etc/shadow /etc/gshadow; do
        [[ -e "$f" ]] || continue; run chown root:shadow "$f" 2>/dev/null; run chmod 640 "$f" 2>/dev/null
        log OK "perms 640 root:shadow on $f"
    done
}

# ============================================================================
#  AUDIT MODULES (mirror the enforcement baseline; read-only)
# ============================================================================
audit_sysctl-kernel() {
    enabled SYSCTL_KERNEL || { chk SKIP LOW sysctl "kernel baseline" - "disabled by profile"; return; }
    a_sysctl HIGH kernel.kptr_restrict 2
    a_sysctl MED  kernel.dmesg_restrict 1
    a_sysctl MED  kernel.kexec_load_disabled 1
    a_sysctl LOW  kernel.sysrq 0
    a_sysctl MED  kernel.perf_event_paranoid 3
    a_sysctl MED  kernel.randomize_va_space 2
    a_sysctl MED  kernel.yama.ptrace_scope "$(tune PTRACE_SCOPE 1)"
    [[ "$(tune DISABLE_BPF_UNPRIV 1)" == "1" ]] && a_sysctl MED kernel.unprivileged_bpf_disabled 1
    a_sysctl LOW net.core.bpf_jit_harden 2
    a_sysctl LOW dev.tty.ldisc_autoload 0
    a_sysctl LOW kernel.core_uses_pid 1
    a_sysctl HIGH fs.protected_hardlinks 1
    a_sysctl HIGH fs.protected_symlinks 1
    a_sysctl MED  fs.protected_fifos 2
    a_sysctl MED  fs.protected_regular 2
    if [[ "$(tune DISABLE_APPORT 1)" == "1" ]]; then
        a_sysctl HIGH fs.suid_dumpable 0
    else
        chk SKIP HIGH sysctl "fs.suid_dumpable" 0 "apport-managed" "apport enabled by profile sets 2 at boot"
    fi
}
audit_sysctl-network() {
    enabled SYSCTL_NETWORK || { chk SKIP LOW sysctl "network baseline" - "disabled by profile"; return; }
    a_sysctl MED net.ipv4.conf.all.rp_filter 1
    a_sysctl MED net.ipv4.conf.all.accept_redirects 0
    a_sysctl MED net.ipv4.conf.all.send_redirects 0
    a_sysctl MED net.ipv4.conf.all.accept_source_route 0
    a_sysctl LOW net.ipv4.conf.all.log_martians 1
    a_sysctl MED net.ipv4.tcp_syncookies 1
    a_sysctl LOW net.ipv4.tcp_rfc1337 1
    a_sysctl MED net.ipv6.conf.all.accept_redirects 0
    a_sysctl MED net.ipv4.ip_forward "$(tune NET_FORWARDING 0)"
    local bl=/etc/modprobe.d/zavetsec-harden.conf pr
    for pr in $(tune NET_PROTO_BLACKLIST "dccp sctp rds tipc"); do
        if [[ -f "$bl" ]] && grep -q "install ${pr} /bin/true" "$bl"; then
            chk PASS LOW sysctl "${pr} blacklisted" yes yes
        else chk WARN LOW sysctl "${pr} blacklisted" yes no; fi
    done
}
audit_ssh() {
    enabled SSH || { chk SKIP LOW ssh "ssh baseline" - "disabled by profile"; return; }
    a_sshd HIGH permitrootlogin "$(tune SSH_PERMIT_ROOT prohibit-password)"
    a_sshd MED  maxauthtries "$(tune SSH_MAXAUTH 3)"
    a_sshd LOW  maxsessions "$(tune SSH_MAXSESSIONS 4)"
    a_sshd LOW  tcpkeepalive "$(tune SSH_TCP_KEEPALIVE no)"
    a_sshd MED  x11forwarding "$(tune SSH_X11 no)"
    a_sshd LOW  allowtcpforwarding "$(tune SSH_ALLOW_TCP_FWD no)"
    a_sshd MED  permitemptypasswords no
    a_sshd MED  ignorerhosts yes
    a_sshd MED  hostbasedauthentication no
    a_sshd LOW  logingracetime "$(tune SSH_GRACE 30)"
    [[ "$(tune SSH_DISABLE_PASSWORD 0)" == "1" ]] && a_sshd HIGH passwordauthentication no
}
audit_auth() {
    enabled AUTH || { chk SKIP LOW auth "auth baseline" - "disabled by profile"; return; }
    a_kv MED /etc/login.defs PASS_MAX_DAYS "$(tune PASS_MAX_DAYS 365)"
    a_kv LOW /etc/login.defs PASS_MIN_DAYS "$(tune PASS_MIN_DAYS 1)"
    a_kv LOW /etc/login.defs UMASK "$(tune UMASK 027)"
    local EM=SHA512
    [[ "${UB_VER%%.*}" =~ ^[0-9]+$ && "${UB_VER%%.*}" -ge 22 ]] && EM=YESCRYPT
    a_kv MED /etc/login.defs ENCRYPT_METHOD "$EM"
    if [[ "$EM" == "YESCRYPT" ]]; then
        a_kv LOW /etc/login.defs YESCRYPT_COST_FACTOR "$(tune YESCRYPT_COST 8)"
    else
        a_kv LOW /etc/login.defs SHA_CRYPT_MIN_ROUNDS "$(tune SHA_ROUNDS 10000)"
    fi
    a_pkg_present LOW libpam-pwquality
    a_kv MED /etc/security/pwquality.conf minlen "$(tune PWQ_MINLEN 14)"
    a_kv LOW /etc/security/pwquality.conf minclass "$(tune PWQ_MINCLASS 4)"
    local HAVE_FAILLOCK=0
    { compgen -G "/usr/lib/*/security/pam_faillock.so" >/dev/null 2>&1 || compgen -G "/lib/*/security/pam_faillock.so" >/dev/null 2>&1; } && HAVE_FAILLOCK=1
    if [[ "$HAVE_FAILLOCK" == "1" ]]; then
        a_kv MED /etc/security/faillock.conf deny "$(tune FAILLOCK_DENY 5)"
        a_kv LOW /etc/security/faillock.conf unlock_time "$(tune FAILLOCK_UNLOCK 900)"
    else
        chk SKIP MED auth "faillock baseline" - "pam_faillock unavailable (PAM < 1.4)"
    fi
    if [[ "$(tune ENABLE_FAILLOCK_PAM 0)" == "1" && "$HAVE_FAILLOCK" == "1" ]]; then
        grep -q pam_faillock /etc/pam.d/common-auth 2>/dev/null \
            && chk PASS MED auth "faillock wired in PAM" present present \
            || chk FAIL MED auth "faillock wired in PAM" present absent
    fi
}
audit_firewall() {
    enabled FIREWALL || { chk SKIP LOW firewall "firewall baseline" - "disabled by profile"; return; }
    command -v ufw >/dev/null 2>&1 || { chk FAIL HIGH firewall "ufw installed" present absent; return; }
    [[ "$(id -u)" -eq 0 ]] || { chk SKIP HIGH firewall "ufw status" active "needs root"; return; }
    local st; st="$(ufw status verbose 2>/dev/null)"
    echo "$st" | grep -qi 'Status: active' && chk PASS HIGH firewall "ufw active" active active \
        || chk FAIL HIGH firewall "ufw active" active inactive
    echo "$st" | grep -qiE 'deny \(incoming\)' && chk PASS HIGH firewall "default deny incoming" deny deny \
        || chk FAIL HIGH firewall "default deny incoming" deny "not-deny"
}
audit_auditd() {
    enabled AUDITD || { chk SKIP LOW auditd "auditd baseline" - "disabled by profile"; return; }
    [[ "$IS_CONTAINER" == "yes" ]] && { chk SKIP LOW auditd "auditd baseline" - "container (host-owned)"; return; }
    a_pkg_present MED auditd
    a_svc_on MED auditd
    if [[ "$(id -u)" -eq 0 ]] && command -v auditctl >/dev/null 2>&1; then
        local nr; nr="$(auditctl -l 2>/dev/null | grep -vc 'No rules')"
        [[ "${nr:-0}" -gt 1 ]] && chk PASS MED auditd "rules loaded" ">0" "${nr} rules" \
            || chk FAIL MED auditd "rules loaded" ">0" "${nr:-0}"
    else chk SKIP LOW auditd "rules loaded" ">0" "needs root"; fi
    [[ -f /etc/audit/rules.d/99-zavetsec.rules ]] && chk PASS LOW auditd "baseline ruleset file" present present \
        || chk WARN LOW auditd "baseline ruleset file" present absent
}
audit_filesystem() {
    enabled FILESYSTEM || { chk SKIP LOW filesystem "fs baseline" - "disabled by profile"; return; }
    if findmnt -rn /dev/shm >/dev/null 2>&1; then
        local o opt; o="$(findmnt -rno OPTIONS /dev/shm 2>/dev/null)"
        for opt in nodev nosuid noexec; do
            echo "$o" | grep -qw "$opt" && chk PASS MED filesystem "/dev/shm ${opt}" set "$opt" \
                || chk FAIL MED filesystem "/dev/shm ${opt}" set missing
        done
    fi
    local bl=/etc/modprobe.d/zavetsec-harden.conf fs
    for fs in $(tune FS_BLACKLIST "cramfs freevxfs jffs2 hfs hfsplus udf"); do
        [[ -f "$bl" ]] && grep -q "install ${fs} /bin/true" "$bl" \
            && chk PASS LOW filesystem "${fs} blacklisted" yes yes \
            || chk WARN LOW filesystem "${fs} blacklisted" yes no
    done
    if [[ "$(tune DISABLE_USB_STORAGE 0)" == "1" ]]; then
        grep -q "install usb-storage /bin/true" "$bl" 2>/dev/null \
            && chk PASS MED filesystem "usb-storage disabled" yes yes \
            || chk FAIL MED filesystem "usb-storage disabled" yes no
    fi
}
audit_services() {
    enabled SERVICES || { chk SKIP LOW services "services baseline" - "disabled by profile"; return; }
    local svc; for svc in $(tune DISABLE_SERVICES "avahi-daemon rpcbind"); do a_svc_off MED "$svc"; done
    local p; for p in telnetd rsh-server talk nis; do a_pkg_absent MED "$p"; done
}
audit_extras() {
    enabled EXTRAS || { chk SKIP LOW extras "extras baseline" - "disabled by profile"; return; }
    local p; for p in $(tune EXTRA_PKGS "fail2ban debsums apt-listchanges needrestart libpam-tmpdir acct sysstat"); do
        a_pkg_present LOW "$p"
    done
    svc_exists fail2ban && a_svc_on MED fail2ban
    if apt_installed fail2ban; then
        [[ -f /etc/fail2ban/jail.local ]] \
            && chk PASS LOW extras "fail2ban jail.local" present present \
            || chk WARN LOW extras "fail2ban jail.local" present absent "settings won't survive pkg updates"
    fi
    apt_installed sysstat && a_kv LOW /etc/default/sysstat ENABLED '"true"'
    if [[ "$(tune AUTO_UPGRADES 1)" == "1" ]]; then
        a_pkg_present MED unattended-upgrades
        grep -qs 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades \
            && chk PASS MED extras "unattended security upgrades" enabled enabled \
            || chk FAIL MED extras "unattended security upgrades" enabled disabled
    fi
}
audit_apparmor() {
    enabled APPARMOR || { chk SKIP LOW apparmor "apparmor baseline" - "disabled by profile"; return; }
    [[ "$IS_CONTAINER" == "yes" ]] && { chk SKIP LOW apparmor "apparmor baseline" - "container (host-owned)"; return; }
    if command -v aa-status >/dev/null 2>&1; then
        if [[ "$(id -u)" -eq 0 ]]; then
            aa-status --enabled 2>/dev/null && chk PASS HIGH apparmor "AppArmor enabled" enabled enabled \
                || chk FAIL HIGH apparmor "AppArmor enabled" enabled disabled
            local comp; comp="$(aa-status --complaining 2>/dev/null || echo 0)"
            [[ "$comp" =~ ^[1-9] ]] && chk WARN MED apparmor "profiles in complain mode" 0 "$comp"
        else chk SKIP HIGH apparmor "AppArmor enabled" enabled "needs root"; fi
    else chk FAIL HIGH apparmor "AppArmor present" yes "aa-status missing"; fi
    a_svc_on MED apparmor
}
audit_misc() {
    enabled MISC || { chk SKIP LOW misc "misc baseline" - "disabled by profile"; return; }
    a_kv LOW /etc/systemd/coredump.conf Storage none
    [[ -f /etc/security/limits.d/99-zavetsec-coredump.conf ]] && chk PASS LOW misc "coredump limits file" present present \
        || chk WARN LOW misc "coredump limits file" present absent
    [[ "$(tune DISABLE_APPORT 1)" == "1" ]] && a_svc_off LOW apport
    local f; for f in /etc/issue /etc/issue.net; do
        [[ -s "$f" ]] && chk PASS LOW misc "banner ${f##*/}" present present \
            || chk WARN LOW misc "banner ${f##*/}" present absent
    done
    a_file_mode  MED  /etc/sudoers.d 750
    if [[ "$(tune SUDO_HARDEN 1)" == "1" ]]; then
        grep -qs "use_pty" /etc/sudoers.d/99-zavetsec-hardening \
            && chk PASS LOW misc "sudo hardening (use_pty)" present present \
            || chk FAIL LOW misc "sudo hardening (use_pty)" present absent
    fi
    a_file_mode  HIGH /etc/shadow 640
    a_file_owner MED  /etc/shadow root:shadow
    a_file_mode  MED  /etc/passwd 644
    a_file_mode  HIGH /etc/ssh/sshd_config 600
    if [[ "$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null)" == "masked" ]]; then
        chk PASS LOW misc "ctrl-alt-del masked" masked masked
    else chk WARN LOW misc "ctrl-alt-del masked" masked "not masked"; fi
}

# ============================================================================
#  REPORT GENERATORS
# ============================================================================
report_txt() {
    local out="$1" total score cats cat
    total=$((A_PASS+A_FAIL)); score=0; [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    {
      echo "==================================================================="
      echo " ZavetSec-Harden-Ubuntu :: Security Audit Report"
      echo "==================================================================="
      echo " Host:      $(hostname 2>/dev/null)"
      echo " Distro:    ${UB_PRETTY}"
      echo " Role:      ${ROLE}    Profile: ${PROFILE}"
      echo " Firewall:  ${FW}    MAC: ${AA}    Container: ${IS_CONTAINER}"
      echo " Privilege: $([[ $(id -u) -eq 0 ]] && echo 'root (full audit)' || echo 'non-root (partial)')"
      echo " Generated: $(_ts)   Tool: v${ZSVER}"
      echo "-------------------------------------------------------------------"
      printf " COMPLIANCE SCORE: %s%%    PASS:%s  FAIL:%s  WARN:%s  SKIP:%s\n" "$score" "$A_PASS" "$A_FAIL" "$A_WARN" "$A_SKIP"
      echo "==================================================================="
      cats="$(printf '%s\n' "${AUDIT_RESULTS[@]}" | cut -d'|' -f3 | awk 'NF&&!seen[$0]++')"
      while IFS= read -r cat; do
        [[ -z "$cat" ]] && continue
        echo; echo "### ${cat^^}"
        printf '%s\n' "${AUDIT_RESULTS[@]}" | awk -F'|' -v c="$cat" \
          '$3==c{n=($7!=""?"  ("$7")":"");printf "  [%-4s] %-5s %-40s exp=%-16s got=%s%s\n",$1,$2,$4,$5,$6,n}'
      done <<< "$cats"
      echo
      echo "-------------------------------------------------------------------"
      if [[ "$(id -u)" -ne 0 ]]; then
        echo " !! NON-ROOT AUDIT — score unreliable: sshd/ufw/AppArmor checks skipped."
        echo " !! Re-run with sudo for a complete assessment."
        echo
      fi
      if [[ $A_FAIL -gt 0 ]]; then
        echo " ${A_FAIL} FAILED CHECK(S) — remediation required:"
        printf '%s\n' "${AUDIT_RESULTS[@]}" | awk -F'|' '$1=="FAIL"{printf "   - [%s] %s (expected %s, got %s)\n",$2,$4,$5,$6}'
      else
        echo " No failed checks."
      fi
      echo
      echo " Remediate by running the same profile with --apply:"
      echo "   sudo ./zavetsec-harden-ubuntu.sh --apply --profile ${PROFILE}"
      echo " Note: baseline-conformance audit, not a certified assessment."
      echo "       Some checks require root (sshd -T, ufw, auditctl, perms)."
    } > "$out"
}

report_html() {
    local out="$1" total score scls host fails rows cats cat st sev c3 chk4 exp act note
    total=$((A_PASS+A_FAIL)); score=0; [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    if   [[ $score -ge 90 ]]; then scls="ok"
    elif [[ $score -ge 70 ]]; then scls="warn"; else scls="bad"; fi
    host="$(hostname 2>/dev/null || echo host)"

    rows=""
    cats="$(printf '%s\n' "${AUDIT_RESULTS[@]}" | cut -d'|' -f3 | awk 'NF&&!seen[$0]++')"
    while IFS= read -r cat; do
        [[ -z "$cat" ]] && continue
        rows+="<h2 class=\"cat\"># $(he "$cat")</h2><table class=\"matrix\"><thead><tr><th>Status</th><th>Sev</th><th>Check</th><th>Expected</th><th>Actual</th><th>Note</th></tr></thead><tbody>"
        while IFS='|' read -r st sev c3 chk4 exp act note; do
            [[ "$c3" == "$cat" ]] || continue
            rows+="<tr class=\"s-${st,,}\"><td><span class=\"badge b-${st,,}\">${st}</span></td><td><span class=\"sev v-${sev,,}\">${sev}</span></td><td class=\"chk\">$(he "$chk4")</td><td>$(he "$exp")</td><td>$(he "$act")</td><td class=\"note\">$(he "$note")</td></tr>"
        done < <(printf '%s\n' "${AUDIT_RESULTS[@]}")
        rows+="</tbody></table>"
    done <<< "$cats"

    cat > "$out" <<HTMLDOC
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZavetSec Audit — ${host} — ${RUN_TS}</title>
<style>
/* self-contained: no external font fetch (report must not phone home).
   JetBrains Mono / Rajdhani apply if installed locally, else system fallbacks. */
:root{--bg:#0a0d10;--panel:#0d1117;--panel2:#11161d;--accent:#00ff88;--accent2:#00cc6a;--red:#ff5f56;--yel:#ffd93d;--cyn:#4fd0e0;--dim:#5b6673;--txt:#c8d2dc;--line:#1c2530}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:'JetBrains Mono',ui-monospace,'Cascadia Mono',Consolas,Menlo,monospace;font-size:13px;line-height:1.5;position:relative;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:repeating-linear-gradient(0deg,rgba(0,255,136,.03) 0 1px,transparent 1px 3px)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse at 50% -10%,rgba(0,255,136,.10),transparent 60%)}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:32px 20px 60px}
h1,h2,.hd{font-family:'Rajdhani','Bahnschrift','Arial Narrow',sans-serif;letter-spacing:.04em}
header{border:1px solid var(--line);background:linear-gradient(180deg,var(--panel2),var(--panel));border-radius:10px;padding:22px 26px;box-shadow:0 0 40px rgba(0,255,136,.06)}
h1{margin:0 0 4px;font-size:30px;color:var(--accent);text-shadow:0 0 18px rgba(0,255,136,.35)}
h1 .v{color:var(--dim);font-size:14px}
.sub{color:var(--dim);font-size:12px}
.grid{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;margin-top:16px;font-size:12.5px}
.grid b{color:var(--cyn);font-weight:600}
.score{display:flex;align-items:center;gap:26px;margin:26px 0 8px;flex-wrap:wrap}
.donut{--v:${score};width:132px;height:132px;border-radius:50%;flex:0 0 auto;background:conic-gradient(var(--dcol) calc(var(--v)*1%),#182029 0);display:flex;align-items:center;justify-content:center;box-shadow:0 0 30px rgba(0,255,136,.12)}
.donut.ok{--dcol:var(--accent)}.donut.warn{--dcol:var(--yel)}.donut.bad{--dcol:var(--red)}
.donut .inner{width:104px;height:104px;border-radius:50%;background:var(--panel);display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut .num{font-family:'Rajdhani','Bahnschrift','Arial Narrow',sans-serif;font-size:40px;font-weight:700;color:#fff;line-height:1}
.donut .lbl{font-size:10px;color:var(--dim);letter-spacing:.12em}
.counts{display:flex;gap:10px;flex-wrap:wrap}
.pill{border:1px solid var(--line);border-radius:8px;padding:10px 16px;background:var(--panel2);min-width:78px;text-align:center}
.pill .n{font-family:'Rajdhani','Bahnschrift','Arial Narrow',sans-serif;font-size:26px;font-weight:700;display:block;line-height:1}
.pill .t{font-size:10px;color:var(--dim);letter-spacing:.1em}
.pill.pass .n{color:var(--accent)}.pill.fail .n{color:var(--red)}.pill.warn .n{color:var(--yel)}.pill.skip .n{color:var(--dim)}
.alert{border-left:3px solid var(--red);background:rgba(255,95,86,.07);padding:14px 18px;border-radius:6px;margin:22px 0}
.alert h3{margin:0 0 8px;font-family:'Rajdhani','Bahnschrift','Arial Narrow',sans-serif;color:var(--red);letter-spacing:.05em}
.alert ul{margin:0;padding-left:18px}.alert code{color:var(--yel)}
.toolbar{margin:26px 0 10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar input{background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:7px 12px;border-radius:6px;font-family:inherit;font-size:12px;flex:1;max-width:280px}
.toolbar button{background:var(--panel2);border:1px solid var(--line);color:var(--dim);padding:7px 12px;border-radius:6px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:.06em}
.toolbar button.on{color:var(--accent);border-color:var(--accent2)}
h2.cat{font-size:19px;color:var(--accent);margin:30px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}
table.matrix{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
.matrix th{text-align:left;color:var(--dim);font-weight:600;padding:6px 10px;border-bottom:1px solid var(--line);text-transform:uppercase;font-size:10.5px;letter-spacing:.08em}
.matrix td{padding:7px 10px;border-bottom:1px solid #131a22;vertical-align:top}
.matrix tr:hover td{background:rgba(0,255,136,.03)}
.chk{color:#e6edf3}.note{color:var(--dim);font-size:11px}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.06em}
.b-pass{background:rgba(0,255,136,.14);color:var(--accent)}
.b-fail{background:rgba(255,95,86,.16);color:var(--red)}
.b-warn{background:rgba(255,217,61,.14);color:var(--yel)}
.b-skip{background:#182029;color:var(--dim)}
.sev{font-size:10px;font-weight:700}
.v-high{color:var(--red)}.v-med{color:var(--yel)}.v-low{color:var(--dim)}
footer{margin-top:36px;color:var(--dim);font-size:11px;border-top:1px solid var(--line);padding-top:14px}
footer b{color:var(--cyn)}footer code{color:var(--accent)}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--accent);margin-right:7px;box-shadow:0 0 8px var(--accent);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
</style></head>
<body><div class="wrap">
<header>
<h1><span class="dot"></span>ZavetSec // Security Audit <span class="v">v${ZSVER}</span></h1>
<div class="sub">Ubuntu hardening compliance report · baseline profile conformance</div>
<div class="grid">
<b>Host</b><span>${host}</span>
<b>Distro</b><span>${UB_PRETTY}</span>
<b>Role / Profile</b><span>${ROLE} / ${PROFILE}</span>
<b>Firewall / MAC</b><span>${FW} / ${AA}</span>
<b>Privilege</b><span>$([[ $(id -u) -eq 0 ]] && echo 'root (full audit)' || echo 'non-root — some checks skipped')</span>
<b>Generated</b><span>${RUN_TS}</span>
</div>
</header>
<div class="score">
<div class="donut ${scls}"><div class="inner"><span class="num">${score}<span style="font-size:18px">%</span></span><span class="lbl">COMPLIANCE</span></div></div>
<div class="counts">
<div class="pill pass"><span class="n">${A_PASS}</span><span class="t">PASS</span></div>
<div class="pill fail"><span class="n">${A_FAIL}</span><span class="t">FAIL</span></div>
<div class="pill warn"><span class="n">${A_WARN}</span><span class="t">WARN</span></div>
<div class="pill skip"><span class="n">${A_SKIP}</span><span class="t">SKIP</span></div>
</div>
</div>
HTMLDOC

    if [[ "$(id -u)" -ne 0 ]]; then
        echo "<div class=\"alert\"><h3>&#9888; NON-ROOT AUDIT — SCORE IS UNRELIABLE</h3><ul><li>sshd, ufw and AppArmor checks were <b>skipped</b> (need root)</li><li>re-run with <code>sudo</code> for a complete assessment</li></ul></div>" >> "$out"
    fi
    if [[ $A_FAIL -gt 0 ]]; then
        fails="$(printf '%s\n' "${AUDIT_RESULTS[@]}" | awk -F'|' '$1=="FAIL"{printf "<li><b>[%s]</b> %s — expected <code>%s</code>, got <code>%s</code></li>\n",$2,$4,$5,$6}')"
        { echo "<div class=\"alert\"><h3>&#9888; ${A_FAIL} FAILED CHECK(S) — REMEDIATION REQUIRED</h3><ul>"; echo "$fails"; echo "</ul></div>"; } >> "$out"
    fi

    cat >> "$out" <<'HTMLMID'
<div class="toolbar">
<input id="q" placeholder="filter checks…" oninput="flt()">
<button id="bf" class="on" onclick="tg('fail')">FAIL</button>
<button id="bw" class="on" onclick="tg('warn')">WARN</button>
<button id="bp" class="on" onclick="tg('pass')">PASS</button>
<button id="bs" class="on" onclick="tg('skip')">SKIP</button>
</div>
HTMLMID

    printf '%s\n' "$rows" >> "$out"

    cat >> "$out" <<HTMLTAIL
<footer>
Generated by <b>ZavetSec-Harden-Ubuntu v${ZSVER}</b> · $(_ts). Baseline-conformance audit, not a certified assessment — pair with <b>lynis</b> / <b>oscap</b> for formal compliance. FAIL items map directly to what the tool enforces with <code>--apply --profile ${PROFILE}</code>.
</footer>
</div>
<script>
var show={fail:1,warn:1,pass:1,skip:1};
function tg(k){show[k]=!show[k];var b={fail:'bf',warn:'bw',pass:'bp',skip:'bs'}[k];document.getElementById(b).classList.toggle('on',show[k]);flt();}
function flt(){var q=document.getElementById('q').value.toLowerCase();
 document.querySelectorAll('table.matrix tbody tr').forEach(function(r){
  var cls='';['fail','warn','pass','skip'].forEach(function(k){if(r.classList.contains('s-'+k))cls=k;});
  r.style.display=(show[cls]&&r.innerText.toLowerCase().indexOf(q)>=0)?'':'none';});}
</script>
</body></html>
HTMLTAIL
}

# ============================================================================
#  MAIN
# ============================================================================
banner() {
cat <<EOF
${C_GRN}${C_BLD}
  ╔══════════════════════════════════════════════════════════╗
  ║   ZavetSec-Harden-Ubuntu  v${ZSVER}                       ║
  ║   single-file baseline · Ubuntu 20.04/22.04/24.04         ║
  ║   dry-run by default · backup + rollback                  ║
  ╚══════════════════════════════════════════════════════════╝${C_RST}
EOF
}
usage() { awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; }
list_modules() { printf '%sModules (run order):%s\n' "$C_BLD" "$C_RST"; local m; for m in "${MODULES[@]}"; do printf '  %s\n' "$m"; done; }
in_csv() { [[ ",$2," == *",$1,"* ]]; }

while [[ $# -gt 0 ]]; do case "$1" in
    --apply) MODE="apply";; --dry-run) MODE="dryrun";; --check|--audit) MODE="audit";;
    --report-dir) REPORT_DIR="$2"; shift;; --report-dir=*) REPORT_DIR="${1#*=}";;
    --format) FMT="$2"; shift;; --format=*) FMT="${1#*=}";;
    --profile) PROFILE="$2"; shift;; --profile=*) PROFILE="${1#*=}";;
    --role) ROLE_OVERRIDE="$2"; shift;; --role=*) ROLE_OVERRIDE="${1#*=}";;
    --only) ONLY="$2"; shift;; --only=*) ONLY="${1#*=}";;
    --skip) SKIP="$2"; shift;; --skip=*) SKIP="${1#*=}";;
    --state-dir) STATE_DIR="$2"; shift;; --state-dir=*) STATE_DIR="${1#*=}";;
    --detect-only) DETECT_ONLY=1;; --force) FORCE=1;;
    --list) list_modules; exit 0;; --no-color) export NO_COLOR=1;;
    -h|--help) banner; usage; exit 0;; --version) echo "$ZSVER"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
esac; shift; done

if ! mkdir -p "${STATE_DIR}/backup" 2>/dev/null; then
    # non-root audit/dry-run: /var/log not writable — fall back quietly
    STATE_DIR="${TMPDIR:-/tmp}/zavetsec-harden/${RUN_TS}"
    mkdir -p "${STATE_DIR}/backup" 2>/dev/null || { echo "ERR: cannot create state dir" >&2; exit 1; }
    STATE_DIR_FALLBACK=1
fi
BACKUP_DIR="${STATE_DIR}/backup"; LOG_FILE="${STATE_DIR}/harden.log"
CHANGES="${STATE_DIR}/changes.log"; ROLLBACK="${STATE_DIR}/rollback.sh"
printf '#!/usr/bin/env bash\n# Auto-generated rollback for run %s\nset -u\n' "$RUN_TS" > "$ROLLBACK"

banner
[[ "${STATE_DIR_FALLBACK:-0}" == "1" ]] && log INFO "state dir: ${STATE_DIR} (no write access to /var/log)"
[[ "$MODE" == "apply" && "$(id -u)" -ne 0 ]] && die "apply requires root. Re-run with sudo."
[[ "$(id -u)" -ne 0 ]] && log WARN "not root — detection works but some probes are limited"

detect
if [[ "$IS_UBUNTU" == "no" ]]; then
    log WARN "this host is not Ubuntu (id=${UB_ID})."
    [[ "$FORCE" == "1" ]] || die "refusing to run on non-Ubuntu. Use --force to override (not recommended)."
elif [[ "$IS_UBUNTU" == "derivative" ]]; then
    log INFO "Ubuntu derivative (${UB_ID}) — proceeding; verify dry-run carefully."
fi
print_detect
[[ "$DETECT_ONLY" == "1" ]] && { log INFO "detect-only: exiting."; exit 0; }

[[ -z "$PROFILE" ]] && PROFILE="$ROLE"
load_profile
log INFO "profile: ${C_YEL}${PROFILE}${C_RST}"
echo

if [[ "$MODE" == "audit" ]]; then
    log INFO "AUDIT mode — read-only, no changes will be made"
    [[ "$(id -u)" -ne 0 ]] && log WARN "not root — checks needing sshd -T / ufw / auditctl / file perms will be SKIPPED"
    echo
    a_sshd_init
    for m in "${MODULES[@]}"; do
        [[ -n "$ONLY" ]] && ! in_csv "$m" "$ONLY" && continue
        [[ -n "$SKIP" ]] &&   in_csv "$m" "$SKIP" && continue
        CURMOD="$m"
        printf '%s──[ %s ]%s\n' "$C_DIM" "$m" "$C_RST"
        "audit_${m}"
    done
    CURMOD="core"; echo

    total=$((A_PASS+A_FAIL)); score=0; [[ $total -gt 0 ]] && score=$(( A_PASS*100/total ))
    scol="$C_GRN"; [[ $score -lt 90 ]] && scol="$C_YEL"; [[ $score -lt 70 ]] && scol="$C_RED"
    printf '%s\n' "${C_BLD}${C_GRN}  AUDIT SUMMARY${C_RST}"
    printf '  Compliance score: %s%s%%%s  (%sPASS:%s %sFAIL:%s %sWARN:%s %sSKIP:%s)\n' \
        "$scol" "$score" "$C_RST" "$C_GRN" "$A_PASS" "$C_RED" "$A_FAIL" "$C_YEL" "$A_WARN" "$C_DIM" "$A_SKIP$C_RST"
    echo

    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="$STATE_DIR"
    host="$(hostname 2>/dev/null || echo host)"
    base="${REPORT_DIR%/}/zavetsec-audit-${host}-${RUN_TS}"
    case "$FMT" in
        txt)  report_txt "${base}.txt";  log OK "TXT report:  ${base}.txt";;
        html) report_html "${base}.html"; log OK "HTML report: ${base}.html";;
        both|*) report_txt "${base}.txt"; report_html "${base}.html"
                log OK "TXT report:  ${base}.txt"
                log OK "HTML report: ${base}.html";;
    esac
    [[ $A_FAIL -gt 0 ]] && log WARN "${A_FAIL} failed check(s) — remediate with: sudo $0 --apply --profile ${PROFILE}"
    echo
    exit 0
fi

if [[ "$MODE" == "apply" ]]; then
    log WARN "APPLY mode. Backups: ${BACKUP_DIR}"
    if [[ -t 0 ]]; then read -r -p "  Proceed? keep a second root session open [type YES]: " a; [[ "$a" == "YES" ]] || die "aborted."; fi
    echo
fi

rc=0
for m in "${MODULES[@]}"; do
    [[ -n "$ONLY" ]] && ! in_csv "$m" "$ONLY" && continue
    [[ -n "$SKIP" ]] &&   in_csv "$m" "$SKIP" && { log INFO "skip $m"; continue; }
    CURMOD="$m"
    printf '%s──[ %s ]%s\n' "$C_DIM" "$m" "$C_RST"
    "mod_${m}" || { log WARN "module $m rc=$?"; rc=$((rc+1)); }
    echo
done
CURMOD="core"
chmod +x "$ROLLBACK" 2>/dev/null || true

printf '%s\n' "${C_BLD}${C_GRN}  SUMMARY${C_RST}"
n=0; [[ -f "$CHANGES" ]] && n="$(wc -l <"$CHANGES" | tr -d ' ')"
printf '  %s change action(s) recorded.\n' "$n"
if [[ "$MODE" == "apply" ]]; then
    printf '  Backups:  %s\n  Rollback: %s\n  Log:      %s\n' "$BACKUP_DIR" "$ROLLBACK" "$LOG_FILE"
    printf '\n  %sRevert:%s sudo bash %s\n' "$C_YEL" "$C_RST" "$ROLLBACK"
else
    printf '  %sDry-run — nothing modified.%s Re-run with --apply to enforce.\n' "$C_DIM" "$C_RST"
fi
[[ $rc -gt 0 ]] && log WARN "$rc module(s) reported non-zero — review log."
echo
exit 0
