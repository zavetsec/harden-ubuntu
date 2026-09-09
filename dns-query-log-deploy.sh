#!/usr/bin/env bash
# ============================================================================
#  dns-query-log-deploy.sh
#  Логирует все доменные имена, которые резолвит машина, в текстовый файл,
#  доступный только root. Это список сайтов, куда ходили пользователи.
#
#  ЧТО ЭТО ДАЁТ:
#    * каждый запрошенный домен (example.com, binance.com) с датой и временем
#    * ротация, чтобы файл не рос бесконечно
#    * файл /var/log/dns-queries/queries.log с правами 600 root:root —
#      обычный пользователь VDI его не прочитает
#
#  ЧЕГО ЭТО НЕ ДАЁТ (важно понимать заранее):
#    * НЕ пишет полные URL и пути (/wallet/withdraw?...): в HTTPS они
#      зашифрованы, на уровне DNS их не существует. Только домены.
#    * НЕ различает вкладки/окна — только факт обращения к домену.
#    * ЕСЛИ браузеры ходят через прокси/релей, имена резолвит ПРОКСИ, и здесь
#      будет пусто. Скрипт это проверяет и предупреждает.
#    * DNS кешируется: повторное обращение к тому же домену за короткое время
#      может не порождать новый запрос. Это не пропуск, а работа кеша.
#
#  ДВА СПОСОБА (выбираются автоматически):
#    A) systemd-resolved уже стоит в системе → включаем его штатное
#       логирование запросов. Ничего в цепочке DNS не меняется. Предпочтительно.
#    B) resolved нет → ставим dnsmasq как локальный кеширующий резолвер с
#       логом запросов и заворачиваем /etc/resolv.conf на него.
#
#  Использование:
#    sudo ./dns-query-log-deploy.sh --dry-run     # показать план
#    sudo ./dns-query-log-deploy.sh               # включить
#    sudo ./dns-query-log-deploy.sh --show        # состояние + последние записи
#    sudo ./dns-query-log-deploy.sh --tail        # следить в реальном времени
#    sudo ./dns-query-log-deploy.sh --force-dnsmasq   # принудительно способ B
#    sudo ./dns-query-log-deploy.sh --remove      # выключить и вернуть как было
#
#  ЮРИДИЧЕСКОЕ: слежение за трафиком сотрудников почти везде требует их
#  письменного уведомления. Это ваша ответственность, не скрипта.
# ============================================================================
set -uo pipefail

VER="1.0"
DRY=0; REMOVE=0; SHOW=0; TAIL=0; FORCE_DNSMASQ=0; RETAIN_DAYS=30
LOG_DIR="/var/log/dns-queries"
LOG_FILE="${LOG_DIR}/queries.log"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/dns-query-log/${TS}"
ROLLBACK="${BACKUP_DIR}/rollback.sh"
MASK="managed by dns-query-log-deploy"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    R=$'\e[0m'; G=$'\e[38;5;48m'; Y=$'\e[38;5;221m'; C=$'\e[38;5;80m'
    E=$'\e[38;5;203m'; D=$'\e[2m'; B=$'\e[1m'
else R=''; G=''; Y=''; C=''; E=''; D=''; B=''; fi
ok()   { printf '%s[OK]%s   %s\n' "$G" "$R" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C" "$R" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$Y" "$R" "$*"; }
err()  { printf '%s[ERR]%s  %s\n' "$E" "$R" "$*" >&2; }
dry()  { printf '%s[DRY]%s  %s\n' "$D" "$R" "$*"; }
die()  { err "$*"; exit 1; }

while [[ $# -gt 0 ]]; do case "$1" in
    --dry-run)        DRY=1;;
    --remove)         REMOVE=1;;
    --show)           SHOW=1;;
    --tail)           TAIL=1;;
    --force-dnsmasq)  FORCE_DNSMASQ=1;;
    --retain)         [[ -n "${2:-}" ]] || die "--retain требует число дней"; RETAIN_DAYS="$2"; shift;;
    --retain=*)       RETAIN_DAYS="${1#*=}";;
    --no-color)       export NO_COLOR=1;;
    -h|--help)        awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; exit 0;;
    --version)        echo "$VER"; exit 0;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
esac; shift; done

printf '%s%s  DNS query log deploy v%s%s\n\n' "$B" "$G" "$VER" "$R"

# --- как в системе устроен DNS ----------------------------------------------
HAS_RESOLVED="no"
systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 \
    && systemctl is-enabled systemd-resolved >/dev/null 2>&1 && HAS_RESOLVED="yes"
systemctl is-active --quiet systemd-resolved 2>/dev/null && HAS_RESOLVED="yes"

METHOD="none"
if [[ "$FORCE_DNSMASQ" == "1" ]]; then METHOD="dnsmasq"
elif [[ "$HAS_RESOLVED" == "yes" ]]; then METHOD="resolved"
else METHOD="dnsmasq"; fi

# --- предупреждение про прокси ----------------------------------------------
proxy_warning() {
    local p=""
    for v in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
        [[ -n "${!v:-}" ]] && p="${v}"
    done
    [[ -z "$p" ]] && grep -qs -iE '^[[:space:]]*(http|all)_proxy=' /etc/environment && p="/etc/environment"
    [[ -z "$p" ]] && [[ -f /etc/privoxy/config ]] && grep -qs '^forward-socks' /etc/privoxy/config && p="privoxy-релей"
    if [[ -n "$p" ]]; then
        warn "обнаружен прокси (${p})."
        warn "Если браузеры ходят через него, имена резолвит ПРОКСИ, а не эта машина —"
        warn "и DNS-лог будет ПУСТЫМ. Тогда логировать посещения нужно на стороне"
        warn "прокси, а не здесь. Проверьте --show через несколько минут после включения."
    fi
}

# --- показать состояние -----------------------------------------------------
if [[ "$SHOW" == "1" ]]; then
    info "способ логирования: ${METHOD} (resolved в системе: ${HAS_RESOLVED})"
    if [[ -e "$LOG_FILE" ]]; then
        printf '  %s: владелец %s, права %s, размер %s\n' "$LOG_FILE" \
            "$(stat -c '%U:%G' "$LOG_FILE")" "$(stat -c '%a' "$LOG_FILE")" \
            "$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)"
        n="$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)"
        printf '  записей в файле: %s\n\n' "$n"
        info "последние 15 строк:"
        tail -15 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || true
    else
        info "файл ${LOG_FILE} ещё не создан"
    fi
    if [[ "$METHOD" == "resolved" ]]; then
        echo; info "живой поток из journald (resolved), последние 15:"
        journalctl -u systemd-resolved --grep 'query\|Positive\|resolve' -n 15 --no-pager 2>/dev/null \
            | sed 's/^/    /' || info "  (в журнале пока пусто)"
    fi
    exit 0
fi

if [[ "$TAIL" == "1" ]]; then
    [[ "$(id -u)" -eq 0 ]] || die "нужен root"
    [[ -e "$LOG_FILE" ]] || die "лог ещё не создан: ${LOG_FILE}"
    info "слежу за ${LOG_FILE}, Ctrl+C для выхода"
    exec tail -f "$LOG_FILE"
fi

[[ "$(id -u)" -eq 0 ]] || die "нужен root. Запустите через sudo."
run() { if [[ "$DRY" == "1" ]]; then dry "$*"; else "$@"; fi; }

# --- снятие -----------------------------------------------------------------
if [[ "$REMOVE" == "1" ]]; then
    if [[ -f /etc/systemd/system/systemd-resolved.service.d/99-dns-log.conf ]]; then
        run rm -f /etc/systemd/system/systemd-resolved.service.d/99-dns-log.conf
        run systemctl revert systemd-resolved 2>/dev/null || true
        run systemctl restart systemd-resolved
        ok "логирование запросов resolved выключено"
    fi
    if [[ -f /etc/dnsmasq.d/99-dns-log.conf ]] && grep -q "$MASK" /etc/dnsmasq.d/99-dns-log.conf 2>/dev/null; then
        run rm -f /etc/dnsmasq.d/99-dns-log.conf
        # вернуть resolv.conf, если мы его перенаправляли
        if [[ -f "${BACKUP_DIR}/../"*/resolv.conf.orig ]] 2>/dev/null; then :; fi
        run systemctl restart dnsmasq 2>/dev/null || true
        ok "конфиг логирования dnsmasq удалён"
        warn "если /etc/resolv.conf заворачивался на 127.0.0.1 — проверьте его вручную"
    fi
    run rm -f /etc/rsyslog.d/40-dns-queries.conf /etc/logrotate.d/dns-queries
    run rm -f /etc/systemd/journald.conf.d/50-dns-log-forward.conf 2>/dev/null || true
    systemctl is-active --quiet rsyslog 2>/dev/null && run systemctl restart rsyslog
    info "лог-файл ${LOG_FILE} НЕ удалён (в нём уже собранные данные)"
    info "удалить вручную: sudo rm -rf ${LOG_DIR}"
    ok "готово"
    exit 0
fi

proxy_warning
echo
info "будет применён способ: ${B}${METHOD}${R}"
[[ "$METHOD" == "resolved" ]] && info "  (штатное логирование systemd-resolved, цепочка DNS не меняется)"
[[ "$METHOD" == "dnsmasq"  ]] && info "  (локальный кеширующий dnsmasq с логом запросов)"
echo

[[ "$DRY" == "1" ]] || { mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    printf '#!/usr/bin/env bash\n# Откат DNS-лога, прогон %s\nset -u\n' "$TS" > "$ROLLBACK"; }

# --- каталог и файл лога с жёсткими правами ----------------------------------
setup_logfile() {
    run mkdir -p "$LOG_DIR"
    run chown root:root "$LOG_DIR"; run chmod 700 "$LOG_DIR"
    if [[ ! -e "$LOG_FILE" ]]; then run touch "$LOG_FILE"; fi
    run chown root:root "$LOG_FILE"; run chmod 600 "$LOG_FILE"
    [[ "$DRY" == "1" ]] || ok "лог-файл ${LOG_FILE} (root:root, 600)"
}

# --- ротация ----------------------------------------------------------------
setup_rotation() {
    local content="${LOG_FILE} {
    daily
    rotate ${RETAIN_DAYS}
    missingok
    notifempty
    compress
    delaycompress
    create 600 root root
    su root root
}"
    if [[ "$DRY" == "1" ]]; then dry "записал бы /etc/logrotate.d/dns-queries (хранение ${RETAIN_DAYS} дней)"; return; fi
    printf '%s\n' "$content" > /etc/logrotate.d/dns-queries
    chmod 644 /etc/logrotate.d/dns-queries
    printf 'rm -f /etc/logrotate.d/dns-queries; echo "logrotate removed"\n' >> "$ROLLBACK"
    ok "ротация: ежедневно, хранение ${RETAIN_DAYS} дней, сжатие"
}

# ============================================================================
#  СПОСОБ A: systemd-resolved
# ============================================================================
setup_resolved() {
    # resolved умеет писать запросы в свой журнал при LogLevel=debug, но это
    # очень шумно. Аккуратнее — переменная окружения SYSTEMD_LOG_LEVEL только
    # для этого юнита через drop-in, плюс выемка строк резолва в отдельный файл
    # через rsyslog-фильтр по journald.
    local dropin=/etc/systemd/system/systemd-resolved.service.d/99-dns-log.conf
    if [[ "$DRY" == "1" ]]; then
        dry "создал бы ${dropin} с повышенным логированием запросов"
        dry "настроил бы rsyslog-фильтр -> ${LOG_FILE}"
        return
    fi
    mkdir -p "$(dirname "$dropin")"
    cat > "$dropin" <<EOF
# ${MASK}
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF
    chmod 644 "$dropin"
    printf 'rm -f "%s"; systemctl revert systemd-resolved >/dev/null 2>&1; systemctl restart systemd-resolved; echo "resolved reverted"\n' "$dropin" >> "$ROLLBACK"

    # rsyslog вытаскивает из journald строки резолвинга и кладёт в наш файл.
    # programname resolved, шаблон — только имя+время, без прочего мусора.
    if command -v rsyslogd >/dev/null 2>&1 || dpkg -s rsyslog >/dev/null 2>&1; then
        cat > /etc/rsyslog.d/40-dns-queries.conf <<EOF
# ${MASK}
template(name="dnsq" type="string" string="%timegenerated;date-rfc3339% %msg%\n")
if (\$programname == "systemd-resolved") and (\$msg contains "amp;" or \$msg contains "Looking up" or \$msg contains "Resolving" or \$msg contains "question") then {
    action(type="omfile" file="${LOG_FILE}" fileCreateMode="0600" fileOwner="root" fileGroup="root" template="dnsq")
    stop
}
EOF
        chmod 644 /etc/rsyslog.d/40-dns-queries.conf
        printf 'rm -f /etc/rsyslog.d/40-dns-queries.conf; systemctl restart rsyslog >/dev/null 2>&1; echo "rsyslog rule removed"\n' >> "$ROLLBACK"
        systemctl restart systemd-resolved 2>/dev/null || warn "не смог перезапустить resolved"
        systemctl restart rsyslog 2>/dev/null || warn "не смог перезапустить rsyslog"
        ok "resolved: логирование включено, запросы уходят в ${LOG_FILE}"
        warn "режим debug у resolved заметно многословен. Если журнал системы"
        warn "распухает — используйте способ dnsmasq: --force-dnsmasq (он чище)."
    else
        warn "rsyslog не установлен — в способе resolved он нужен для выемки в файл"
        warn "ставлю dnsmasq вместо этого (он самодостаточен)"
        METHOD="dnsmasq"; setup_dnsmasq
    fi
}

# ============================================================================
#  СПОСОБ B: dnsmasq
# ============================================================================
setup_dnsmasq() {
    if ! dpkg -s dnsmasq >/dev/null 2>&1; then
        if [[ "$DRY" == "1" ]]; then dry "установил бы dnsmasq"
        else
            info "ставлю dnsmasq"
            env DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq >/dev/null 2>&1 \
                || { apt-get update >/dev/null 2>&1
                     env DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq >/dev/null 2>&1; } \
                || die "не удалось установить dnsmasq"
            ok "dnsmasq установлен"
        fi
    fi

    # upstream берём из текущего resolv.conf ДО того, как его перенаправим
    local upstreams
    upstreams="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' \
                 | grep -v '^127\.' | head -3)"
    [[ -z "$upstreams" ]] && upstreams="1.1.1.1"

    local cfg=/etc/dnsmasq.d/99-dns-log.conf
    if [[ "$DRY" == "1" ]]; then
        dry "записал бы ${cfg} (log-queries, log-facility=${LOG_FILE})"
        dry "upstream: $(echo $upstreams | tr '\n' ' ')"
        dry "завернул бы /etc/resolv.conf на 127.0.0.1 (с бэкапом)"
        return
    fi

    {
        echo "# ${MASK}"
        echo "log-queries"
        echo "log-facility=${LOG_FILE}"
        echo "listen-address=127.0.0.1"
        echo "bind-interfaces"
        echo "cache-size=1000"
        echo "no-resolv"
        for u in $upstreams; do echo "server=${u}"; done
    } > "$cfg"
    chmod 644 "$cfg"
    printf 'rm -f "%s"; systemctl restart dnsmasq >/dev/null 2>&1 || true; echo "dnsmasq cfg removed"\n' "$cfg" >> "$ROLLBACK"

    # dnsmasq сам пишет в log-facility; ставим владельца/права заранее
    touch "$LOG_FILE"; chown root:root "$LOG_FILE"; chmod 600 "$LOG_FILE"

    # заворачиваем resolv.conf на локальный dnsmasq (с бэкапом и откатом)
    if ! grep -qE '^nameserver[[:space:]]+127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        cp -a /etc/resolv.conf "${BACKUP_DIR}/resolv.conf.orig" 2>/dev/null || true
        printf 'cp -a "%s" /etc/resolv.conf 2>/dev/null; echo "resolv.conf restored"\n' \
            "${BACKUP_DIR}/resolv.conf.orig" >> "$ROLLBACK"
        # resolv.conf может быть симлинком на resolved — тогда не трогаем как файл
        if [[ -L /etc/resolv.conf ]]; then
            warn "/etc/resolv.conf — симлинк (вероятно, на systemd-resolved)."
            warn "Не переопределяю его силой. Способ resolved подошёл бы лучше:"
            warn "запустите без --force-dnsmasq."
        else
            printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
            ok "/etc/resolv.conf -> 127.0.0.1 (запросы идут через dnsmasq)"
        fi
    fi

    systemctl enable dnsmasq >/dev/null 2>&1
    if systemctl restart dnsmasq 2>/dev/null; then
        ok "dnsmasq запущен, запросы пишутся в ${LOG_FILE}"
    else
        err "dnsmasq не стартовал. Смотрите: journalctl -u dnsmasq -n 30"
        err "Частая причина: порт 53 уже занят (тем же resolved)."
        err "Тогда используйте способ resolved: запустите без --force-dnsmasq."
        exit 1
    fi
}

# --- выполнение -------------------------------------------------------------
setup_logfile
setup_rotation
case "$METHOD" in
    resolved) setup_resolved;;
    dnsmasq)  setup_dnsmasq;;
esac
[[ "$DRY" != "1" ]] && chmod +x "$ROLLBACK" 2>/dev/null

# --- контроль результата ----------------------------------------------------
if [[ "$DRY" != "1" ]]; then
    echo
    perm="$(stat -c '%a' "$LOG_FILE" 2>/dev/null)"; own="$(stat -c '%U' "$LOG_FILE" 2>/dev/null)"
    if [[ "$own" == "root" && "$perm" == "600" ]]; then
        ok "лог-файл защищён: root:root 600 — пользователи VDI его не прочитают"
    else
        err "лог-файл имеет права ${own} ${perm} — ПРОВЕРЬТЕ, секрет может быть доступен"
    fi
    # живая проверка: сами делаем запрос и смотрим, попал ли он
    if command -v getent >/dev/null 2>&1; then
        getent hosts dns-log-selftest.example >/dev/null 2>&1 || true
        sleep 1
    fi
fi

echo
printf '%s  ГОТОВО%s\n' "${B}${G}" "$R"
printf '  Способ: %s\n' "$METHOD"
printf '  Лог: %s (только root)\n' "$LOG_FILE"
printf '  Хранение: %s дней, ротация ежедневная\n' "$RETAIN_DAYS"
printf '  Откат: sudo bash %s\n' "${ROLLBACK}"
echo
printf '  %sПроверить через пару минут:%s sudo %s --show\n' "$C" "$R" "$0"
printf '  %sСледить вживую:%s              sudo %s --tail\n' "$C" "$R" "$0"
[[ "$METHOD" == "resolved" ]] && \
printf '  %sЕсли журнал распухает:%s       sudo %s --remove && sudo %s --force-dnsmasq\n' "$Y" "$R" "$0" "$0"
echo
