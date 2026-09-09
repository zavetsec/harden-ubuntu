#!/usr/bin/env bash
# ============================================================================
#  dns-query-log-deploy.sh  v2.0
#  Логирует все доменные имена, которые резолвит машина, в текстовый файл,
#  доступный только root. Это список сайтов, куда ходили пользователи.
#
#  ЧТО ИЗМЕНИЛОСЬ В v2.0 (после боя на реальном VDI):
#    * убран хрупкий способ через systemd-resolved + rsyslog-фильтр: формат
#      отладочных строк resolved зависит от версии, и выемка в файл срывалась.
#    * теперь ЕДИНСТВЕННЫЙ способ — dnsmasq, который пишет запросы в файл сам.
#    * скрипт САМ снимает у systemd-resolved DNS-заглушку (DNSStubListener=no),
#      освобождает порт 53 и сажает на него dnsmasq. Больше не нужно чинить
#      resolv.conf руками — resolved продолжает управлять symlink'ом, а
#      реальным резолвером на :53 становится dnsmasq.
#    * перезапуск в правильном порядке: сперва освобождаем 53, потом dnsmasq.
#    * в конце — живая самопроверка: скрипт сам делает запрос и убеждается,
#      что он попал в файл. Если нет — говорит об этом сразу, а не через 15 мин.
#
#  ЧЕГО ЭТО НЕ ДАЁТ (важно понимать заранее):
#    * НЕ пишет полные URL и пути (/wallet/withdraw?...): в HTTPS они
#      зашифрованы, на уровне DNS их нет. Только домены.
#    * инициатор в логе — 127.0.0.1, а не имя оператора: на одном VDI с общим
#      сетевым стеком запросы к резолверу неотличимы по пользователю. Различать
#      операторов на уровне DNS нельзя в принципе.
#    * ЕСЛИ браузеры ходят через прокси/релей, имена резолвит ПРОКСИ — здесь
#      будет пусто. Скрипт это проверяет и предупреждает.
#    * DNS кешируется (и в dnsmasq, и в самом Chrome): повторный заход на тот
#      же домен за короткое время может не порождать нового запроса.
#
#  Использование:
#    sudo ./dns-query-log-deploy.sh --dry-run     # показать план
#    sudo ./dns-query-log-deploy.sh               # включить
#    sudo ./dns-query-log-deploy.sh --show        # состояние + последние записи
#    sudo ./dns-query-log-deploy.sh --tail        # следить в реальном времени
#    sudo ./dns-query-log-deploy.sh --verify      # прогнать самопроверку ещё раз
#    sudo ./dns-query-log-deploy.sh --remove      # выключить и вернуть как было
#
#  ЮРИДИЧЕСКОЕ: слежение за трафиком сотрудников почти везде требует их
#  письменного уведомления. Это ваша ответственность, не скрипта.
# ============================================================================
set -uo pipefail

VER="2.0"
DRY=0; REMOVE=0; SHOW=0; TAIL=0; VERIFY=0; RETAIN_DAYS=30
LOG_DIR="/var/log/dns-queries"
LOG_FILE="${LOG_DIR}/queries.log"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/dns-query-log/${TS}"
ROLLBACK="${BACKUP_DIR}/rollback.sh"
MASK="managed by dns-query-log-deploy"
DNSMASQ_CFG="/etc/dnsmasq.d/99-dns-log.conf"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/50-zavetsec-no-stub.conf"

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
    --dry-run)   DRY=1;;
    --remove)    REMOVE=1;;
    --show)      SHOW=1;;
    --tail)      TAIL=1;;
    --verify)    VERIFY=1;;
    --retain)    [[ -n "${2:-}" ]] || die "--retain требует число дней"; RETAIN_DAYS="$2"; shift;;
    --retain=*)  RETAIN_DAYS="${1#*=}";;
    --no-color)  export NO_COLOR=1;;
    -h|--help)   awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; exit 0;;
    --version)   echo "$VER"; exit 0;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
esac; shift; done

printf '%s%s  DNS query log deploy v%s%s\n\n' "$B" "$G" "$VER" "$R"

HAS_RESOLVED="no"
systemctl is-active --quiet systemd-resolved 2>/dev/null && HAS_RESOLVED="yes"

proxy_warning() {
    local p=""
    for v in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
        [[ -n "${!v:-}" ]] && p="${v}"
    done
    [[ -z "$p" ]] && grep -qs -iE '^[[:space:]]*(http|all)_proxy=' /etc/environment && p="/etc/environment"
    [[ -z "$p" ]] && [[ -f /etc/privoxy/config ]] && grep -qs '^forward-socks' /etc/privoxy/config && p="privoxy-релей"
    if [[ -n "$p" ]]; then
        warn "обнаружен прокси (${p})."
        warn "Если браузеры ходят через него, имена резолвит ПРОКСИ, а не эта машина,"
        warn "и DNS-лог останется пустым. Тогда логировать нужно на стороне прокси."
    fi
}

verify_logging() {
    command -v getent >/dev/null 2>&1 || { warn "getent нет — не могу самопроверить"; return 0; }
    local probe="selftest-$(date +%s)-$$.zavetsec.test"
    info "самопроверка: резолвлю пробный домен и ищу его в логе..."
    getent hosts "$probe" >/dev/null 2>&1 || true
    getent hosts example.com >/dev/null 2>&1 || true
    sleep 2
    if grep -qs "$probe" "$LOG_FILE" 2>/dev/null; then
        ok "запросы попадают в ${LOG_FILE} — логирование работает"
        return 0
    fi
    if [[ -n "$(find "$LOG_FILE" -newermt '-6 seconds' 2>/dev/null)" ]] \
       && grep -qsE 'query\[' "$LOG_FILE" 2>/dev/null; then
        ok "запросы попадают в ${LOG_FILE} — логирование работает"
        return 0
    fi
    return 1
}

if [[ "$SHOW" == "1" ]]; then
    dpkg -s dnsmasq >/dev/null 2>&1 && ok "dnsmasq установлен" || info "dnsmasq не установлен"
    systemctl is-active --quiet dnsmasq 2>/dev/null && ok "служба dnsmasq запущена" || info "dnsmasq не запущена"
    if command -v ss >/dev/null 2>&1; then
        local53="$(ss -tulnpH 2>/dev/null | awk '$5 ~ /:53$/ {print $5, $7}')"
        [[ -n "$local53" ]] && { info "порт 53 слушают:"; printf '%s\n' "$local53" | sed 's/^/    /'; }
    fi
    if [[ -e "$LOG_FILE" ]]; then
        printf '  %s: владелец %s, права %s, размер %s\n' "$LOG_FILE" \
            "$(stat -c '%U:%G' "$LOG_FILE")" "$(stat -c '%a' "$LOG_FILE")" \
            "$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)"
        printf '  строк query[] в логе: %s\n\n' "$(grep -cE 'query\[' "$LOG_FILE" 2>/dev/null || echo 0)"
        info "последние 15 запросов:"
        grep -E 'query\[' "$LOG_FILE" 2>/dev/null | tail -15 | sed 's/^/    /' || info "  (пока пусто)"
    else
        info "файл ${LOG_FILE} ещё не создан"
    fi
    exit 0
fi

if [[ "$TAIL" == "1" ]]; then
    [[ "$(id -u)" -eq 0 ]] || die "нужен root"
    [[ -e "$LOG_FILE" ]] || die "лог ещё не создан: ${LOG_FILE}"
    info "слежу за запросами в ${LOG_FILE}, Ctrl+C для выхода"
    exec tail -f "$LOG_FILE" | grep --line-buffered -E 'query\['
fi

[[ "$(id -u)" -eq 0 ]] || die "нужен root. Запустите через sudo."
run() { if [[ "$DRY" == "1" ]]; then dry "$*"; else "$@"; fi; }

if [[ "$VERIFY" == "1" ]]; then
    if verify_logging; then exit 0
    else err "запросы НЕ попадают в лог. Запустите: sudo $0 --show и проверьте порт 53"; exit 1; fi
fi

if [[ "$REMOVE" == "1" ]]; then
    if [[ -f "$DNSMASQ_CFG" ]] && grep -q "$MASK" "$DNSMASQ_CFG" 2>/dev/null; then
        run rm -f "$DNSMASQ_CFG"
        run systemctl stop dnsmasq 2>/dev/null || true
        run systemctl disable dnsmasq 2>/dev/null || true
        ok "конфиг dnsmasq удалён, служба остановлена"
    fi
    if [[ -f "$RESOLVED_DROPIN" ]]; then
        run rm -f "$RESOLVED_DROPIN"
        run systemctl restart systemd-resolved 2>/dev/null || true
        ok "DNS-заглушка systemd-resolved возвращена (порт 53 снова у resolved)"
    fi
    run rm -f /etc/logrotate.d/dns-queries
    info "лог-файл ${LOG_FILE} НЕ удалён (в нём собранные данные)"
    info "удалить вручную: sudo rm -rf ${LOG_DIR}"
    ok "готово. Проверьте, что имена резолвятся: getent hosts ya.ru"
    exit 0
fi

proxy_warning
echo
info "способ: dnsmasq на порту 53 (единственный, самодостаточный)"
[[ "$HAS_RESOLVED" == "yes" ]] && \
    info "systemd-resolved активен — сниму у него DNS-заглушку и передам :53 dnsmasq"
echo

[[ "$DRY" == "1" ]] || { mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    printf '#!/usr/bin/env bash\n# Откат DNS-лога, прогон %s\nset -u\n' "$TS" > "$ROLLBACK"; }

run mkdir -p "$LOG_DIR"
run chown root:root "$LOG_DIR"; run chmod 700 "$LOG_DIR"
[[ "$DRY" == "1" ]] || { [[ -e "$LOG_FILE" ]] || touch "$LOG_FILE"; chown root:root "$LOG_FILE"; chmod 600 "$LOG_FILE"; ok "лог-файл ${LOG_FILE} (root:root 600)"; }

if [[ "$DRY" == "1" ]]; then dry "записал бы /etc/logrotate.d/dns-queries (хранение ${RETAIN_DAYS} дней)"
else
    cat > /etc/logrotate.d/dns-queries <<EOF
${LOG_FILE} {
    daily
    rotate ${RETAIN_DAYS}
    missingok
    notifempty
    compress
    delaycompress
    create 600 root root
    su root root
    postrotate
        systemctl kill -s HUP dnsmasq 2>/dev/null || true
    endscript
}
EOF
    chmod 644 /etc/logrotate.d/dns-queries
    printf 'rm -f /etc/logrotate.d/dns-queries; echo "logrotate removed"\n' >> "$ROLLBACK"
    ok "ротация: ежедневно, хранение ${RETAIN_DAYS} дней, сжатие"
fi

UPSTREAMS=""
if [[ "$HAS_RESOLVED" == "yes" ]] && command -v resolvectl >/dev/null 2>&1; then
    UPSTREAMS="$(resolvectl status 2>/dev/null | awk '/Current DNS Server:/{print $4} /DNS Servers:/{for(i=3;i<=NF;i++)print $i}' \
                 | grep -E '^[0-9a-fA-F:.]+$' | grep -v '^127\.' | sort -u | head -3)"
fi
if [[ -z "$UPSTREAMS" ]]; then
    UPSTREAMS="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' \
                 | grep -vE '^127\.' | head -3)"
fi
[[ -z "$UPSTREAMS" ]] && UPSTREAMS=$'1.1.1.1\n8.8.8.8'
info "upstream DNS: $(echo $UPSTREAMS | tr '\n' ' ')"

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
else ok "dnsmasq уже установлен"; fi

if [[ "$HAS_RESOLVED" == "yes" ]]; then
    # Три директивы вместе, и все три обязательны:
    #   DNSStubListener=no — освобождает 127.0.0.53:53 под dnsmasq
    #   DNS=127.0.0.1      — resolved пересылает запросы в dnsmasq
    #   Domains=~.         — ВСЕ домены гонит в этот DNS, а не напрямую к провайдеру
    # Без DNS= и Domains= resolved перестаёт слушать stub, но запросы в dnsmasq
    # не отправляет — и журнал остаётся пустым (это была бага ранней версии).
    if [[ "$DRY" == "1" ]]; then
        dry "создал бы ${RESOLVED_DROPIN}: DNSStubListener=no, DNS=127.0.0.1, Domains=~."
        dry "перезапустил бы systemd-resolved (передаёт весь DNS в dnsmasq)"
    else
        mkdir -p "$(dirname "$RESOLVED_DROPIN")"
        cat > "$RESOLVED_DROPIN" <<EOF
# ${MASK}
[Resolve]
DNS=127.0.0.1
Domains=~.
DNSStubListener=no
EOF
        chmod 644 "$RESOLVED_DROPIN"
        printf 'rm -f "%s"; systemctl restart systemd-resolved 2>/dev/null; echo "resolved drop-in удалён, DNS вернулся к исходному"\n' "$RESOLVED_DROPIN" >> "$ROLLBACK"
        systemctl restart systemd-resolved 2>/dev/null || warn "не смог перезапустить resolved"
        ok "resolved: stub снят, весь DNS направлен в dnsmasq (127.0.0.1)"
    fi
fi

if [[ "$DRY" == "1" ]]; then
    dry "записал бы ${DNSMASQ_CFG} (log-queries, log-facility=${LOG_FILE}, порт 53)"
    echo
    printf '%s  Dry-run — ничего не изменено.%s\n\n' "$D" "$R"
    exit 0
fi

{
    echo "# ${MASK}"
    echo "log-queries"
    echo "log-facility=${LOG_FILE}"
    echo "listen-address=127.0.0.1"
    echo "bind-dynamic"
    echo "cache-size=1000"
    echo "no-resolv"
    echo "no-hosts"
    while read -r u; do [[ -n "$u" ]] && echo "server=${u}"; done <<< "$UPSTREAMS"
} > "$DNSMASQ_CFG"
chmod 644 "$DNSMASQ_CFG"
printf 'rm -f "%s"\n' "$DNSMASQ_CFG" >> "$ROLLBACK"

touch "$LOG_FILE"; chown root:root "$LOG_FILE"; chmod 600 "$LOG_FILE"

if ! dnsmasq --test 2>&1 | grep -qi 'syntax check ok'; then
    err "dnsmasq --test не прошёл:"
    dnsmasq --test 2>&1 | sed 's/^/      /' >&2
    rm -f "$DNSMASQ_CFG"
    [[ -f "$RESOLVED_DROPIN" ]] && { rm -f "$RESOLVED_DROPIN"; systemctl restart systemd-resolved 2>/dev/null; }
    die "конфиг откатан, resolved возвращён. Ничего не сломано."
fi
ok "dnsmasq --test пройден"

systemctl enable dnsmasq >/dev/null 2>&1
printf 'systemctl disable dnsmasq 2>/dev/null; systemctl stop dnsmasq 2>/dev/null; echo "dnsmasq stopped"\n' >> "$ROLLBACK"

if systemctl restart dnsmasq 2>/dev/null; then
    ok "dnsmasq запущен на 127.0.0.1:53"
else
    err "dnsmasq не стартовал. Последние строки журнала:"
    journalctl -u dnsmasq -n 15 --no-pager 2>/dev/null | sed 's/^/      /' >&2
    rm -f "$DNSMASQ_CFG"
    [[ -f "$RESOLVED_DROPIN" ]] && { rm -f "$RESOLVED_DROPIN"; systemctl restart systemd-resolved 2>/dev/null; }
    err "конфиг откатан, resolved возвращён. Проверьте: getent hosts ya.ru"
    exit 1
fi
sleep 1
chmod +x "$ROLLBACK" 2>/dev/null

if command -v ss >/dev/null 2>&1; then
    who53="$(ss -tulnpH 2>/dev/null | awk '$5 ~ /127.0.0.1:53$/ {print $7}' | grep -o 'dnsmasq' | head -1)"
    [[ "$who53" == "dnsmasq" ]] && ok "порт 127.0.0.1:53 держит dnsmasq" \
        || warn "на 127.0.0.1:53 dnsmasq не виден — проверьте ss -tulnp | grep :53"
fi

echo
if verify_logging; then
    STATUS="работает (системный DNS)"
    info "системный резолв логируется. Теперь проверьте БРАУЗЕР:"
    info "  1) в Chrome должен быть DoH=off (chrome-policy-deploy.sh --doh off)"
    info "  2) закройте Chrome полностью, откройте новый сайт"
    info "  3) sudo $0 --tail  — и смотрите, появляются ли домены"
    warn "если getent логируется, а браузер нет — почти всегда включён DoH в Chrome"
else
    STATUS="НЕ подтверждено"
    warn "самопроверка не увидела запрос в логе за отведённое время."
    warn "Возможные причины:"
    warn "  • резолв всё ещё идёт мимо dnsmasq — проверьте: ss -tulnp | grep :53"
    warn "  • браузеры ходят через прокси (см. предупреждение выше)"
    warn "Диагностика: sudo $0 --show"
fi

echo
printf '%s  ГОТОВО%s\n' "${B}${G}" "$R"
printf '  Логирование: %s\n' "$STATUS"
printf '  Лог (только root): %s\n' "$LOG_FILE"
printf '  Хранение: %s дней\n' "$RETAIN_DAYS"
printf '  Откат: sudo bash %s\n' "$ROLLBACK"
echo
printf '  %sСмотреть:%s      sudo %s --show\n' "$C" "$R" "$0"
printf '  %sСледить вживую:%s sudo %s --tail\n' "$C" "$R" "$0"
printf '  %sПерепроверить:%s  sudo %s --verify\n' "$C" "$R" "$0"
echo
