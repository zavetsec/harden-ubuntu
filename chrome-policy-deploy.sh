#!/usr/bin/env bash
# ============================================================================
#  chrome-policy-deploy.sh
#  Разворачивает единые политики безопасности Google Chrome для ВСЕХ
#  пользователей машины (Ubuntu). Политики кладутся в /etc, принадлежат root
#  и пользователем не отключаются.
#
#  Что делает:
#    * создаёт /etc/opt/chrome/policies/{managed,recommended}
#    * пишет managed/10-zavetsec-baseline.json с базовым набором политик
#    * принудительно ставит всем uBlock Origin Lite (MV3) — разово, без участия
#      пользователя; он не сможет его удалить
#    * по умолчанию запрещает удаление истории и режим инкогнито
#      (отключается ключами --no-lock-history / --no-block-incognito)
#    * DevTools запрещены (DeveloperToolsAvailability: 2), view-source тоже
#    * проверяет валидность JSON и права доступа
#    * делает бэкап прежнего файла и генерирует скрипт отката
#
#  Использование:
#    sudo ./chrome-policy-deploy.sh --dry-run        # показать, ничего не менять
#    sudo ./chrome-policy-deploy.sh                  # применить
#    sudo ./chrome-policy-deploy.sh --allow-ext ID   # разрешить расширение (можно много раз)
#    sudo ./chrome-policy-deploy.sh --force-ext ID   # ПРИНУДИТЕЛЬНО поставить всем
#    sudo ./chrome-policy-deploy.sh --no-ublock      # не ставить uBlock Origin Lite
#    sudo ./chrome-policy-deploy.sh --webrtc proxy   # WebRTC только через прокси
#    sudo ./chrome-policy-deploy.sh --no-lock-history    # разрешить чистить историю
#    sudo ./chrome-policy-deploy.sh --no-block-incognito # разрешить режим инкогнито
#    sudo ./chrome-policy-deploy.sh                  # DoH включён (по умолчанию, безопаснее)
#    sudo ./chrome-policy-deploy.sh --doh off        # выкл DoH: только если нужен DNS-лог на этой машине
#    sudo ./chrome-policy-deploy.sh --allow-devtools # оставить DevTools включёнными
#    sudo ./chrome-policy-deploy.sh --with-chromium  # продублировать для Chromium
#    sudo ./chrome-policy-deploy.sh --install-chrome # + подключить репозиторий Google
#    sudo ./chrome-policy-deploy.sh --remove         # снять политики
#    sudo ./chrome-policy-deploy.sh --show           # показать, что применено сейчас
# ============================================================================
set -uo pipefail

VER="1.0"
DRY=0; WITH_CHROMIUM=0; INSTALL_CHROME=0; REMOVE=0; SHOW=0; ALLOW_DEVTOOLS=0; NO_UBLOCK=0
WEBRTC="default"; LOCK_HISTORY=1; BLOCK_INCOGNITO=1; DOH_MODE="automatic"; BLOCK_PASSWORDS=1
EXTRA_EXTS=(); FORCE_EXTS=()

CHROME_BASE="/etc/opt/chrome/policies"
CHROMIUM_BASE="/etc/chromium/policies"
POLICY_NAME="10-zavetsec-baseline.json"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/chrome-policy/${TS}"
ROLLBACK="${BACKUP_DIR}/rollback.sh"

# uBlock Origin Lite (uBOL) — MV3-сборка от того же автора.
# Классический uBlock Origin (cjpalhdlnbpafiamejdnhcphjbkeiagm) — Manifest V2,
# и в актуальном Chrome он не запускается ни при каких настройках: политика
# ExtensionManifestV2Availability убрана ещё в Chrome 139, последние флаги —
# в Chrome 151 (июль 2026). Ставить надо именно uBOL.
UBLOCK_ID="ddkjiahejlhfcafbddmgiahcphecmpfh"
UBLOCK_MV2_ID="cjpalhdlnbpafiamejdnhcphjbkeiagm"
CWS_UPDATE_URL="https://clients2.google.com/service/update2/crx"
DEFAULT_EXTS=("$UBLOCK_ID")

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    R=$'\e[0m'; G=$'\e[38;5;48m'; Y=$'\e[38;5;221m'; C=$'\e[38;5;80m'
    E=$'\e[38;5;203m'; D=$'\e[2m'; B=$'\e[1m'
else R=''; G=''; Y=''; C=''; E=''; D=''; B=''; fi

ok()   { printf '%s[OK]%s   %s\n'   "$G" "$R" "$*"; }
info() { printf '%s[INFO]%s %s\n'   "$C" "$R" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$Y" "$R" "$*"; }
err()  { printf '%s[ERR]%s  %s\n'   "$E" "$R" "$*" >&2; }
dry()  { printf '%s[DRY]%s  %s\n'   "$D" "$R" "$*"; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do case "$1" in
    --dry-run)        DRY=1;;
    --with-chromium)  WITH_CHROMIUM=1;;
    --install-chrome) INSTALL_CHROME=1;;
    --allow-devtools) ALLOW_DEVTOOLS=1;;
    --allow-ext)      [[ -n "${2:-}" ]] || die "--allow-ext требует ID расширения"
                      EXTRA_EXTS+=("$2"); shift;;
    --allow-ext=*)    EXTRA_EXTS+=("${1#*=}");;
    --force-ext)      [[ -n "${2:-}" ]] || die "--force-ext требует ID расширения"
                      FORCE_EXTS+=("$2"); shift;;
    --force-ext=*)    FORCE_EXTS+=("${1#*=}");;
    --no-ublock)      NO_UBLOCK=1;;
    --webrtc)         [[ -n "${2:-}" ]] || die "--webrtc требует proxy|default"
                      WEBRTC="$2"; shift;;
    --webrtc=*)       WEBRTC="${1#*=}";;
    --no-lock-history)   LOCK_HISTORY=0;;
    --no-block-incognito) BLOCK_INCOGNITO=0;;
    --allow-history-delete) LOCK_HISTORY=0;;
    --allow-incognito)   BLOCK_INCOGNITO=0;;
    --doh)            [[ -n "${2:-}" ]] || die "--doh требует off|automatic|secure"; DOH_MODE="$2"; shift;;
    --doh=*)          DOH_MODE="${1#*=}";;
    --enable-doh)     DOH_MODE="automatic";;
    --allow-passwords) BLOCK_PASSWORDS=0;;
    --remove)         REMOVE=1;;
    --show)           SHOW=1;;
    --no-color)       export NO_COLOR=1;;
    -h|--help)        awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; exit 0;;
    --version)        echo "$VER"; exit 0;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
esac; shift; done

printf '%s%s  Chrome policy deploy v%s%s\n\n' "$B" "$G" "$VER" "$R"

# --- режим просмотра: root не нужен ----------------------------------------
if [[ "$SHOW" == "1" ]]; then
    found=0
    for f in "${CHROME_BASE}/managed/"*.json "${CHROMIUM_BASE}/managed/"*.json; do
        [[ -e "$f" ]] || continue
        found=1
        printf '%s── %s%s\n' "$B" "$f" "$R"
        printf '   владелец: %s  права: %s\n' "$(stat -c '%U:%G' "$f")" "$(stat -c '%a' "$f")"
        if command -v python3 >/dev/null 2>&1; then
            python3 -m json.tool --no-ensure-ascii "$f" 2>/dev/null || warn "невалидный JSON"
        else cat "$f"; fi
        echo
    done
    [[ "$found" == "0" ]] && info "политики Chrome не найдены"
    info "фактически применённое смотрите в самом браузере: chrome://policy"
    exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "нужен root. Запустите через sudo."

run() { if [[ "$DRY" == "1" ]]; then dry "$*"; else "$@"; fi; }

# --- снятие политик ---------------------------------------------------------
if [[ "$REMOVE" == "1" ]]; then
    for base in "$CHROME_BASE" "$CHROMIUM_BASE"; do
        f="${base}/managed/${POLICY_NAME}"
        if [[ -e "$f" ]]; then run rm -f "$f"; ok "удалён $f"
        else info "нет $f"; fi
    done
    info "перезапустите Chrome, чтобы изменения вступили в силу"
    exit 0
fi

# --- опционально: репозиторий Google ---------------------------------------
if [[ "$INSTALL_CHROME" == "1" ]]; then
    if command -v google-chrome >/dev/null 2>&1 || dpkg -s google-chrome-stable >/dev/null 2>&1; then
        ok "Google Chrome уже установлен"
    else
        info "подключаю официальный репозиторий Google Chrome"
        if [[ "$DRY" == "1" ]]; then
            dry "curl ... linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg"
            dry "echo 'deb [...] https://dl.google.com/linux/chrome/deb/ stable main' > /etc/apt/sources.list.d/google-chrome.list"
            dry "apt-get update && apt-get install -y google-chrome-stable"
        else
            if curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
                 | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg 2>/dev/null; then
                printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main\n' \
                    > /etc/apt/sources.list.d/google-chrome.list
                apt-get update >/dev/null 2>&1
                if env DEBIAN_FRONTEND=noninteractive apt-get install -y google-chrome-stable >/dev/null 2>&1; then
                    ok "Google Chrome установлен"
                else warn "не удалось установить google-chrome-stable — поставьте вручную"; fi
            else
                warn "не удалось получить ключ репозитория (нет сети?) — пропускаю установку"
            fi
        fi
    fi
fi

# --- собираем список разрешённых расширений --------------------------------
EXTS=("${DEFAULT_EXTS[@]}")
if [[ ${#EXTRA_EXTS[@]} -gt 0 ]]; then EXTS+=("${EXTRA_EXTS[@]}"); fi
for id in "${EXTS[@]}"; do
    [[ "$id" =~ ^[a-p]{32}$ ]] || warn "ID '${id}' не похож на ID расширения Chrome (32 буквы a-p)"
done
EXT_JSON=""
for id in "${EXTS[@]}"; do EXT_JSON+="${EXT_JSON:+, }\"${id}\""; done

# --- принудительная установка (ExtensionInstallForcelist) --------------------
# Расширение ставится молча при первом запуске Chrome у КАЖДОГО пользователя
# и не может быть отключено или удалено им.
FORCED=()
[[ "$NO_UBLOCK" == "1" ]] || FORCED+=("$UBLOCK_ID")
if [[ ${#FORCE_EXTS[@]} -gt 0 ]]; then FORCED+=("${FORCE_EXTS[@]}"); fi
for id in "${FORCED[@]}"; do
    if [[ "$id" == "$UBLOCK_MV2_ID" ]]; then
        err "ID ${id} — это классический uBlock Origin на Manifest V2."
        err "В актуальном Chrome он не запустится: MV2 отключён окончательно."
        err "Используйте uBlock Origin Lite: ${UBLOCK_ID}"
        exit 1
    fi
    [[ "$id" =~ ^[a-p]{32}$ ]] || warn "ID '${id}' не похож на ID расширения Chrome"
done
FORCE_JSON=""
for id in "${FORCED[@]}"; do FORCE_JSON+="${FORCE_JSON:+, }\"${id};${CWS_UPDATE_URL}\""; done
FORCE_BLOCK=""
if [[ -n "$FORCE_JSON" ]]; then
    FORCE_BLOCK="  \"ExtensionInstallForcelist\": [${FORCE_JSON}],
"
fi

# --- DevTools ---------------------------------------------------------------
if [[ "$ALLOW_DEVTOOLS" == "1" ]]; then
    DEVTOOLS_BLOCK=""
    info "DevTools оставлены включёнными (--allow-devtools)"
else
    # 2 = DeveloperToolsDisallowed. Заодно закрываем view-source: и
    # devtools:// — иначе запрет обходится в два клика.
    DEVTOOLS_BLOCK='
  "DeveloperToolsAvailability": 2,
  "URLBlocklist": ["view-source:*", "devtools://*", "chrome://net-export"],
'
    warn "DevTools будут ЗАПРЕЩЕНЫ для всех пользователей (F12, Ctrl+Shift+I, view-source)"
    warn "если на машине кто-то разрабатывает или отлаживает веб — это ему сломает работу"
fi

# --- История и инкогнито ----------------------------------------------------
# AllowDeletingBrowserHistory=false убирает удаление истории из интерфейса.
# ВАЖНО: это защита уровня UI. Файл History лежит в профиле пользователя и
# доступен ему на запись — оператор с шеллом может удалить файл или профиль
# целиком. Настоящий неудаляемый журнал посещений даёт dns-query-log-deploy.sh
# (root:root 600), а не эта политика. Здесь — только «в пару кликов не сотрёт».
if [[ "$LOCK_HISTORY" == "1" ]]; then
    HISTORY_BLOCK='  "AllowDeletingBrowserHistory": false,
'
    info "удаление истории через браузер будет запрещено"
    warn "это НЕ мешает удалить файл History в профиле — надёжный лог даёт DNS-логгер"
else
    HISTORY_BLOCK=""
    info "удаление истории оставлено разрешённым (--no-lock-history)"
fi

# Запрет инкогнито обязателен, если замыкаем историю: в инкогнито история
# просто не пишется, и замок на её удаление теряет смысл.
if [[ "$BLOCK_INCOGNITO" == "1" ]]; then
    INCOGNITO_BLOCK='  "IncognitoModeAvailability": 1,
'
    info "режим инкогнито будет отключён"
else
    INCOGNITO_BLOCK=""
    info "режим инкогнито оставлен доступным (--no-block-incognito)"
    [[ "$LOCK_HISTORY" == "1" ]] &&         warn "замок на историю почти бесполезен без запрета инкогнито: в нём история не пишется"
fi

# --- DNS over HTTPS ---------------------------------------------------------
# По умолчанию automatic (безопаснее): Chrome шифрует DNS через DoH. Это скрывает
# список доменов от наблюдателя на пути и защищает от подмены DNS-ответов.
# ЦЕНА безопасности: браузерный DNS уходит в обход машины, поэтому DNS-лог
# (dns-query-log-deploy.sh) по браузеру будет ПУСТЫМ.
#
# --doh off нужен ТОЛЬКО если вы сознательно логируете посещения на этой машине
# и приняли, что DNS перестанет шифроваться. Если браузеры ходят через прокси —
# лучше не выключать DoH, а логировать на стороне прокси.
case "$DOH_MODE" in
  off)
    DOH_JSON='  "DnsOverHttpsMode": "off",
'
    warn "DoH ОТКЛЮЧЁН — включайте только если нужен DNS-лог на этой машине"
    warn "цена: DNS-запросы браузера перестают шифроваться и становятся видны"
    warn "на пути до резолвера; появляется риск подмены DNS-ответов"
    ;;
  automatic|secure)
    DOH_JSON="  \"DnsOverHttpsMode\": \"${DOH_MODE}\",
"
    info "DoH включён (${DOH_MODE}) — DNS Chrome шифруется (безопаснее)"
    [[ "$DOH_MODE" == "automatic" ]] && info "  (automatic: DoH при поддержке провайдером, иначе обычный DNS)"
    ;;
  *) die "--doh принимает off, automatic или secure (получено: ${DOH_MODE})";;
esac

# --- Пароли -----------------------------------------------------------------
# PasswordManagerEnabled=false полностью выключает встроенный менеджер: браузер
# не предлагает сохранять, не хранит, не автозаполняет пароли. Ранее сохранённые
# перестают подставляться. Пользователь не может включить обратно.
# PasswordSharingEnabled=false — запрет "поделиться паролем" (Chrome умеет).
# Автозаполнение адресов и карт тоже выключено (ниже в JSON).
#
# ВАЖНО про "админ видит, пользователь нет": браузером это НЕ строится. Пароли
# менеджера привязаны к профилю пользователя, между профилями не видны, а в
# момент входа пароль всё равно оказывается в памяти вкладки. Для схемы
# "админ владеет, оператор пользуется вслепую" нужен внешний менеджер
# (Bitwarden/Vaultwarden) или SSO, а не политика браузера.
if [[ "$BLOCK_PASSWORDS" == "1" ]]; then
    PW_BLOCK='  "PasswordManagerEnabled": false,
  "PasswordSharingEnabled": false,
  "ImportSavedPasswords": false,
'
    info "встроенный менеджер паролей будет отключён для всех пользователей"
    info "  (сохранённые в браузере пароли перестанут подставляться)"
else
    PW_BLOCK=""
    info "встроенный менеджер паролей оставлен доступным (--allow-passwords)"
fi

# --- WebRTC -----------------------------------------------------------------
# ВАЖНО: в Chrome НЕТ политики, полностью убирающей WebRTC. RTCPeerConnection
# остаётся доступен из JavaScript при любых настройках. Максимум, что даёт
# корпоративная политика — запретить обход прокси, и для задачи «не светить
# реальный IP за прокси» этого достаточно.
case "$WEBRTC" in
  proxy|off)
    [[ "$WEBRTC" == "off" ]] && {
        warn "Chrome не умеет отключать WebRTC политикой — применяю строжайший"
        warn "доступный режим (disable_non_proxied_udp). Сам API останется в JS."
    }
    # Обе формы имени: WebRtcIPHandlingPolicy — историческая, WebRtcIPHandling —
    # актуальная. Незнакомую Chrome просто пометит в chrome://policy и пропустит.
    WEBRTC_BLOCK='  "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
  "WebRtcIPHandling": "disable_non_proxied_udp",
  "WebRtcLocalIpsAllowedUrls": [],
'
    info "WebRTC: запрещён непроксированный UDP, локальные IP не отдаются сайтам"
    warn "видеозвонки в браузере соединятся, только если прокси пропускает медиатрафик"
    ;;
  default)
    WEBRTC_BLOCK=""
    ;;
  *)
    die "--webrtc принимает proxy или default (получено: ${WEBRTC})"
    ;;
esac

# --- сам файл политик -------------------------------------------------------
POLICY_JSON=$(cat <<EOF
{
  "_comment": "Managed by chrome-policy-deploy.sh — не редактируйте вручную, изменения перезапишутся",

${WEBRTC_BLOCK}${HISTORY_BLOCK}${INCOGNITO_BLOCK}  "SafeBrowsingProtectionLevel": 2,
  "DownloadRestrictions": 1,
  "SSLVersionMin": "tls1.2",
  "HttpsOnlyMode": "force_enabled",
  "InsecureFormsWarningsEnabled": true,
${DOH_JSON}${DEVTOOLS_BLOCK}
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallAllowlist": [${EXT_JSON}],
${FORCE_BLOCK}  "ExtensionSettings": {
    "${UBLOCK_ID}": { "toolbar_pin": "force_pinned" }
  },
  "BlockExternalExtensions": true,

  "BrowserSignin": 0,
  "SyncDisabled": true,
  "MetricsReportingEnabled": false,
  "SearchSuggestEnabled": false,
${PW_BLOCK}  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "BackgroundModeEnabled": false,
  "RemoteAccessHostFirewallTraversal": false,

  "DefaultGeolocationSetting": 2,
  "DefaultNotificationsSetting": 2,
  "DefaultSensorsSetting": 2,
  "DefaultWebBluetoothGuardSetting": 2,
  "DefaultWebUsbGuardSetting": 2,
  "DefaultSerialGuardSetting": 2,
  "DefaultFileSystemReadGuardSetting": 2,
  "DefaultFileSystemWriteGuardSetting": 2,
  "DefaultInsecureContentSetting": 2,

  "ComponentUpdatesEnabled": true,
  "RelaunchNotification": 2,
  "RelaunchNotificationPeriod": 86400000,
  "CloudPolicyOverridesPlatformPolicy": false
}
EOF
)

# --- проверка JSON ДО записи (кривой файл Chrome просто молча игнорирует) ---
if command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$POLICY_JSON" | python3 -m json.tool >/dev/null 2>&1; then
        ok "JSON валиден"
    else
        err "сгенерирован невалидный JSON — ничего не записываю:"
        printf '%s' "$POLICY_JSON" | python3 -m json.tool 2>&1 | head -5 >&2
        exit 1
    fi
else
    warn "python3 нет — пропускаю проверку JSON"
fi

# --- целевые каталоги -------------------------------------------------------
TARGETS=("$CHROME_BASE")
if [[ "$WITH_CHROMIUM" == "1" ]]; then
    TARGETS+=("$CHROMIUM_BASE")
    if snap list chromium >/dev/null 2>&1; then
        warn "Chromium установлен как snap — он может НЕ читать ${CHROMIUM_BASE}."
        warn "После применения обязательно проверьте chrome://policy в самом Chromium."
    fi
fi

[[ "$DRY" == "1" ]] || { mkdir -p "$BACKUP_DIR"
    printf '#!/usr/bin/env bash\n# Откат политик Chrome, прогон %s\nset -u\n' "$TS" > "$ROLLBACK"; }

for base in "${TARGETS[@]}"; do
    mgd="${base}/managed"; rec="${base}/recommended"; dst="${mgd}/${POLICY_NAME}"

    run mkdir -p "$mgd" "$rec"

    if [[ -e "$dst" ]]; then
        if [[ "$DRY" == "1" ]]; then
            dry "бэкап $dst -> ${BACKUP_DIR}"
        else
            cp -a "$dst" "${BACKUP_DIR}/$(echo "$dst" | tr '/' '_')"
            printf 'cp -a "%s" "%s" && echo "restored %s"\n' \
                "${BACKUP_DIR}/$(echo "$dst" | tr '/' '_')" "$dst" "$dst" >> "$ROLLBACK"
            info "бэкап: $dst"
        fi
    else
        [[ "$DRY" == "1" ]] || printf 'rm -f "%s" && echo "removed %s"\n' "$dst" "$dst" >> "$ROLLBACK"
    fi

    if [[ "$DRY" == "1" ]]; then
        dry "записал бы $dst"
    else
        printf '%s\n' "$POLICY_JSON" > "$dst"
        chown root:root "$dst"; chmod 644 "$dst"
        chown root:root "$mgd" "$rec"; chmod 755 "$mgd" "$rec"
        ok "записан $dst"
    fi
done

if [[ "$DRY" == "1" ]]; then
    echo; info "Dry-run — ничего не изменено. Содержимое будущего файла:"
    printf '%s\n' "$POLICY_JSON" | sed 's/^/    /'
    exit 0
fi

chmod +x "$ROLLBACK" 2>/dev/null

# --- контроль прав: файл не должен быть доступен на запись пользователям ----
for base in "${TARGETS[@]}"; do
    dst="${base}/managed/${POLICY_NAME}"
    [[ -e "$dst" ]] || continue
    perm="$(stat -c '%a' "$dst")"; owner="$(stat -c '%U' "$dst")"
    if [[ "$owner" != "root" || "${perm:1}" =~ [2367] ]]; then
        err "$dst доступен на запись не только root (${owner} ${perm}) — политики можно обойти!"
    else
        ok "права корректны: ${owner} ${perm}"
    fi
done

# --- кто сейчас запущен -----------------------------------------------------
# ВАЖНО: сопоставляем по ИМЕНИ процесса (-x), а не по всей командной строке —
# иначе pgrep находит сам этот скрипт, в пути которого есть слово "chrome".
echo
BROWSER_USERS="$(pgrep -x 'chrome|google-chrome|chromium|chromium-browser' 2>/dev/null \
                 | while read -r p; do ps -o user= -p "$p" 2>/dev/null; done | sort -u)"
if [[ -n "$BROWSER_USERS" ]]; then
    warn "Chrome/Chromium сейчас запущен у пользователей:"
    printf '%s\n' "$BROWSER_USERS" | sed 's/^/    /'
    warn "политики применятся только после ПОЛНОГО закрытия и перезапуска браузера"
else
    ok "запущенных экземпляров браузера нет — политики применятся при следующем старте"
fi

echo
printf '%s  ГОТОВО%s\n' "${B}${G}" "$R"
printf '  Файл политик: %s/managed/%s\n' "$CHROME_BASE" "$POLICY_NAME"
printf '  Разрешённые расширения: %s\n' "${EXTS[*]}"
if [[ ${#FORCED[@]} -gt 0 ]]; then
    printf '  Ставятся принудительно:  %s\n' "${FORCED[*]}"
    [[ "$NO_UBLOCK" == "1" ]] || printf '    %s= uBlock Origin Lite (MV3)%s\n' "$D" "$R"
fi
printf '  DevTools: %s\n' "$([[ "$ALLOW_DEVTOOLS" == "1" ]] && echo 'разрешены' || echo 'ЗАПРЕЩЕНЫ')"
if [[ "$WEBRTC" != "default" ]]; then
    printf '  WebRTC: только через прокси (полностью Chrome отключать не умеет)\n'
fi
printf '  Удаление истории: %s\n' "$([[ "$LOCK_HISTORY" == "1" ]] && echo 'запрещено в браузере' || echo 'разрешено')"
printf '  Режим инкогнито: %s\n' "$([[ "$BLOCK_INCOGNITO" == "1" ]] && echo 'отключён' || echo 'доступен')"
printf '  DoH: %s\n' "$([[ "$DOH_MODE" == "off" ]] && echo 'ВЫКЛЮЧЕН (DNS не шифруется, но логируется)' || echo "${DOH_MODE} (шифруется, безопаснее)")"
printf '  Менеджер паролей: %s\n' "$([[ "$BLOCK_PASSWORDS" == "1" ]] && echo 'отключён' || echo 'доступен')"
printf '  Бэкап и откат: %s\n' "$ROLLBACK"
echo
printf '  %sПроверка:%s откройте chrome://policy, нажмите Reload policies,\n' "$C" "$R"
printf '            у всех политик статус должен быть OK\n'
[[ "$WEBRTC" != "default" ]] && \
printf '  %sУтечка IP:%s проверьте на https://browserleaks.com/webrtc\n' "$C" "$R"
printf '  %sОткат:%s    sudo bash %s\n' "$Y" "$R" "$ROLLBACK"
echo
