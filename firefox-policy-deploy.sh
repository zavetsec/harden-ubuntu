#!/usr/bin/env bash
# ============================================================================
#  firefox-policy-deploy.sh
#  Разворачивает единые политики безопасности Mozilla Firefox для ВСЕХ
#  пользователей машины (Ubuntu). Аналог chrome-policy-deploy.sh.
#
#  Что делает:
#    * пишет /etc/firefox/policies/policies.json — этот путь работает и для
#      snap-сборки Ubuntu, и для deb от Mozilla, и для Flatpak
#    * принудительно ставит всем uBlock Origin (ПОЛНЫЙ, не Lite — в Firefox
#      сохранён блокирующий webRequest, поэтому MV3-урезание его не коснулось)
#    * блокирует установку любых других расширений
#    * отключает инструменты разработчика, телеметрию, Pocket, синхронизацию
#    * включает строгую защиту от отслеживания и режим только-HTTPS
#    * проверяет валидность JSON и права доступа, делает бэкап и откат
#
#  Использование:
#    sudo ./firefox-policy-deploy.sh --dry-run          # показать, не менять
#    sudo ./firefox-policy-deploy.sh                    # применить
#    sudo ./firefox-policy-deploy.sh --allow-devtools   # оставить DevTools
#    sudo ./firefox-policy-deploy.sh --no-ublock        # без uBlock Origin
#    sudo ./firefox-policy-deploy.sh --webrtc off       # выключить WebRTC совсем
#    sudo ./firefox-policy-deploy.sh --webrtc proxy     # WebRTC только через прокси
#    sudo ./firefox-policy-deploy.sh --doh off          # не трогать DNS вообще
#    sudo ./firefox-policy-deploy.sh --no-lock-history  # разрешить чистить историю
#    sudo ./firefox-policy-deploy.sh --no-block-private # разрешить приватный режим
#    sudo ./firefox-policy-deploy.sh --allow-passwords  # разрешить менеджер паролей
#
#  ЧЕГО СКРИПТ НЕ ДЕЛАЕТ НИКОГДА:
#    * не задаёт политику Proxy и не пишет ни одного параметра network.proxy.*
#    * не переключает Firefox на системный прокси и не уводит с него
#    Настройки прокси остаются ровно такими, какими вы их сделали. Перед
#    записью файла это проверяется автоматически (см. «страховка от прокси»).
#    sudo ./firefox-policy-deploy.sh --force-ext 'ID=URL'   # доп. расширение
#    sudo ./firefox-policy-deploy.sh --allow-ext ID     # разрешить установку
#    sudo ./firefox-policy-deploy.sh --also-distribution # + в каталог установки
#    sudo ./firefox-policy-deploy.sh --show             # что применено сейчас
#    sudo ./firefox-policy-deploy.sh --remove           # снять политики
#
#  Проверка результата: откройте в Firefox about:policies
# ============================================================================
set -uo pipefail

VER="1.0"
DRY=0; REMOVE=0; SHOW=0; ALLOW_DEVTOOLS=0; NO_UBLOCK=0; ALSO_DIST=0
LOCK_HISTORY=1; BLOCK_PRIVATE=1
WEBRTC="default"; DOH="auto"; BLOCK_PASSWORDS=1
ALLOW_EXTS=(); FORCE_SPECS=()

POLICY_DIR="/etc/firefox/policies"
POLICY_FILE="${POLICY_DIR}/policies.json"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/firefox-policy/${TS}"
ROLLBACK="${BACKUP_DIR}/rollback.sh"

# В Firefox расширения адресуются не 32-буквенным ID как в Chrome, а
# идентификатором вида addon@example.com, и для принудительной установки
# нужен прямой URL на .xpi.
UBLOCK_ID="uBlock0@raymondhill.net"
UBLOCK_URL="https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"

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
    --dry-run)           DRY=1;;
    --allow-devtools)    ALLOW_DEVTOOLS=1;;
    --no-lock-history)     LOCK_HISTORY=0;;
    --allow-history-delete) LOCK_HISTORY=0;;
    --no-block-private)    BLOCK_PRIVATE=0;;
    --allow-private)       BLOCK_PRIVATE=0;;
    --allow-passwords)     BLOCK_PASSWORDS=0;;
    --no-ublock)         NO_UBLOCK=1;;
    --also-distribution) ALSO_DIST=1;;
    --webrtc)            [[ -n "${2:-}" ]] || die "--webrtc требует off|proxy|default"
                         WEBRTC="$2"; shift;;
    --webrtc=*)          WEBRTC="${1#*=}";;
    --doh)               [[ -n "${2:-}" ]] || die "--doh требует on|off|auto"
                         DOH="$2"; shift;;
    --doh=*)             DOH="${1#*=}";;
    --allow-ext)         [[ -n "${2:-}" ]] || die "--allow-ext требует ID расширения"
                         ALLOW_EXTS+=("$2"); shift;;
    --allow-ext=*)       ALLOW_EXTS+=("${1#*=}");;
    --force-ext)         [[ -n "${2:-}" ]] || die "--force-ext требует 'ID=URL'"
                         FORCE_SPECS+=("$2"); shift;;
    --force-ext=*)       FORCE_SPECS+=("${1#*=}");;
    --remove)            REMOVE=1;;
    --show)              SHOW=1;;
    --no-color)          export NO_COLOR=1;;
    -h|--help)           awk 'NR>1{ if(/^#/){sub(/^# ?/,"");print} else exit }' "$0"; exit 0;;
    --version)           echo "$VER"; exit 0;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
esac; shift; done

printf '%s%s  Firefox policy deploy v%s%s\n\n' "$B" "$G" "$VER" "$R"

# --- как установлен Firefox -------------------------------------------------
FF_KIND="не найден"
DIST_DIRS=()
if snap list firefox >/dev/null 2>&1; then
    FF_KIND="snap"
elif [[ -d /usr/lib/firefox ]]; then
    FF_KIND="deb (/usr/lib/firefox)"; DIST_DIRS+=("/usr/lib/firefox/distribution")
elif [[ -d /opt/firefox ]]; then
    FF_KIND="tarball (/opt/firefox)"; DIST_DIRS+=("/opt/firefox/distribution")
elif command -v firefox >/dev/null 2>&1; then
    FF_KIND="есть в PATH"
fi

# --- режим просмотра --------------------------------------------------------
if [[ "$SHOW" == "1" ]]; then
    info "установка Firefox: ${FF_KIND}"
    if [[ -e "$POLICY_FILE" ]]; then
        printf '%s── %s%s\n' "$B" "$POLICY_FILE" "$R"
        printf '   владелец: %s  права: %s\n' \
            "$(stat -c '%U:%G' "$POLICY_FILE")" "$(stat -c '%a' "$POLICY_FILE")"
        if command -v python3 >/dev/null 2>&1; then
            python3 -m json.tool --no-ensure-ascii "$POLICY_FILE" 2>/dev/null || warn "невалидный JSON"
        else cat "$POLICY_FILE"; fi
    else
        info "политики не найдены: ${POLICY_FILE} отсутствует"
    fi
    for d in "${DIST_DIRS[@]}"; do
        [[ -e "${d}/policies.json" ]] && { echo; printf '%s── %s/policies.json%s\n' "$B" "$d" "$R"; cat "${d}/policies.json"; }
    done
    echo; info "фактически применённое смотрите в браузере: about:policies"
    exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "нужен root. Запустите через sudo."
run() { if [[ "$DRY" == "1" ]]; then dry "$*"; else "$@"; fi; }

# --- есть ли на машине прокси -----------------------------------------------
# Нужно только чтобы НЕ навредить: при обнаруженном прокси скрипт не лезет
# в разрешение имён. Сами настройки прокси не читаются и не меняются.
PROXY_FOUND="no"; PROXY_HINT=""
for v in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    [[ -n "${!v:-}" ]] && { PROXY_FOUND="yes"; PROXY_HINT="переменная окружения ${v}"; break; }
done
if [[ "$PROXY_FOUND" == "no" && -r /etc/environment ]] \
   && grep -qiE '^[[:space:]]*(http|https|all)_proxy=' /etc/environment; then
    PROXY_FOUND="yes"; PROXY_HINT="/etc/environment"
fi
if [[ "$PROXY_FOUND" == "no" ]] && command -v gsettings >/dev/null 2>&1; then
    m="$(gsettings get org.gnome.system.proxy mode 2>/dev/null | tr -d "'")"
    [[ -n "$m" && "$m" != "none" ]] && { PROXY_FOUND="yes"; PROXY_HINT="GNOME (режим ${m})"; }
fi
if [[ "$PROXY_FOUND" == "no" && -r /etc/apt/apt.conf.d/proxy.conf ]]; then
    PROXY_FOUND="yes"; PROXY_HINT="apt proxy.conf"
fi
[[ "$PROXY_FOUND" == "yes" ]] && info "обнаружен прокси: ${PROXY_HINT} — настройки прокси НЕ изменяются"

info "установка Firefox: ${FF_KIND}"
[[ "$FF_KIND" == "не найден" ]] && warn "Firefox не обнаружен — политики всё равно запишутся и сработают после установки"

# --- снятие -----------------------------------------------------------------
if [[ "$REMOVE" == "1" ]]; then
    if [[ -e "$POLICY_FILE" ]]; then run rm -f "$POLICY_FILE"; ok "удалён $POLICY_FILE"
    else info "нет $POLICY_FILE"; fi
    for d in "${DIST_DIRS[@]}"; do
        [[ -e "${d}/policies.json" ]] && { run rm -f "${d}/policies.json"; ok "удалён ${d}/policies.json"; }
    done
    info "перезапустите Firefox, чтобы изменения вступили в силу"
    exit 0
fi

# --- расширения -------------------------------------------------------------
# Блок ExtensionSettings: "*" запрещает всё, дальше точечные исключения.
EXT_ENTRIES=()

if [[ "$NO_UBLOCK" != "1" ]]; then
    EXT_ENTRIES+=("    \"${UBLOCK_ID}\": {
      \"installation_mode\": \"force_installed\",
      \"install_url\": \"${UBLOCK_URL}\",
      \"default_area\": \"navbar\",
      \"updates_disabled\": false
    }")
fi

for spec in "${FORCE_SPECS[@]}"; do
    fid="${spec%%=*}"; furl="${spec#*=}"
    if [[ "$fid" == "$spec" || -z "$furl" ]]; then
        err "--force-ext требует формат 'ID=URL', получено: ${spec}"
        err "например: --force-ext 'uBlock0@raymondhill.net=https://.../latest.xpi'"
        err "В Firefox, в отличие от Chrome, нужен прямой адрес .xpi — по одному"
        err "идентификатору браузер расширение найти не может."
        exit 1
    fi
    [[ "$furl" =~ ^https:// ]] || { err "URL расширения должен начинаться с https:// — ${furl}"; exit 1; }
    EXT_ENTRIES+=("    \"${fid}\": {
      \"installation_mode\": \"force_installed\",
      \"install_url\": \"${furl}\",
      \"default_area\": \"navbar\"
    }")
done

for aid in "${ALLOW_EXTS[@]}"; do
    EXT_ENTRIES+=("    \"${aid}\": { \"installation_mode\": \"allowed\" }")
done

EXT_JSON="    \"*\": {
      \"installation_mode\": \"blocked\",
      \"allowed_types\": [\"extension\"],
      \"blocked_install_message\": \"Установка расширений на этой машине разрешена только администратором.\"
    }"
for e in "${EXT_ENTRIES[@]}"; do EXT_JSON+=",
${e}"; done

# --- DevTools ---------------------------------------------------------------
if [[ "$ALLOW_DEVTOOLS" == "1" ]]; then
    DEVTOOLS_JSON='    "DisableDeveloperTools": false,'
    info "инструменты разработчика оставлены включёнными"
else
    DEVTOOLS_JSON='    "DisableDeveloperTools": true,
    "BlockAboutConfig": true,
    "BlockAboutProfiles": true,'
    warn "DevTools будут ЗАПРЕЩЕНЫ, about:config и about:profiles заблокированы"
    warn "ВНИМАНИЕ: в Firefox нет надёжного способа закрыть view-source: политикой,"
    warn "в отличие от Chrome, где это делается через URLBlocklist. Просмотр"
    warn "исходного кода страницы, скорее всего, останется доступен."
fi

# --- История и приватный режим ----------------------------------------------
# В Firefox НЕТ прямого аналога chrome-политики AllowDeletingBrowserHistory.
# Эквивалент собирается из двух политик:
#   DisableForgetButton  — убирает кнопку "Забыть" (быстрая очистка истории)
#   DisablePrivateBrowsing — запрещает приватный режим (в нём история не пишется,
#                            иначе замок на историю обходится в один клик)
# Плюс важно НЕ включать SanitizeOnShutdown — иначе Firefox сам чистит историю
# при закрытии, что противоположно задаче. Мы его и не задаём.
#
# ЧЕСТНО: как и в Chrome, это защита уровня интерфейса. Файл places.sqlite
# лежит в профиле пользователя и доступен ему на запись — оператор с шеллом
# может стереть историю, удалив файл. Настоящий неудаляемый журнал — только
# внешний (на прокси или на уровне сети), не внутри браузера.
if [[ "$LOCK_HISTORY" == "1" ]]; then
    HISTORY_JSON='    "DisableForgetButton": true,
'
    info "кнопка быстрой очистки истории ('Забыть') будет убрана"
    warn "это НЕ мешает удалить файл истории в профиле — гарантию даёт только внешний лог"
else
    HISTORY_JSON=""
    info "удаление истории оставлено разрешённым (--no-lock-history)"
fi

if [[ "$BLOCK_PRIVATE" == "1" ]]; then
    PRIVATE_JSON='    "DisablePrivateBrowsing": true,
'
    info "приватный режим будет отключён"
else
    PRIVATE_JSON=""
    info "приватный режим оставлен доступным (--no-block-private)"
    [[ "$LOCK_HISTORY" == "1" ]] && \
        warn "замок на историю почти бесполезен без запрета приватного режима: в нём история не пишется"
fi

# --- Пароли -----------------------------------------------------------------
# PasswordManagerEnabled=false выключает встроенный менеджер целиком.
# OfferToSaveLogins=false — не предлагать сохранять. DisablePasswordReveal —
# убрать кнопку "показать" в сохранённых (защита от подглядывания, не более).
# Как и в Chrome: схему "админ владеет, оператор пользуется вслепую" браузером
# не построить — это внешний менеджер (Bitwarden) или SSO.
if [[ "$BLOCK_PASSWORDS" == "1" ]]; then
    PW_JSON='    "PasswordManagerEnabled": false,
    "OfferToSaveLogins": false,
    "DisablePasswordReveal": true,
'
    info "встроенный менеджер паролей Firefox будет отключён для всех"
else
    PW_JSON=""
    info "встроенный менеджер паролей оставлен доступным (--allow-passwords)"
fi

# --- DNS over HTTPS ---------------------------------------------------------
# Единственная настройка в этом наборе, которая соприкасается с прокси: при
# включённом DoH Firefox резолвит имена сам, по HTTPS к стороннему резолверу,
# в обход того, как имена разрешаются в вашей сети. За прокси это способно
# сломать внутренние имена и увести часть DNS мимо прокси, поэтому по
# умолчанию (auto) при обнаруженном прокси DoH просто не трогается.
case "$DOH" in
  auto)
    if [[ "$PROXY_FOUND" == "yes" ]]; then
        DOH_BLOCK=""
        info "DoH не настраивается: обнаружен прокси, разрешение имён оставлено вашей сети"
    else
        DOH_BLOCK='    "DNSOverHTTPS": {
      "Enabled": true,
      "Fallback": true,
      "Locked": false
    },
'
        info "DoH включён (прокси не обнаружен)"
    fi
    ;;
  on)
    DOH_BLOCK='    "DNSOverHTTPS": {
      "Enabled": true,
      "Fallback": true,
      "Locked": false
    },
'
    [[ "$PROXY_FOUND" == "yes" ]] && \
        warn "DoH включён принудительно при работающем прокси — внутренние имена могут перестать резолвиться"
    ;;
  off)
    DOH_BLOCK=""
    info "DoH не настраивается (--doh off)"
    ;;
  *) die "--doh принимает on, off или auto (получено: ${DOH})";;
esac

# --- WebRTC -----------------------------------------------------------------
# За прокси WebRTC — главный канал утечки реального IP: он собирает ICE-кандидаты
# напрямую через STUN по UDP, минуя прокси, и отдаёт этот адрес любому сайту
# через JavaScript. В Firefox, в отличие от Chrome, это лечится полностью.
case "$WEBRTC" in
  off)
    # media.peerconnection.enabled=false убирает RTCPeerConnection из JS
    # целиком: утечь нечему, но и видеозвонки в браузере работать перестанут.
    WEBRTC_PREFS='
      "media.peerconnection.enabled":                   { "Value": false, "Status": "locked" },'
    warn "WebRTC будет ОТКЛЮЧЁН полностью"
    warn "перестанут работать: Google Meet, Zoom в браузере, Teams web, Jitsi,"
    warn "Discord web, демонстрация экрана и любые голосовые звонки на сайтах"
    ;;
  proxy)
    # WebRTC остаётся рабочим, но обязан ходить только через прокси:
    #   proxy_only          — запрет любых кандидатов в обход прокси
    #   no_host             — не отдавать адреса локальных интерфейсов
    #   default_address_only— только один адрес основного маршрута
    WEBRTC_PREFS='
      "media.peerconnection.enabled":                   { "Value": true,  "Status": "locked" },
      "media.peerconnection.ice.proxy_only":            { "Value": true,  "Status": "locked" },
      "media.peerconnection.ice.no_host":               { "Value": true,  "Status": "locked" },
      "media.peerconnection.ice.default_address_only":  { "Value": true,  "Status": "locked" },'
    info "WebRTC разрешён только через прокси — реальный IP не утечёт"
    warn "если прокси не пропускает медиатрафик, звонки в браузере не соединятся"
    ;;
  default)
    WEBRTC_PREFS=""
    ;;
  *)
    die "--webrtc принимает off, proxy или default (получено: ${WEBRTC})"
    ;;
esac

# --- сам файл политик -------------------------------------------------------
POLICY_JSON=$(cat <<EOF
{
  "policies": {
    "_comment": "Managed by firefox-policy-deploy.sh — не редактируйте вручную",

${DEVTOOLS_JSON}

    "HttpsOnlyMode": "force_enabled",
    "SSLVersionMin": "tls1.2",
    "DisableSecurityBypass": {
      "InvalidCertificate": true,
      "SafeBrowsing": true
    },
    "EnableTrackingProtection": {
      "Value": true,
      "Locked": true,
      "Cryptomining": true,
      "Fingerprinting": true,
      "EmailTracking": true
    },
    "Cookies": {
      "Behavior": "reject-tracker-and-partition-foreign",
      "Locked": true
    },
${DOH_BLOCK}
    "ExtensionSettings": {
${EXT_JSON}
    },
    "InstallAddonsPermission": { "Default": false },
    "ExtensionUpdate": true,

    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisableFirefoxAccounts": true,
${HISTORY_JSON}${PRIVATE_JSON}    "DisablePocket": true,
    "DisableFeedbackCommands": true,
    "DisableProfileImport": true,
    "DisableSetDesktopBackground": true,
    "DisableFormHistory": true,
${PW_JSON}    "SearchSuggestEnabled": false,

    "Permissions": {
      "Location":      { "BlockNewRequests": true, "Locked": true },
      "Notifications": { "BlockNewRequests": true, "Locked": true },
      "VirtualReality":{ "BlockNewRequests": true, "Locked": true },
      "Autoplay":      { "Default": "block-audio-video", "Locked": false }
    },
    "PopupBlocking": { "Default": true, "Locked": false },

    "FirefoxHome": {
      "Pocket": false,
      "SponsoredPocket": false,
      "SponsoredTopSites": false
    },
    "FirefoxSuggest": {
      "WebSuggestions": false,
      "SponsoredSuggestions": false,
      "ImproveSuggest": false,
      "Locked": true
    },
    "UserMessaging": {
      "WhatsNew": false,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "MoreFromMozilla": false,
      "SkipOnboarding": true
    },

    "AppAutoUpdate": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",

    "Preferences": {${WEBRTC_PREFS}
      "network.predictor.enabled":            { "Value": false, "Status": "locked" },
      "network.dns.disablePrefetch":          { "Value": true,  "Status": "locked" },
      "privacy.globalprivacycontrol.enabled": { "Value": true,  "Status": "locked" },
      "browser.contentblocking.category":     { "Value": "strict", "Status": "locked" }
    }
  }
}
EOF
)

# --- проверка JSON ДО записи ------------------------------------------------
# Firefox при синтаксической ошибке просто игнорирует весь файл: политики
# молча не применятся, а вы будете уверены, что всё настроено.
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

# --- страховка от прокси ----------------------------------------------------
# Гарантия на уровне кода, а не обещания в комментарии: если в сгенерированный
# файл когда-нибудь попадёт политика Proxy или параметр network.proxy.*,
# скрипт откажется его записывать. Настройки прокси — ваши, не наши.
if command -v python3 >/dev/null 2>&1; then
    if ! printf '%s' "$POLICY_JSON" | python3 -c '
import json, sys
pol = json.load(sys.stdin).get("policies", {})
bad = []
if "Proxy" in pol:
    bad.append("политика Proxy")
for k in pol.get("Preferences", {}):
    if k.startswith("network.proxy"):
        bad.append("параметр " + k)
if bad:
    print("НАЙДЕНО: " + ", ".join(bad))
    sys.exit(1)
sys.exit(0)
'; then
        err "в файл политик попали настройки прокси — запись отменена."
        err "Этот скрипт не должен менять параметры прокси. Проверьте изменения в коде."
        exit 1
    fi
    ok "проверка пройдена: настройки прокси не затрагиваются"
fi

# --- запись -----------------------------------------------------------------
TARGETS=("$POLICY_FILE")
if [[ "$ALSO_DIST" == "1" ]]; then
    if [[ ${#DIST_DIRS[@]} -eq 0 ]]; then
        warn "--also-distribution: каталог установки Firefox не найден, пропускаю"
    else
        for d in "${DIST_DIRS[@]}"; do TARGETS+=("${d}/policies.json"); done
    fi
fi
[[ "$FF_KIND" == "snap" && "$ALSO_DIST" == "1" ]] && \
    warn "у snap-сборки файловая система только для чтения — писать в каталог установки бесполезно"

if [[ "$DRY" != "1" ]]; then
    mkdir -p "$BACKUP_DIR"
    printf '#!/usr/bin/env bash\n# Откат политик Firefox, прогон %s\nset -u\n' "$TS" > "$ROLLBACK"
fi

for dst in "${TARGETS[@]}"; do
    run mkdir -p "$(dirname "$dst")"
    if [[ -e "$dst" ]]; then
        if [[ "$DRY" == "1" ]]; then
            dry "бэкап $dst"
        else
            b="${BACKUP_DIR}/$(echo "$dst" | tr '/' '_')"
            cp -a "$dst" "$b"
            printf 'cp -a "%s" "%s" && echo "restored %s"\n' "$b" "$dst" "$dst" >> "$ROLLBACK"
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
        chown root:root "$(dirname "$dst")"; chmod 755 "$(dirname "$dst")"
        ok "записан $dst"
    fi
done

if [[ "$DRY" == "1" ]]; then
    echo; info "Dry-run — ничего не изменено. Содержимое будущего файла:"
    printf '%s\n' "$POLICY_JSON" | sed 's/^/    /'
    exit 0
fi

chmod +x "$ROLLBACK" 2>/dev/null

# --- контроль прав ----------------------------------------------------------
for dst in "${TARGETS[@]}"; do
    [[ -e "$dst" ]] || continue
    perm="$(stat -c '%a' "$dst")"; owner="$(stat -c '%U' "$dst")"
    if [[ "$owner" != "root" || "${perm:1}" =~ [2367] ]]; then
        err "$dst доступен на запись не только root (${owner} ${perm}) — политики можно обойти!"
    else
        ok "права корректны: ${owner} ${perm}"
    fi
done

# --- запущенные экземпляры --------------------------------------------------
echo
FF_USERS="$(pgrep -x 'firefox|firefox-bin|firefox-esr' 2>/dev/null \
            | while read -r p; do ps -o user= -p "$p" 2>/dev/null; done | sort -u)"
if [[ -n "$FF_USERS" ]]; then
    warn "Firefox сейчас запущен у пользователей:"
    printf '%s\n' "$FF_USERS" | sed 's/^/    /'
    warn "политики применятся только после полного закрытия и перезапуска"
else
    ok "запущенных экземпляров нет — политики применятся при следующем старте"
fi

echo
printf '%s  ГОТОВО%s\n' "${B}${G}" "$R"
printf '  Файл политик: %s\n' "$POLICY_FILE"
if [[ "$NO_UBLOCK" != "1" ]]; then
    printf '  uBlock Origin: ставится принудительно (полная версия, не Lite)\n'
else
    printf '  uBlock Origin: не ставится (--no-ublock)\n'
fi
printf '  DevTools: %s\n' "$([[ "$ALLOW_DEVTOOLS" == "1" ]] && echo 'разрешены' || echo 'ЗАПРЕЩЕНЫ')"
printf '  Очистка истории: %s\n' "$([[ "$LOCK_HISTORY" == "1" ]] && echo 'кнопка Забыть убрана' || echo 'разрешена')"
printf '  Приватный режим: %s\n' "$([[ "$BLOCK_PRIVATE" == "1" ]] && echo 'отключён' || echo 'доступен')"
printf '  Менеджер паролей: %s\n' "$([[ "$BLOCK_PASSWORDS" == "1" ]] && echo 'отключён' || echo 'доступен')"
case "$WEBRTC" in
  off)   printf '  WebRTC: отключён полностью\n';;
  proxy) printf '  WebRTC: только через прокси\n';;
  *)     printf '  WebRTC: не изменялся (по умолчанию)\n';;
esac
printf '  Прокси: не изменялся%s\n' "$([[ "$PROXY_FOUND" == "yes" ]] && echo " (обнаружен: ${PROXY_HINT})" || echo "")"
printf '  Бэкап и откат: %s\n' "$ROLLBACK"
echo
printf '  %sПроверка:%s откройте about:policies — вкладка "Активные" покажет\n' "$C" "$R"
printf '            применённое, вкладка "Ошибки" — что браузер не понял\n'
[[ "$WEBRTC" != "default" ]] && \
printf '  %sУтечка IP:%s проверьте на https://browserleaks.com/webrtc\n' "$C" "$R"
printf '  %sОткат:%s    sudo bash %s\n' "$Y" "$R" "$ROLLBACK"
echo
