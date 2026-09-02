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
    --no-ublock)         NO_UBLOCK=1;;
    --also-distribution) ALSO_DIST=1;;
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
    "DNSOverHTTPS": {
      "Enabled": true,
      "Fallback": true,
      "Locked": false
    },

    "ExtensionSettings": {
${EXT_JSON}
    },
    "InstallAddonsPermission": { "Default": false },
    "ExtensionUpdate": true,

    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisableFirefoxAccounts": true,
    "DisablePocket": true,
    "DisableFeedbackCommands": true,
    "DisableProfileImport": true,
    "DisableSetDesktopBackground": true,
    "DisableFormHistory": true,
    "DisablePasswordReveal": true,
    "PasswordManagerEnabled": false,
    "OfferToSaveLogins": false,
    "SearchSuggestEnabled": false,

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

    "Preferences": {
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
printf '  Бэкап и откат: %s\n' "$ROLLBACK"
echo
printf '  %sПроверка:%s откройте about:policies — вкладка "Активные" покажет\n' "$C" "$R"
printf '            применённое, вкладка "Ошибки" — что браузер не понял\n'
printf '  %sОткат:%s    sudo bash %s\n' "$Y" "$R" "$ROLLBACK"
echo
