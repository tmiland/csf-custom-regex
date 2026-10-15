#!/usr/bin/env bash
#
#------------------------------------------------------------------------------#
# csf-custom-regex
#
# Installs regex.custom.pm (custom lfd regex rules) into CSF and wires up the
# log paths the rules need in /etc/csf/csf.conf.
#
# Supports Debian-family and RHEL-family systems. Virtualmin is detected
# automatically and is OPTIONAL: without it, the nginx access/error rules
# (CUSTOM3_LOG/CUSTOM4_LOG) and the standard CSF log rules stay active, while
# the Virtualmin-only rules (CUSTOM1_LOG/CUSTOM2_LOG) are left untouched.
#
# Log paths are chosen by detecting installed services and existing log files
# instead of hardcoding one distro's layout.
#
# https://github.com/tmiland/csf-custom-regex
#------------------------------------------------------------------------------#
#
# MIT License - see LICENSE
#
#------------------------------------------------------------------------------#

set -euo pipefail

VERSION='1.0.3'

CSF_CONF='/etc/csf/csf.conf'
CSF_BIN='/usr/sbin/csf'
CSF_PM_DIR='/usr/local/csf/bin'
CSF_PM_FILE="$CSF_PM_DIR/regex.custom.pm"
LFD_LOG='/var/log/lfd.log'

# Pinned to the matching release tag so the installer and the rules can never
# skew. Override with --pm-url if needed.
PM_URL="https://github.com/tmiland/csf-custom-regex/raw/v${VERSION}/regex.custom.pm"

CSF_INSTALLER_URL='https://github.com/tmiland/csf/raw/master/csf_installer.sh'
VIRTUALMIN_INSTALLER_URL='https://github.com/virtualmin/virtualmin-install/raw/master/virtualmin-install.sh'

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
opt_install=0 opt_uninstall=0 opt_check=0 opt_dryrun=0 opt_status=0
opt_follow=0 opt_yes=0 opt_with_virtualmin=0 opt_help=0 opt_version=0

usage() {
  cat <<'EOF'
Usage: csf_custom_regex.sh [ACTION] [OPTIONS]

Actions:
  -i, --install          Install/update regex.custom.pm and wire up the log
                         paths it needs in /etc/csf/csf.conf
  -u, --uninstall        Restore the previous regex.custom.pm and the csf.conf
                         backup made before the last install
  -c, --check            Report OS, detected services and log-path status
                         (read-only; exit 1 if problems are found)
  -n, --dry-run          Show what --install would change (read-only)
  -s, --status           Show recent custom rule triggers from lfd.log
  -h, --help             Show this help
  -V, --version          Show version

Options:
  -y, --yes              Non-interactive: accept defaults. Never installs
                         Virtualmin (use --with-virtualmin for that)
      --with-virtualmin  Install Virtualmin if it is not detected
      --pm-url URL       Override the regex.custom.pm download URL
  -f, --follow           With --status: follow lfd.log (tail -f)
EOF
}

SCRIPT_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    -i|--install)        opt_install=1 ;;
    -u|--uninstall)      opt_uninstall=1 ;;
    -c|--check)          opt_check=1 ;;
    -n|--dry-run)        opt_dryrun=1 ;;
    -s|--status)         opt_status=1 ;;
    -f|--follow)         opt_follow=1 ;;
    -y|--yes)            opt_yes=1 ;;
    --with-virtualmin)   opt_with_virtualmin=1 ;;
    --pm-url)
      shift
      [ $# -gt 0 ] || { echo "ERROR: --pm-url needs a URL" >&2; exit 2; }
      PM_URL="$1"
      ;;
    -h|--help)           opt_help=1 ;;
    -V|--version)        opt_version=1 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$opt_help" -eq 1 ]; then
  usage
  exit 0
fi
if [ "$opt_version" -eq 1 ]; then
  echo "csf-custom-regex $VERSION"
  exit 0
fi
if [ "$((opt_install + opt_uninstall + opt_check + opt_dryrun + opt_status))" -eq 0 ]; then
  usage >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Glob-aware existence check: works for plain paths and patterns like
# /var/log/virtualmin/*_access_log
path_exists() { compgen -G "$1" >/dev/null 2>&1; }

# Print the first existing path from the candidates, or fail.
pick_existing() {
  local c
  for c in "$@"; do
    if path_exists "$c"; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# confirm "Question?" y|n  -- returns 0 for yes, 1 for no.
# --yes and non-interactive runs take the default without prompting.
confirm() {
  local q="$1" def="${2:-n}" a
  if [ "$opt_yes" -eq 1 ] || [ ! -t 0 ]; then
    [ "$def" = y ]
    return
  fi
  while :; do
    read -r -p "$q [y/n] (default: $def): " a || a="$def"
    case "${a:-$def}" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
    esac
  done
}

require_root() {
  if [ "$EUID" -eq 0 ]; then
    return 0
  fi
  if [ -t 0 ] && have su; then
    info 'Root permissions required, re-running with su...'
    local requoted=''
    local a
    for a in ${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}; do
      requoted+=$(printf '%q ' "$a")
    done
    exec su -s "$(command -v bash)" -c "$requoted"
  fi
  die 'This action requires root permissions.'
}

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
os_field() {
  [ -r /etc/os-release ] || return 0
  sed -n "s/^$1=//p" /etc/os-release | tr -d '"'
}

detect_os() {
  local id like
  OS_PRETTY=$(os_field PRETTY_NAME)
  OS_PRETTY=${OS_PRETTY:-unknown}
  id=$(os_field ID)
  like=$(os_field ID_LIKE)
  OS_FAMILY='unknown'
  case " $id $like " in
    *debian*|*ubuntu*)                        OS_FAMILY='debian' ;;
    *rhel*|*fedora*|*centos*|*almalinux*|*rocky*) OS_FAMILY='rhel' ;;
    *" ol "*)                                 OS_FAMILY='rhel' ;;
  esac
}

detect_services() {
  has_virtualmin=0 has_nginx=0 has_webmin=0 has_exim=0 has_dovecot=0
  has_db=0 has_proftpd=0 has_bind=0 has_rsyslog=0

  if [ -f /usr/sbin/virtualmin ] || [ -d /etc/webmin/virtual-server ]; then
    has_virtualmin=1
  fi
  if have nginx; then has_nginx=1; fi
  if [ -d /etc/webmin ]; then has_webmin=1; fi
  if have exim4 || have exim; then has_exim=1; fi
  if have dovecot; then has_dovecot=1; fi
  if have mariadbd || have mysqld; then has_db=1; fi
  if have proftpd; then has_proftpd=1; fi
  if have named; then has_bind=1; fi
  if have rsyslogd; then has_rsyslog=1; fi
}

# ---------------------------------------------------------------------------
# Log path plan
# ---------------------------------------------------------------------------
setting_names=(
  CUSTOM1_LOG CUSTOM2_LOG CUSTOM3_LOG CUSTOM4_LOG CUSTOM5_LOG CUSTOM6_LOG
  CUSTOM7_LOG SSHD_LOG WEBMIN_LOG SYSLOG_LOG BIND_LOG IPTABLES_LOG
  SMTPAUTH_LOG POP3D_LOG IMAPD_LOG FTPD_LOG HTACCESS_LOG MODSEC_LOG
)
declare -A setting_value=()
declare -A setting_note=()
problems=()
notes=()

# plan_skip NAME REASON [problem]
plan_skip() {
  setting_note["$1"]="$2"
  if [ "${3:-note}" = problem ]; then
    problems+=("$1: $2")
  fi
}

build_plan() {
  local p
  setting_value=()
  setting_note=()
  problems=()
  notes=()

  # -- Virtualmin (optional) ------------------------------------------------
  if [ "$has_virtualmin" -eq 1 ]; then
    setting_value[CUSTOM1_LOG]='/var/log/virtualmin/*_access_log'
    setting_value[CUSTOM2_LOG]='/var/log/virtualmin/*_error_log'
    setting_value[HTACCESS_LOG]='/var/log/virtualmin/*_access_log'
    setting_value[MODSEC_LOG]='/var/log/virtualmin/*_error_log'
  else
    plan_skip CUSTOM1_LOG 'Virtualmin not detected'
    plan_skip CUSTOM2_LOG 'Virtualmin not detected'
    plan_skip HTACCESS_LOG 'Virtualmin not detected'
    plan_skip MODSEC_LOG 'Virtualmin not detected'
    notes+=('Virtualmin not detected: the Virtualmin-only rules (CUSTOM1_LOG/CUSTOM2_LOG) stay inactive; nginx coverage comes from CUSTOM3_LOG/CUSTOM4_LOG.')
  fi

  # -- nginx (paths are identical on both families) --------------------------
  if [ "$has_nginx" -eq 1 ]; then
    setting_value[CUSTOM3_LOG]='/var/log/nginx/access.log'
    setting_value[CUSTOM4_LOG]='/var/log/nginx/error.log'
    if ! path_exists /var/log/nginx/access.log; then
      notes+=('nginx detected but /var/log/nginx/access.log does not exist yet; it should appear once nginx serves requests.')
    fi
  else
    plan_skip CUSTOM3_LOG 'nginx not detected'
    plan_skip CUSTOM4_LOG 'nginx not detected'
  fi

  # -- database error log ----------------------------------------------------
  if [ "$has_db" -eq 1 ]; then
    if p=$(pick_existing /var/log/mysql/error.log /var/log/mariadb/mariadb.log \
                       /var/log/mariadb/error.log /var/log/mysqld.log); then
      setting_value[CUSTOM5_LOG]="$p"
    else
      plan_skip CUSTOM5_LOG 'MariaDB/MySQL detected but no error log found' problem
    fi
  else
    plan_skip CUSTOM5_LOG 'no MariaDB/MySQL server detected'
  fi

  # -- dovecot / exim --------------------------------------------------------
  if [ "$has_dovecot" -eq 1 ]; then
    if p=$(pick_existing /var/log/dovecot.log /var/log/maillog /var/log/mail.log); then
      setting_value[CUSTOM6_LOG]="$p"
    else
      plan_skip CUSTOM6_LOG 'dovecot detected but no log found' problem
    fi
  else
    plan_skip CUSTOM6_LOG 'dovecot not detected'
  fi

  if [ "$has_exim" -eq 1 ]; then
    if p=$(pick_existing /var/log/exim4/rejectlog /var/log/exim/rejectlog \
                       /var/log/exim_rejectlog); then
      setting_value[CUSTOM7_LOG]="$p"
    else
      plan_skip CUSTOM7_LOG 'exim detected but no rejectlog found' problem
    fi
  else
    plan_skip CUSTOM7_LOG 'exim not detected'
  fi

  # -- ssh / webmin ----------------------------------------------------------
  if p=$(pick_existing /var/log/auth.log /var/log/secure); then
    setting_value[SSHD_LOG]="$p"
  else
    plan_skip SSHD_LOG 'no auth.log or secure log found' problem
  fi

  if [ "$has_webmin" -eq 1 ]; then
    if p=$(pick_existing /var/log/auth.log /var/log/secure); then
      setting_value[WEBMIN_LOG]="$p"
    else
      plan_skip WEBMIN_LOG 'webmin detected but no auth log found' problem
    fi
  else
    plan_skip WEBMIN_LOG 'webmin not detected'
  fi

  # -- syslog ----------------------------------------------------------------
  if p=$(pick_existing /var/log/syslog /var/log/messages); then
    setting_value[SYSLOG_LOG]="$p"
  else
    plan_skip SYSLOG_LOG 'no /var/log/syslog or /var/log/messages found' problem
    notes+=('No file-based syslog detected: the system may be journald-only. Install rsyslog (apt install rsyslog / dnf install rsyslog) for SYSLOG, SSHD and SMTPAUTH rule coverage.')
  fi

  if [ "$has_bind" -eq 1 ]; then
    if p=$(pick_existing /var/log/syslog /var/log/messages); then
      setting_value[BIND_LOG]="$p"
    else
      plan_skip BIND_LOG 'bind detected but no syslog found' problem
    fi
  else
    plan_skip BIND_LOG 'bind not detected'
  fi

  if p=$(pick_existing /var/log/messages /var/log/kern.log /var/log/syslog); then
    setting_value[IPTABLES_LOG]="$p"
  else
    plan_skip IPTABLES_LOG 'no kernel/messages log found' problem
  fi

  # -- mail auth -------------------------------------------------------------
  if p=$(pick_existing /var/log/mail.log /var/log/maillog \
                     /var/log/exim4/mainlog /var/log/exim/mainlog); then
    setting_value[SMTPAUTH_LOG]="$p"
  else
    plan_skip SMTPAUTH_LOG 'no mail log found'
  fi

  if p=$(pick_existing /var/log/mail.log /var/log/maillog /var/log/dovecot.log); then
    setting_value[POP3D_LOG]="$p"
    setting_value[IMAPD_LOG]="$p"
  else
    plan_skip POP3D_LOG 'no mail log found'
    plan_skip IMAPD_LOG 'no mail log found'
  fi

  # -- ftp -------------------------------------------------------------------
  if [ "$has_proftpd" -eq 1 ]; then
    if p=$(pick_existing /var/log/proftpd/proftpd.log /var/log/secure /var/log/messages); then
      setting_value[FTPD_LOG]="$p"
    else
      plan_skip FTPD_LOG 'proftpd detected but no log found' problem
    fi
  else
    plan_skip FTPD_LOG 'proftpd not detected'
  fi
}

# ---------------------------------------------------------------------------
# csf.conf access
# ---------------------------------------------------------------------------
conf_get() {
  [ -r "$CSF_CONF" ] || return 0
  sed -n "s/^$1 = \"\(.*\)\"$/\1/p" "$CSF_CONF"
}

conf_set() {
  local name="$1" value="$2" escaped
  escaped=$(printf '%s' "$value" | sed -e 's/[&|\\]/\\&/g')
  sed -i "s|^${name} = .*|${name} = \"${escaped}\"|" "$CSF_CONF"
  if [ "$(conf_get "$name")" != "$value" ]; then
    die "failed to update $name in $CSF_CONF"
  fi
}

print_plan() {
  local name current planned
  printf '%-15s %-32s %s\n' 'SETTING' 'CURRENT' 'PLANNED'
  for name in "${setting_names[@]}"; do
    current=$(conf_get "$name")
    current=${current:-<none>}
    if [ -n "${setting_value[$name]:-}" ]; then
      planned="${setting_value[$name]}"
      if [ "$planned" = "${current}" ]; then
        planned="$planned (unchanged)"
      fi
    else
      planned="SKIP - ${setting_note[$name]:-not detected}"
    fi
    printf '%-15s %-32s %s\n' "$name" "$current" "$planned"
  done
}

apply_plan() {
  local name current value changed=0
  for name in "${setting_names[@]}"; do
    value="${setting_value[$name]:-}"
    [ -n "$value" ] || continue
    current=$(conf_get "$name")
    if [ "$current" = "$value" ]; then
      continue
    fi
    conf_set "$name" "$value"
    printf '  %-15s %s -> %s\n' "$name" "${current:-<none>}" "$value"
    changed=$((changed + 1))
  done
  if [ "$changed" -eq 0 ]; then
    info '  No csf.conf changes needed.'
  fi
}

# ---------------------------------------------------------------------------
# Installers for the dependencies
# ---------------------------------------------------------------------------
install_csf() {
  # Run in a subshell: the upstream installer calls exit, which would
  # otherwise terminate this script before the install steps below.
  if have curl; then
    # shellcheck disable=SC1090
    ( set -- -i; source <(curl -sSLf "$CSF_INSTALLER_URL") )
  elif have wget; then
    # shellcheck disable=SC1090
    ( set -- -i; source <(wget -qO - "$CSF_INSTALLER_URL") )
  else
    die 'curl or wget is required.'
  fi
}

install_virtualmin() {
  # Subshell for the same reason as install_csf.
  if have curl; then
    # shellcheck disable=SC1090
    ( set -- --minimal --bundle LEMP --extra webmin-postgresql,postgresql,postgresql-client --include PostgreSQL; source <(curl -sSLf "$VIRTUALMIN_INSTALLER_URL") )
  elif have wget; then
    # shellcheck disable=SC1090
    ( set -- --minimal --bundle LEMP --extra webmin-postgresql,postgresql,postgresql-client --include PostgreSQL; source <(wget -qO - "$VIRTUALMIN_INSTALLER_URL") )
  else
    die 'curl or wget is required.'
  fi
}

# ---------------------------------------------------------------------------
# regex.custom.pm
# ---------------------------------------------------------------------------
download_pm() {
  local tmp
  tmp=$(mktemp) || die 'mktemp failed'
  if have curl; then
    curl -sSLf "$PM_URL" -o "$tmp" || { rm -f "$tmp"; die "download failed: $PM_URL"; }
  elif have wget; then
    wget -qO "$tmp" "$PM_URL" || { rm -f "$tmp"; die "download failed: $PM_URL"; }
  else
    die 'curl or wget is required.'
  fi
  if [ -n "${CSF_PM_SHA256:-}" ]; then
    printf '%s  %s\n' "$CSF_PM_SHA256" "$tmp" | sha256sum -c - >/dev/null 2>&1 \
      || { rm -f "$tmp"; die 'regex.custom.pm checksum mismatch (CSF_PM_SHA256)'; }
  fi
  perl -c "$tmp" >/dev/null 2>&1 \
    || { rm -f "$tmp"; die 'downloaded regex.custom.pm failed the perl syntax check'; }
  printf '%s\n' "$tmp"
}

install_pm() {
  local tmp ts
  ts=$(date +%d%m%y-%H%M%S)
  tmp=$(download_pm)
  if [ -f "$CSF_PM_FILE" ]; then
    cp -a "$CSF_PM_FILE" "${CSF_PM_FILE}.bak.${ts}"
    info "  Backed up existing regex.custom.pm to ${CSF_PM_FILE}.bak.${ts}"
  fi
  mv "$tmp" "$CSF_PM_FILE"
  info "  Installed $CSF_PM_FILE"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
detect_all() {
  detect_os
  detect_services
  build_plan
}

do_check() {
  detect_all
  printf 'OS:        %s [%s family]\n' "$OS_PRETTY" "$OS_FAMILY"
  if [ -f "$CSF_BIN" ]; then
    local csf_version=''
    if [ -r /usr/local/csf/version.txt ]; then
      csf_version=$(sed -n '1p' /usr/local/csf/version.txt)
    fi
    printf 'CSF:       installed%s\n' "${csf_version:+ ($csf_version)}"
  else
    printf 'CSF:       NOT installed\n'
    problems+=('CSF is not installed')
  fi
  printf 'Services:  virtualmin:%s nginx:%s webmin:%s exim:%s dovecot:%s db:%s proftpd:%s bind:%s rsyslog:%s\n' \
    "$has_virtualmin" "$has_nginx" "$has_webmin" "$has_exim" "$has_dovecot" \
    "$has_db" "$has_proftpd" "$has_bind" "$has_rsyslog"
  echo
  print_plan

  if [ "${#notes[@]}" -gt 0 ]; then
    echo
    echo 'Notes:'
    local n
    for n in ${notes[@]+"${notes[@]}"}; do
      printf '  - %s\n' "$n"
    done
  fi
  if [ "${#problems[@]}" -gt 0 ]; then
    echo
    echo 'Problems:'
    local p
    for p in ${problems[@]+"${problems[@]}"}; do
      printf '  - %s\n' "$p"
    done
    exit 1
  fi
  echo
  info 'No problems found.'
}

do_dryrun() {
  detect_all
  printf 'OS:        %s [%s family]\n' "$OS_PRETTY" "$OS_FAMILY"
  if [ -f "$CSF_BIN" ]; then
    printf 'CSF:       installed\n'
  else
    printf 'CSF:       NOT installed (--install would offer to install it)\n'
  fi
  echo
  print_plan
  echo
  info "regex.custom.pm would be downloaded from:"
  info "  $PM_URL"
  info 'Dry run: no changes made.'
}

do_install() {
  local ts
  require_root

  detect_os
  detect_services

  # CSF is the only hard requirement.
  if [ ! -f "$CSF_BIN" ]; then
    if confirm 'CSF is not installed. Install CSF now?' y; then
      install_csf
      if [ ! -f "$CSF_BIN" ]; then
        die 'CSF installation did not complete.'
      fi
    else
      die 'CSF is required, aborting.'
    fi
  fi
  [ -r "$CSF_CONF" ] || die "$CSF_CONF not found - is CSF installed correctly?"

  # Virtualmin is optional.
  if [ "$has_virtualmin" -eq 0 ]; then
    local vm_attempted=0
    if [ "$opt_with_virtualmin" -eq 1 ]; then
      vm_attempted=1
      install_virtualmin
      detect_services
    elif [ "$opt_yes" -eq 0 ] && [ -t 0 ]; then
      if confirm 'Virtualmin is not installed. Install Virtualmin now? (optional: without it, the Virtualmin-only web rules stay inactive)' n; then
        vm_attempted=1
        install_virtualmin
        detect_services
      fi
    fi
    if [ "$vm_attempted" -eq 1 ] && [ "$has_virtualmin" -eq 0 ]; then
      warn 'Virtualmin installation did not complete - continuing without the Virtualmin-only rules.'
    fi
  fi

  build_plan

  echo
  info 'Planned log path changes:'
  print_plan

  echo
  ts=$(date +%d%m%y-%H%M%S)
  cp -a "$CSF_CONF" "${CSF_CONF}.bak.${ts}"
  info "Backed up $CSF_CONF to ${CSF_CONF}.bak.${ts}"
  "$CSF_BIN" --profile backup "b4_customregex_${ts}" >/dev/null 2>&1 \
    || warn 'csf profile backup failed (continuing)'

  echo
  info 'Installing regex.custom.pm:'
  install_pm

  echo
  info 'Applying log path changes:'
  apply_plan

  echo
  info 'Restarting CSF/lfd:'
  local csf_ra_out csf_ra_rc=0
  csf_ra_out=$("$CSF_BIN" -ra 2>&1) || csf_ra_rc=$?
  printf '%s\n' "$csf_ra_out"
  if [ "$csf_ra_rc" -ne 0 ]; then
    warn "csf -ra exited with status $csf_ra_rc - check the output above."
    warn "Restore with: csf --profile list (then: csf --profile restore <name>)"
    warn "or: cp ${CSF_CONF}.bak.${ts} ${CSF_CONF}"
  fi

  echo
  info 'Done. Active custom log slots:'
  local name
  for name in "${setting_names[@]}"; do
    if [ -n "${setting_value[$name]:-}" ]; then
      printf '  %-15s %s\n' "$name" "${setting_value[$name]}"
    fi
  done
  echo
  info 'Show rule triggers with: csf_custom_regex.sh --status'
}

# Print the newest file in DIR matching NAME_GLOB (by mtime), or nothing.
newest_file() {
  local dir="$1" glob="$2"
  find "$dir" -maxdepth 1 -name "$glob" -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn | sed -n '1p' | cut -d' ' -f2- || true
}

do_uninstall() {
  require_root
  local pm_backup conf_backup
  pm_backup=$(newest_file "$CSF_PM_DIR" 'regex.custom.pm.bak.*')
  conf_backup=$(newest_file "$(dirname "$CSF_CONF")" 'csf.conf.bak.*')

  if [ -n "$pm_backup" ] && [ -f "$pm_backup" ]; then
    cp -a "$pm_backup" "$CSF_PM_FILE"
    info "Restored $CSF_PM_FILE from $pm_backup"
  else
    warn "No regex.custom.pm backup found in $CSF_PM_DIR - leaving it in place."
  fi

  if [ -n "$conf_backup" ] && [ -f "$conf_backup" ]; then
    cp -a "$conf_backup" "$CSF_CONF"
    info "Restored $CSF_CONF from $conf_backup"
  else
    warn "No csf.conf backup found - leaving $CSF_CONF in place."
  fi

  if [ -f "$CSF_BIN" ]; then
    "$CSF_BIN" -ra
  fi

  echo
  info 'Done. Full configuration profile backups (made before each install) can'
  info 'be listed and restored with:'
  info '  csf --profile list'
  info '  csf --profile restore <name>'
}

do_status() {
  [ -r "$LFD_LOG" ] || die "cannot read $LFD_LOG"
  if [ "$opt_follow" -eq 1 ]; then
    info "Following $LFD_LOG (Ctrl-C to stop)..."
    tail -f "$LFD_LOG" | grep --line-buffered 'LF_CUSTOMTRIGGER'
  else
    local matches
    matches=$(grep 'LF_CUSTOMTRIGGER' "$LFD_LOG" | tail -n 20 || true)
    if [ -z "$matches" ]; then
      info 'No custom rule triggers found yet.'
    else
      printf '%s\n' "$matches"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if [ "$opt_check" -eq 1 ]; then
  do_check
elif [ "$opt_dryrun" -eq 1 ]; then
  do_dryrun
elif [ "$opt_install" -eq 1 ]; then
  do_install
elif [ "$opt_uninstall" -eq 1 ]; then
  do_uninstall
elif [ "$opt_status" -eq 1 ]; then
  do_status
fi
