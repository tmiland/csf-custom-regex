#!/usr/bin/env bash

## Author: Tommy Miland (@tmiland) - Copyright (c) 2021
#------------------------------------------------------------------------------#
#
# MIT License
#
# Copyright (c) 2020 Tommy Miland
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#------------------------------------------------------------------------------#
## Uncomment for debugging purpose
#set -o errexit
#set -o pipefail
#set -o nounset
#set -o xtrace
cd "$(dirname "$0")" || exit
CURRDIR=$(pwd)
SCRIPT_FILENAME=$(basename "$0")
cd - > /dev/null || exit
sfp=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || greadlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
if [ -z "$sfp" ]; then sfp=${BASH_SOURCE[0]}; fi
SCRIPT_DIR=$(dirname "${sfp}")
date=$(date +"%d%m%y-%H%M%S")

# Make sure that the script runs with root permissions
  if [[ "$EUID" != 0 ]]; then
    echo -e "This action needs root permissions."
    echo -e "Please enter your root password...";
    cd "$CURRDIR" || exit
    su -s "$(which bash)" -c "./$SCRIPT_FILENAME $1"
    cd - > /dev/null || exit
    exit 0; 
  fi

csf_installer_url=https://github.com/tmiland/csf/raw/master/csf_installer.sh
install_csf() {
  csf_args=${*:-"-i"}
  shift
  if [[ $(command -v 'curl') ]]; then
    set -- $csf_args
    # shellcheck disable=SC1090
    source <(curl -sSLf $csf_installer_url)
  elif [[ $(command -v 'wget') ]]; then
    set -- $csf_args
    # shellcheck disable=SC1090
    . <(wget -qO - $csf_installer_url)
  else
    echo -e "This script requires curl or wget.\nProcess aborted"
    exit 0
  fi
}

virtualmin_installer_url=https://github.com/virtualmin/virtualmin-install/raw/master/virtualmin-install.sh
install_virtualmin() {
  virtualmin_args=${*:-"--minimal --bundle LEMP"}
  shift
  if [[ $(command -v 'curl') ]]; then
    set -- $virtualmin_args
    # shellcheck disable=SC1090
    source <(curl -sSLf $virtualmin_installer_url)
  elif [[ $(command -v 'wget') ]]; then
    set -- $virtualmin_args
    # shellcheck disable=SC1090
    . <(wget -qO - $virtualmin_installer_url)
  else
    echo -e "This script requires curl or wget.\nProcess aborted"
    exit 0
  fi
}

# Check if Virtualmin is installed
if [[ ! -f /usr/sbin/virtualmin ]]; then
  echo -e "Virtualmin is not installed."
  while [[ $install_virtualmin != "y" && $install_virtualmin != "n" ]]; do
    read -p "Do you want to install Virtualmin? [y/n]: " install_virtualmin
  done

  while true; do
    case $install_virtualmin in
      [Yy]* )
        install_virtualmin
        break
        ;;
      [Nn]* ) 
        break 
        ;;
    esac
  done
elif [[ ! -f /usr/sbin/csf ]]; then
  echo -e "CSF Firewall is not installed."
  while [[ $install_csf != "y" && $install_csf != "n" ]]; do
    read -p "Do you want to install CSF? [y/n]: " install_csf
  done

  while true; do
    case $install_csf in
      [Yy]* )
        install_csf
        break
        ;;
      [Nn]* ) 
        break 
        ;;
    esac
  done
fi

# enable CSF Firewall native fail2ban like support
# https://community.centminmod.com/posts/62343/
install() {
  echo "-------------------------------------------------"
  echo "install CSF Firewall custom regex support"
  echo "-------------------------------------------------"
  echo
/usr/sbin/csf --profile backup backup-b4-customregex.$date
cp -a /usr/local/csf/bin/regex.custom.pm /usr/local/csf/bin/regex.custom.pm.bak.$date
egrep 'CUSTOM1_LOG|CUSTOM2_LOG|CUSTOM3_LOG|CUSTOM4_LOG' /etc/csf/csf.conf
sed -i "s|CUSTOM1_LOG = .*|CUSTOM1_LOG = \"/var/log/virtualmin/\*_access_log\"|" /etc/csf/csf.conf
sed -i "s|CUSTOM2_LOG = .*|CUSTOM2_LOG = \"/var/log/virtualmin/\*_error_log\"|" /etc/csf/csf.conf
sed -i "s|CUSTOM3_LOG = .*|CUSTOM3_LOG = \"/var/log/nginx/access.log\"|" /etc/csf/csf.conf
sed -i "s|CUSTOM4_LOG = .*|CUSTOM4_LOG = \"/var/log/nginx/error.log\"|" /etc/csf/csf.conf
egrep 'CUSTOM1_LOG|CUSTOM2_LOG|CUSTOM3_LOG|CUSTOM4_LOG' /etc/csf/csf.conf

egrep 'HTACCESS_LOG|MODSEC_LOG|SSHD_LOG|FTPD_LOG|SMTPAUTH_LOG|IPTABLES_LOG|BIND_LOG|SYSLOG_LOG|WEBMIN_LOG' /etc/csf/csf.conf
sed -i "s|HTACCESS_LOG = .*|HTACCESS_LOG = \"/var/log/virtualmin/\*_error_log\"|" /etc/csf/csf.conf
sed -i "s|MODSEC_LOG   = .*|MODSEC_LOG = \"/var/log/virtualmin/\*_error_log\"|" /etc/csf/csf.conf
sed -i "s|SSHD_LOG     = .*|SSHD_LOG = \"/var/log/auth.log\"|" /etc/csf/csf.conf
sed -i "s|FTPD_LOG     = .*|FTPD_LOG = \"/var/log/proftpd/proftpd.log\"|" /etc/csf/csf.conf
sed -i "s|SMTPAUTH_LOG = .*|SMTPAUTH_LOG = \"/var/log/mail.log\"|" /etc/csf/csf.conf
sed -i "s|IPTABLES_LOG = .*|IPTABLES_LOG = \"/var/log/messages\"|" /etc/csf/csf.conf
sed -i "s|BIND_LOG     = .*|BIND_LOG = \"/var/log/syslog\"|" /etc/csf/csf.conf
sed -i "s|SYSLOG_LOG   = .*|SYSLOG_LOG = \"/var/log/syslog\"|" /etc/csf/csf.conf
sed -i "s|WEBMIN_LOG   = .*|WEBMIN_LOG = \"/var/log/auth.log\"|" /etc/csf/csf.conf
egrep 'HTACCESS_LOG|MODSEC_LOG|SSHD_LOG|FTPD_LOG|SMTPAUTH_LOG|IPTABLES_LOG|BIND_LOG|SYSLOG_LOG|WEBMIN_LOG' /etc/csf/csf.conf
wget -O /usr/local/csf/bin/regex.custom.pm https://github.com/tmiland/csf-custom-regex/raw/master/regex.custom.pm
/usr/sbin/csf -ra
echo
echo "---------------------------------------------------"
echo "CSF Firewall custom regex support installed"
echo "---------------------------------------------------"
echo
}

status() {
  echo "---------------------------------------"
  echo "Latest Banned IP Addresses:"
  tail -f /var/log/lfd.log | grep 'LF_CUSTOMTRIGGER'
}

case "$1" in
  --install|-i)
    install
    ;;
  --status|-s)
    status
    ;;
  *)
    echo "$0 {--install|-i|--status|-s}"
    ;;
esac
