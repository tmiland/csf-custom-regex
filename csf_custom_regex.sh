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
date=$(date +"%d%m%y-%H%M%S")
# Check if Virtualmin is installed
if [[ ! -f /usr/sbin/virtualmin ]]; then
  echo -e "Error: Virtualmin is not installed."
  exit 1;
fi
# enable CSF Firewall native fail2ban like support
# https://community.centminmod.com/posts/62343/
install() {
  echo "-------------------------------------------------"
  echo "install CSF Firewall native fail2ban like support"
  echo "-------------------------------------------------"
  echo
csf --profile backup backup-b4-customregex.$date
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
csf -ra
echo
echo "---------------------------------------------------"
echo "CSF Firewall native fail2ban like support installed"
echo "---------------------------------------------------"
echo
}

status() {
fgrep 'LF_CUSTOMTRIGGER' /var/log/lfd.log | tail -100
}

case "$1" in
  install )
    install
    ;;
  status )
    status
    ;;
  * )
    echo "$0 {install|status}"
    ;;
esac
