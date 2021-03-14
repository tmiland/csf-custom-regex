#!/usr/bin/env bash

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
