#!/usr/bin/perl
###############################################################################
# Copyright 2006-2018, Way to the Web Limited
# URL: http://www.configserver.com
# Email: sales@waytotheweb.com
###############################################################################

sub custom_line {
        my $line = shift;
        my $lgfile = shift;

# Do not edit before this point
###############################################################################
#
# Custom regex matching can be added to this file without it being overwritten
# by csf upgrades. The format is slightly different to regex.pm to cater for
# additional parameters. You need to specify the log file that needs to be
# scanned for log line matches in csf.conf under CUSTOMx_LOG. You can scan up
# to 9 custom logs (CUSTOM1_LOG .. CUSTOM9_LOG)
#
# The regex matches in this file will supercede the matches in regex.pm
#
# Example:
#       if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /^\S+\s+\d+\s+\S+ \S+ pure-ftpd: \(\?\@(\d+\.\d+\.\d+\.\d+)\) \[WARNING\] Authentication failed for user/)) {
#               return ("Failed myftpmatch login from",$1,"myftpmatch","5","20,21","1","0");
#       }
#
# The return values from this example are as follows:
#
# "Failed myftpmatch login from" = text for custom failure message
# $1 = the offending IP address
# "myftpmatch" = a unique identifier for this custom rule, must be alphanumeric and have no spaces
# "5" = the trigger level for blocking
# "20,21" = the ports to block the IP from in a comma separated list, only used if LF_SELECT enabled. To specify the protocol use 53;udp,53;tcp
# "1" = n/temporary (n = number of seconds to temporarily block) or 1/permanant IP block, only used if LF_TRIGGER is disabled
# "0" = whether to trigger Cloudflare block if CF_ENABLE is set. "0" = disable, "1" = enable

# rule sets inspired by ethanpill's work at https://community.centminmod.com/posts/49893/

# /var/log/virtualmin/*_access_log
# Nginx 444  (Default: 5 errors bans for 24 hours)
if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD].*(\s444\s)/)) {
    return ("Nginx 444",$1,"nginx_444","5","80,443","86400","0");
}

# /var/log/nginx/access.log
# Nginx 444  (Default: 5 errors bans for 24 hours)
if (($globlogs{CUSTOM3_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD].*(\s444\s)/)) {
    return ("Nginx 444",$1,"nginx_444","5","80,443","86400","0");
}

# /var/log/virtualmin/*_error_log
# NginX security rules trigger (Default: 40 errors bans for 24 hours)
if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /.*access forbidden by rule, client: (\S+).*/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_security","40","80,443","86400","0");
}

# /var/log/nginx/localhost.error.log
# NginX security rules trigger (Default: 40 errors bans for 24 hours)
if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*access forbidden by rule, client: (\S+).*/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_security","40","80,443","86400","0");
}

# /var/log/virtualmin/*_error_log
# NginX 404 errors (Default: 50 errors bans for 24 hours)
if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /.*No such file or directory\), client: (\S+),.*/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_404s","50","80,443","86400","0");
}

# /var/log/nginx/localhost.error.log
# NginX 404 errors (Default: 50 errors bans for 24 hours)
if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*No such file or directory\), client: (\S+),.*/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_404s","50","80,443","86400","0");
}

# /var/log/virtualmin/*_access_log
#Trying to download htaccess or htpasswd  (Default: 2 error bans for 24 hours)
if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /.*\.(htpasswd|htaccess).*client: (\S+),.*GET/)) {
    return ("Trying to download .ht files",$1,"nginx_htfiles","2","80,443","86400","0");
}

# /var/log/nginx/access.log
#Trying to download htaccess or htpasswd  (Default: 2 error bans for 24 hours)
if (($globlogs{CUSTOM3_LOG}{$lgfile}) and ($line =~ /.*\.(htpasswd|htaccess).*client: (\S+),.*GET/)) {
    return ("Trying to download .ht files",$1,"nginx_htfiles","2","80,443","86400","0");
}

# Wordpress fail2ban plugin https://wordpress.org/plugins/wp-fail2ban-redux/
# (Default: 2 errors bans for 24 hours)
if (($globlogs{SYSLOG_LOG}{$lgfile}) and ($line =~ /.*Authentication attempt for unknown user .* from (.*)\n/)) {
    return ("Wordpress unknown user from",$1,"fail2ban_unknownuser","2","80,443","86400","0");
}

# Wordpress fail2ban plugin https://wordpress.org/plugins/wp-fail2ban-redux/
# (Default: 2 errors bans for 24 hours)
if (($globlogs{SYSLOG_LOG}{$lgfile}) and ($line =~ /.*Blocked user enumeration attempt from (.*)\n/)) {
    return ("WordPress user enumeration attempt from",$1,"fail2ban_userenum","2","80,443","86400","0");
}

# Wordpress fail2ban plugin https://wordpress.org/plugins/wp-fail2ban-redux/
# (Default: 2 errors bans for 24 hours)
if (($globlogs{SYSLOG_LOG}{$lgfile}) and ($line =~ /.*Pingback error .* generated from (.*)\n/)) {
    return ("WordPress pingback error",$1,"fail2ban_pingback","2","80,443","86400","0");
}

# Wordpress fail2ban plugin https://wordpress.org/plugins/wp-fail2ban-redux/
# (Default: 2 errors bans for 24 hours)
if (($globlogs{SYSLOG_LOG}{$lgfile}) and ($line =~ /.*Spammed comment from (.*)\n/)) {
    return ("WordPress spam comments from",$1,"fail2ban_spam","2","80,443","86400","0");
}

# Wordpress fail2ban plugin https://wordpress.org/plugins/wp-fail2ban-redux/
# (Default: 2 errors bans for 24 hours)
if (($globlogs{SYSLOG_LOG}{$lgfile}) and ($line =~ /.*XML-RPC multicall authentication failure (.*)\n/)) {
    return ("WordPress XML-RPC multicall fail from",$1,"fail2ban_xmlrpc","5","80,443","86400","0");
}

# /var/log/virtualmin/*_error_log
# https://community.centminmod.com/posts/74546/
# Nginx connection limit rule trigger (Default: 30 errors bans for 60mins)
if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /.*limiting connections by zone .*, client: (\S+),(.*)/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_conn_limit","30","80,443","3600","0");
}

# /var/log/nginx/localhost.error.log
# https://community.centminmod.com/posts/74546/
# Nginx connection limit rule trigger (Default: 30 errors bans for 60mins)
if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*limiting connections by zone .*, client: (\S+),(.*)/)) {
    return ("NGINX Security rule triggered from",$1,"nginx_conn_limit_localhost","30","80,443","3600","0");
}

# Block brute force failed SASL attempts. Debian, dovecot / postfix server.
# Block an IP that has 5 failed SASL login attempts
# if (($globlogs{SMTPAUTH_LOG} {$lgfile}) and ($line =~ /^\S+\s+\d+\s+\S+ \S+ postfix\/smtpd\[\d+\]: warning:.*\[(\d+\.\d+\.\d+\.\d+)\]: SASL [A-Z]*? authentication failed/)) {
#     return ("Failed SASL login from",$1,"mysaslmatch","5","25,465,587","1");
# }
# Source: https://github.com/sillsdev/ops-ansible-common-roles/blob/master/csf_config/files/regex.custom.pm
# postfix/smtpd UNKNOWN from unknown
if (($lgfile eq $config{SMTPAUTH_LOG}) and ($line =~ /postfix\/smtpd[^U]*UNKNOWN from unknown\[(\d+\.\d+\.\d+\.\d+)\]/)) {
    return ("UNKNOWN from unknown from",$1,"postfix_unknown","2","25,587","3600");
}

# postfix/smtpd lost connection after AUTH
if (($lgfile eq $config{SMTPAUTH_LOG}) and ($line =~ /postfix\/smtpd\[\d+\]: lost connection after AUTH from [^\[]+\[(\d+\.\d+\.\d+\.\d+)\]/)) {
    return ("lost connection after AUTH from",$1,"postfix_lost","4","25,587","3600");
}

#Postfix SMTP AUTH
# Source: https://github.com/rlunar/Ajenti/blob/20a9d53a0110dc8cc90eccd9c1e9706d0b050c75/csf/regex.pm#L310-L314
if (($config{LF_SMTPAUTH}) and ($globlogs{SMTPAUTH_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ postfix\/smtpd(?:\[\d+\])?: warning: \S+\[(\S+)\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed/)) {
	$ip = $2; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SMTP AUTH login from","$ip","smtpauth")} else {return}
}

# # postfix discard php header check
# if (($lgfile eq $config{SMTPAUTH_LOG}) and ($line =~ /postfix\/cleanup[^d]*discard: header X-PHP-Script: [^f]+for (\d+\.\d+\.\d+\.\d+)/)) {
#     return ("discard via php header check from ",$1,"postfix_discard","2","25,587,80","3600");
# }
# 
# # postfix warn php header check
# if (($lgfile eq $config{SMTPAUTH_LOG}) and ($line =~ /postfix\/cleanup[^w]+warning: header X-PHP-Script: ([^f]+)for (\d+\.\d+\.\d+\.\d+)/)) {
#     return ("warn via php header check from ",$2,"postfix_warn_php","2","25,587,80","3600");
# }

# SMTP Hostname unknown
# Source: https://community.keyhelp.de/viewtopic.php?t=9260
# if (($lgfile eq $config{SMTPAUTH_LOG}) and ($line =~ /^\S+\s+\d+\s+\S+ \S+ postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from \S+\[(\S+)\]: 450 4\.7\.25 Client host rejected: cannot find your hostname/)) {
#     return ("Client host rejected: hostname not found",$1,"smtphostname","4","","86400","0");
# }

#BIND
# Source: https://github.com/rlunar/Ajenti/blob/20a9d53a0110dc8cc90eccd9c1e9706d0b050c75/csf/regex.pm#L218-L222
if (($config{LF_BIND}) and ($globlogs{BIND_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ named\[\d+\]: client (\S+)\#\d+(\s\(\S+\))?\:( view external\:)? (update|zone transfer|query \(cache\)) \'[^\']*\' denied$/)) {
      $ip = $2; $acc = ""; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("bind triggered by","$ip|$acc","bind")} else {return}
}

#webmin
# Source: https://github.com/rlunar/Ajenti/blob/20a9d53a0110dc8cc90eccd9c1e9706d0b050c75/csf/regex.pm#L242-L246
if (($config{LF_WEBMIN}) and ($globlogs{WEBMIN_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ webmin\[\d+\]: Invalid login as (\S+) from (\S+)/)) {
      $ip = $3; $acc = $2; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed Webmin login from","$ip|$acc","webmin")} else {return}
}

#proftpd
# Source: https://github.com/rlunar/Ajenti/blob/20a9d53a0110dc8cc90eccd9c1e9706d0b050c75/csf/regex.pm#L137-L153
if (($config{LF_FTPD}) and ($globlogs{FTPD_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ proftpd\[\d+\]:? \S+ \([^\[]+\[(\S+)\]\)( -)?:? - no such user \'(\S*)\'/)) {
      $ip = $2; $acc = $4; $ip =~ s/^::ffff://; $acc =~ s/:$//g;
	if (checkip(\$ip)) {return ("Failed FTP login from","$ip|$acc","ftpd")} else {return}
}
if (($config{LF_FTPD}) and ($globlogs{FTPD_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ proftpd\[\d+\]:? \S+ \([^\[]+\[(\S+)\]\)( -)?:? USER (\S*) no such user found from/)) {
      $ip = $2; $acc = $4; $ip =~ s/^::ffff://; $acc =~ s/:$//g;
	if (checkip(\$ip)) {return ("Failed FTP login from","$ip|$acc","ftpd")} else {return}
}
if (($config{LF_FTPD}) and ($globlogs{FTPD_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ proftpd\[\d+\]:? \S+ \([^\[]+\[(\S+)\]\)( -)?:? - SECURITY VIOLATION/)) {
      $ip = $2; $acc = ""; $ip =~ s/^::ffff://; $acc =~ s/:$//g;
	if (checkip(\$ip)) {return ("Failed FTP login from","$ip|$acc","ftpd")} else {return}
}
if (($config{LF_FTPD}) and ($globlogs{FTPD_LOG}{$lgfile}) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) \S+ proftpd\[\d+\]:? \S+ \([^\[]+\[(\S+)\]\)( -)?:? - USER (\S*) \(Login failed\): Incorrect password/)) {
      $ip = $2; $acc = $4; $ip =~ s/^::ffff://; $acc =~ s/:$//g;
	if (checkip(\$ip)) {return ("Failed FTP login from","$ip|$acc","ftpd")} else {return}
}

#openSSH
#RH
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: pam_unix\(sshd:auth\): authentication failure; logname=\S* uid=\S* euid=\S* tty=\S* ruser=\S* rhost=(\S+)\s+(user=(\S+))?/)) {
	$ip = $3; $acc = $5; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Failed none for (\S*) from (\S+) port \S+/)) {
      $ip = $4; $acc = $3; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Failed password for (invalid user |illegal user )?(\S*) from (\S+)( port \S+ \S+\s*)?/)) {
      $ip = $5; $acc = $4; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Failed keyboard-interactive(\/pam)? for (invalid user )?(\S*) from (\S+) port \S+/)) {
      $ip = $6; $acc = $4; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Invalid user (\S*) from (\S+)/)) {
      $ip = $4; $acc = $3; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: User (\S*) from (\S+)\s* not allowed because not listed in AllowUsers/)) {
      $ip = $4; $acc = $3; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Did not receive identification string from (\S+)/)) {
      $ip = $3; $acc = ""; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: refused connect from (\S+)/)) {
      $ip = $3; $acc = ""; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}

#Debian/Ubuntu
if (($config{LF_SSHD}) and (($lgfile eq "/var/log/messages") or ($lgfile eq "/var/log/secure") or ($globlogs{SSHD_LOG}{$lgfile})) and ($line =~ /^(\S+|\S+\s+\d+\s+\S+) (\S+ )?sshd\[\d+\]: Illegal user (\S*) from (\S+)/)) {
      $ip = $4; $acc = $3; $ip =~ s/^::ffff://;
	if (checkip(\$ip)) {return ("Failed SSH login from","$ip|$acc","sshd")} else {return}
}
# If the matches in this file are not syntactically correct for perl then lfd
# will fail with an error. You are responsible for the security of any regex
# expressions you use. Remember that log file spoofing can exploit poorly
# constructed regex's
###############################################################################
# Do not edit beyond this point

        return 0;
}

1;
