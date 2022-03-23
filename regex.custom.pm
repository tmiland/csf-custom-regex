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
    return ("Nginx Security rule triggered from",$1,"nginx_security","40","80,443","86400","0");
  }

# /var/log/nginx/error.log
# NginX security rules trigger (Default: 40 errors bans for 24 hours)
  if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*access forbidden by rule, client: (\S+).*/)) {
    return ("Nginx Security rule triggered from",$1,"nginx_security","40","80,443","86400","0");
  }

# /var/log/virtualmin/*_error_log
# NginX 404 errors (Default: 50 errors bans for 24 hours)
  if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /.*No such file or directory\), client: (\S+),.*/)) {
    return ("Nginx Security rule triggered from",$1,"nginx_404s","50","80,443","86400","0");
  }

# /var/log/nginx/error.log
# NginX 404 errors (Default: 50 errors bans for 24 hours)
  if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*No such file or directory\), client: (\S+),.*/)) {
    return ("Nginx Security rule triggered from",$1,"nginx_404s","50","80,443","86400","0");
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
# Nginx connection limit rule trigger (Default: 5 errors bans for 60mins)
  if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /.*limiting connections by zone .*, client: (\S+),(.*)/)) {
    return ("Nginx Security rule triggered from",$1,"nginx_conn_limit","5","80,443","3600","0");
  }

# /var/log/nginx/error.log
# https://community.centminmod.com/posts/74546/
# Nginx connection limit rule trigger (Default: 5 errors bans for 60mins)
  if (($globlogs{CUSTOM4_LOG}{$lgfile}) and ($line =~ /.*limiting connections by zone .*, client: (\S+),(.*)/)) {
    return ("Nginx Security rule triggered from",$1,"nginx_conn_limit_localhost","5","80,443","3600","0");
  }

# WordPress Catch all
  # if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(\/wp-admin|wp-admins.php|administrator\/|login.php|backend|admin|\/xmlrpc.php|\/wp-(app|cron|login|register|mail).php|wp-.*.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(_index)?.xml|wlwmanifest.xml|wp-cl-plugin.php|[a-z0-9_-]+-sitemap([0-9]+)?.xml)/)) {
  #   return ("WordPress Catch all Attack",$1,"wordpress","7","80,443","1");
  # }

# /var/log/virtualmin/*_access_log
# WordPress Non Existent plugin locations
# (Default: 2 errors bans for 24 hours)
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD] (\/wp-content\/plugins\/).*(\s404\s)/)) {
    return ("WordPress Plugins Honeypot Trap",$1,"wordpress_404","2","80,443","86400","0");
  }

# /var/log/nginx/access.log
# WordPress Non Existent plugin locations
# (Default: 2 errors bans for 24 hours)
  if (($globlogs{CUSTOM3_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD] (\/wp-content\/plugins\/).*(\s404\s)/)) {
    return ("WordPress Plugins Honeypot Trap",$1,"wordpress_404","2","80,443","86400","0");
  }

# /var/log/virtualmin/*_access_log
# Non Existent Dot directory locations
# (Default: 2 errors bans for 24 hours)
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /^(\S+) -.*[GET|POST|HEAD] (\/\.).*(\s404\s)/)) {
    return ("Dot directory Honeypot Trap",$1,"nginx_404","2","80,443","86400","0");
  }

# /var/log/nginx/access.log
# Non Existent Dot directory locations
# (Default: 2 errors bans for 24 hours)
  if (($globlogs{CUSTOM3_LOG}{$lgfile}) and ($line =~ /^(\S+) -.*[GET|POST|HEAD] (\/\.).*(\s404\s)/)) {
    return ("Dot directory Honeypot Trap",$1,"nginx_404","2","80,443","86400","0");
  }

# /var/log/virtualmin/*_access_log
# Accessing the server by Invalid Hostname (IP)
# (Default: 10 errors bans for 24 hours)
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD].*(\s410\s)/)) {
    return ("Invalid Hostname Honeypot Trap",$1,"nginx_410","10","80,443","86400","0");
  }

# /var/log/nginx/access.log
# Accessing the server by Invalid Hostname (IP)
# (Default: 10 errors bans for 24 hours)
  if (($globlogs{CUSTOM3_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST|HEAD].*(\s410\s)/)) {
    return ("Invalid Hostname Honeypot Trap",$1,"nginx_410","10","80,443","86400","0");
  }

# Source: https://www.digitalflare.co.uk/blog/view/blocking-wp-login-and-xmlrpc-brute-force-attacks-with-csf-cpanel/
# WordPress XMLRPC
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(xmlrpc.php)/)) {
    return ("WordPress XMLPRC Attack",$1,"wordpress_xmlrpc","3","80,443","1");
  }

# WordPress-LOGINS
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(wp-login.php)/)) {
    return ("WordPress Login Attack",$1,"wordpress_login","3","80,443","1");
  }

# WordPress-ADMINS
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(wp-admins.php)/)) {
    return ("WordPress ADMIN Attack",$1,"wordpress_admin","3","80,443","1");
  }

# WordPress-PLUGIN
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(wp-cl-plugin.php)/)) {
    return ("WordPress wp-cl-plugin Attack",$1,"wordpress_plugin","3","80,443","1");
  }

# WordPress-wlwmanifest.xml
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(wlwmanifest.xml)/)) {
    return ("WordPress wlwmanifest.xml Attack",$1,"manifest","3","80,443","1");
  }

# shell.php
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(shell.php)/)) {
    return ("SHELL shell.php Attack",$1,"shell","3","80,443","1");
  }

# xing.php
  if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /(\S+) -.*[GET|POST].*(xing.php)/)) {
    return ("XING xing.php Attack",$1,"xing","3","80,443","1");
  }

# Source: https://github.com/sillsdev/ops-ansible-common-roles/blob/master/csf_config/files/regex.custom.pm
# Default: 5 errors bans permanant (Uses settings from LF_SMTPAUTH)
# postfix/smtpd UNKNOWN from unknown
  if (($config{LF_SMTPAUTH}) and ($globlogs{SMTPAUTH_LOG}{$lgfile}) and ($line =~ /postfix\/smtpd[^U]*UNKNOWN from unknown\[(\d+\.\d+\.\d+\.\d+)\]/)) {
    $ip = $1; $acc = "";
    $ip =~ s/^::ffff://;
    if (&checkip($ip)) {return ("UNKNOWN from unknown from","$ip|$acc","postfix_unknown")} else {return}
  }

# postfix/smtpd lost connection after AUTH
# Default: 5 errors bans permanant (Uses settings from LF_SMTPAUTH)
  if (($config{LF_SMTPAUTH}) and ($globlogs{SMTPAUTH_LOG}{$lgfile}) and ($line =~ /postfix\/smtpd\[\d+\]: lost connection after AUTH from [^\[]+\[(\d+\.\d+\.\d+\.\d+)\]/)) {
    $ip = $1; $acc = "";
    $ip =~ s/^::ffff://;
    if (&checkip($ip)) {return ("lost connection after AUTH from","$ip|$acc","postfix_lost")} else {return}
  }

# postfix/smtpd disconnect from unknown
# Default: 5 errors bans permanant (Uses settings from LF_SMTPAUTH)
  if (($config{LF_SMTPAUTH}) and ($globlogs{SMTPAUTH_LOG}{$lgfile}) and ($line =~ /postfix\/smtpd[^U]*disconnect from unknown\[(\d+\.\d+\.\d+\.\d+)\]/)) {
    $ip = $1; $acc = "";
    $ip =~ s/^::ffff://;
    if (&checkip($ip)) {return ("lost connection after AUTH from","$ip|$acc","postfix_disconnect")} else {return}
  }

# postfix/smtpd disconnect from domain[ip-address]
# Default: 5 errors bans permanant (Uses settings from LF_SMTPAUTH)
  if (($config{LF_SMTPAUTH}) and ($globlogs{SMTPAUTH_LOG}{$lgfile}) and ($line =~ /^\S+\s+\d+\s+\S+ \S+ postfix\/submission\/smtpd\[\d+\]: disconnect from \S+\[(\S+)\]/)) {
    $ip = $1; $acc = "";
    $ip =~ s/^::ffff://;
    if (&checkip($ip)) {return ("lost connection after AUTH from","$ip|$acc","postfix_disconnect")} else {return}
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

# If the matches in this file are not syntactically correct for perl then lfd
# will fail with an error. You are responsible for the security of any regex
# expressions you use. Remember that log file spoofing can exploit poorly
# constructed regex's
###############################################################################
# Do not edit beyond this point

        return 0;
}

1;
