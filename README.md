# csf custom regex
 enable CSF Firewall native fail2ban like support

### ***Work in progress***

See the script in action:
<a href="https://www.abuseipdb.com/user/28030" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks" alt="AbuseIPDB Contributor Badge">
	<img src="https://www.abuseipdb.com/contributor/28030.svg" style="width: 401px;">
</a>

Inspiration from: [enable CSF Firewall native fail2ban like support](https://community.centminmod.com/posts/62343/)

```bash
$ wget https://github.com/tmiland/csf-custom-regex/raw/master/csf_custom_regex.sh
$ chmod +x csf_custom_regex.sh
$ ./csf_custom_regex.sh [install/status]
```

- Install option will download [regex.custom.pm](https://github.com/tmiland/csf-custom-regex/raw/master/regex.custom.pm)
- Status option will run ```tail -f /var/log/lfd.log | grep 'LF_CUSTOMTRIGGER'```

You will see lines like: ```Mar 15 00:05:46 vps lfd[688]: (nginx_444) Nginx 444 [IP Adress] (CA/Canada/-): 5 in the last 3600 secs - *Blocked in csf* for 86400 secs [LF_CUSTOMTRIGGER]```

**Logpaths are currently hardcoded to match Debian 10 with Virtualmin.**

* If Virtualmin or CSF is not installed, you will get the question to install.
This will source the [Virtualmin install script](https://github.com/virtualmin/virtualmin-install) and [CSF installer script](https://github.com/tmiland/csf)

## Compatibility and Requirements

* Debian 9 and later
  - Might add Compatibility on request 
* Virtualmin is required
  * Might change in the future 

## Credits
- Code is customized from these sources:
  * [enable CSF Firewall native fail2ban like support](https://community.centminmod.com/posts/62343/)
  * [Custom REGEX rules for CSF](https://forum.configserver.com/viewtopic.php?t=7517)
  * [sillsdev/ops-ansible-common-roles](https://github.com/sillsdev/ops-ansible-common-roles/blob/master/csf_config/files/regex.custom.pm)
  * [configserver](http://www.configserver.com)

## Donations 
- [PayPal me](https://paypal.me/milanddata)
- [BTC] : 33mjmoPxqfXnWNsvy8gvMZrrcG3gEa3YDM

## Web Hosting

Sign up for web hosting using this link, and receive $100 in credit over 60 days.

[DigitalOcean](https://m.do.co/c/f1f2b475fca0)

#### Disclaimer 

*** ***Use at own risk*** ***

### License

[![MIT License Image](https://upload.wikimedia.org/wikipedia/commons/thumb/0/0c/MIT_logo.svg/220px-MIT_logo.svg.png)](https://github.com/tmiland/csf-custom-regex/blob/master/LICENSE)

[MIT License](https://github.com/tmiland/csf-custom-regex/blob/master/LICENSE)
