# csf custom regex

enable CSF Firewall custom regex support

[![CI](https://github.com/tmiland/csf-custom-regex/actions/workflows/ci.yml/badge.svg)](https://github.com/tmiland/csf-custom-regex/actions/workflows/ci.yml)

### ***Work in progress***

See the script in action:
<a href="https://www.abuseipdb.com/user/28030" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks" alt="AbuseIPDB Contributor Badge">
	<img src="https://www.abuseipdb.com/contributor/28030.svg" width="401">
</a>

Inspiration from: [enable CSF Firewall native fail2ban like support](https://community.centminmod.com/posts/62343/)

## Installation

```bash
wget https://github.com/tmiland/csf-custom-regex/raw/master/csf_custom_regex.sh
chmod +x csf_custom_regex.sh
```

Preview first (recommended) — nothing is changed by these:

```bash
./csf_custom_regex.sh --check      # OS, detected services, log paths, problems
./csf_custom_regex.sh --dry-run    # exactly what --install would change
```

Then install:

```bash
./csf_custom_regex.sh --install
```

## What it does

- Installs [regex.custom.pm](https://github.com/tmiland/csf-custom-regex/raw/master/regex.custom.pm) into `/usr/local/csf/bin/`
- Detects the OS family and the installed services (Virtualmin, nginx, Webmin, Exim, Dovecot, MariaDB/MySQL, ProFTPD, BIND, rsyslog) and wires up the matching log paths in `/etc/csf/csf.conf`
- **Virtualmin is optional**: it is detected automatically. Without it the nginx access/error rules (`CUSTOM3_LOG`/`CUSTOM4_LOG`) and the standard CSF rules stay active, and the Virtualmin-only rules are simply left inactive
- Backs up `csf.conf` and `regex.custom.pm` before every change, plus a `csf --profile backup`
- `--status` shows recent `LF_CUSTOMTRIGGER` lines from `/var/log/lfd.log` (add `-f` to follow)

You will see lines like:

```
Mar 15 00:05:46 vps lfd[688]: (nginx_444) Nginx 444 [192.0.2.10] (CA/Canada/-): 5 in the last 3600 secs - *Blocked in csf* for 86400 secs [LF_CUSTOMTRIGGER]
```

## Options

| Option | Description |
| ------ | ----------- |
| `--install` / `-i` | Install/update `regex.custom.pm` and the log paths |
| `--uninstall` / `-u` | Restore the previous `regex.custom.pm` and the `csf.conf` backup |
| `--check` / `-c` | Read-only status report (exit 1 when problems are found) |
| `--dry-run` / `-n` | Show what `--install` would change, change nothing |
| `--status` / `-s` | Show recent triggers from `/var/log/lfd.log` (add `-f` to follow) |
| `--yes` / `-y` | Non-interactive; never installs Virtualmin |
| `--with-virtualmin` | Install Virtualmin if it is not detected |
| `--pm-url URL` | Override the `regex.custom.pm` download URL |
| `--help` / `-h` | Show help |
| `--version` / `-V` | Show version |

## Active rules per log slot

| Slot | Wired when | Rules |
| ---- | ---------- | ----- |
| `CUSTOM1_LOG` / `CUSTOM2_LOG` | Virtualmin detected | Virtualmin access/error log rules (incl. the Virtualmin-only xmlrpc, wp-login, 444 and 410 rules) |
| `CUSTOM3_LOG` / `CUSTOM4_LOG` | nginx detected | The same access/error rules on nginx logs (works without Virtualmin) |
| `CUSTOM5_LOG` | MariaDB/MySQL detected | mysql login failures |
| `CUSTOM6_LOG` | Dovecot detected | dovecot login failures |
| `CUSTOM7_LOG` | Exim detected | exim/dovecot rejectlog rules |
| `SSHD_LOG`, `SYSLOG_LOG`, `SMTPAUTH_LOG`, `POP3D_LOG`, `FTPD_LOG`, `WEBMIN_LOG`, `HTACCESS_LOG`, `MODSEC_LOG` | matching service/log detected | existing sshd, syslog, mail auth, ftp, webmin and htaccess/modsec rules |

Log paths are chosen by probing existing files, so Debian-family and RHEL-family layouts are both handled.

> **Note on `CUSTOM6_LOG` (dovecot unknown user):** this rule can only match with a file-based passdb (e.g. `passwd-file`). With `passdb = pam` (common on Virtualmin/ISPConfig setups), PAM reports unknown users as a plain password mismatch, so dovecot never logs `unknown user` and the rule stays silent. Check with: `doveconf -n | grep -A1 'passdb {'`.

## Tests

Every push to `master` and every pull request runs [CI](.github/workflows/ci.yml):

- **ShellCheck** on `csf_custom_regex.sh` and `tests/smoke.sh`
- **Perl syntax check** (`perl -c regex.custom.pm`)
- **Installer smoke tests** (`tests/smoke.sh`) — no root required, nothing on the system is changed

The smoke tests run natively on Ubuntu and inside Debian 12/13 and Rocky 8/9 containers. Run them locally with:

```bash
bash tests/smoke.sh
```

## Tested on

* Debian 10-13 (maintainer tested; Debian 12/13 also smoke-tested in CI containers)
* RHEL-family (RHEL/Alma/Rocky/CentOS/Fedora): log paths supported and smoke-tested in CI containers (Rocky 8/9), not yet tested by the maintainer on a live system — reports welcome

## Compatibility and Requirements

* Debian 9+ or RHEL 8+ (bash, perl, CSF Firewall)
* Virtualmin is optional
* A file-based syslog (`rsyslog`) is recommended: on journald-only systems the syslog, sshd and mail-auth rules have no log file to read. `--check` warns about this

## Credits

- Code is customized from these sources:
  * [enable CSF Firewall native fail2ban like support](https://community.centminmod.com/posts/62343/)
  * [Custom REGEX rules for CSF](https://forum.configserver.com/viewtopic.php?t=7517)
  * [sillsdev/ops-ansible-common-roles](https://github.com/sillsdev/ops-ansible-common-roles/blob/master/csf_config/files/regex.custom.pm)
  * [configserver](http://www.configserver.com)

## Donations

<a href="https://www.buymeacoffee.com/tmiland" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
- [PayPal me](https://paypal.me/milanddata)
- [BTC] : 33mjmoPxqfXnWNsvy8gvMZrrcG3gEa3YDM

## Disclaimer

***Use at your own risk***

## License

[![MIT License Image](https://upload.wikimedia.org/wikipedia/commons/thumb/0/0c/MIT_logo.svg/220px-MIT_logo.svg.png)](https://github.com/tmiland/csf-custom-regex/blob/master/LICENSE)

[MIT License](https://github.com/tmiland/csf-custom-regex/blob/master/LICENSE)

## Note on repository history

The repository was deleted and recreated on **2026-10-15**, and its history was rewritten to remove accidentally committed sensitive data:

- Pre-rewrite commits and tags no longer resolve; the `v1.0.0`–`v1.0.3` tags were re-created on the rewritten commits.
- Existing forks were detached from the recreated repository and will not receive updates unless re-forked.

If you forked this project or pinned an old revision, please re-fork or re-pin from the current `master`.
