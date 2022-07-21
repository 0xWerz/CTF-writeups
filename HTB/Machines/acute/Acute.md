# Acute HTB | 0xwerz | 03/06/22 
### The official [box page](https://app.hackthebox.com/machines/Undetected) on HTB 
<p align="center">
<img src="./img/Acute.png" alt="Acute poster" width="620"/>
</p>


### The writeup:
#### System Scan | **IP: 110.10.11.145**
as usual let's add the ip to to the `/etc/hosts` file and name it `acute.htb`
> `echo '10.10.11.145    undetected.htb ' >> /etc/hosts`

startup a nmap scan | **-sC for the default set of scripts**. | **-sV for Enables version detection**. | **-T4 for sending the traffic fast**.
>`nmap -sC -sV -T4 10.10.11.145`
```
werz@ctf01:~/ctf/htb/acute$ nmap -sC -sV -T4 10.10.11.145 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-03 01:58 CET
Nmap scan report for acute.htb (10.10.11.145)
Host is up (0.28s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Not valid before: 2022-01-06T06:34:58
|_Not valid after:  2030-01-04T06:34:58
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-07-21T00:58:43+00:00; -1s from scanner time.
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.73 seconds
```

## Open Ports
|Ports|Service|Takeaways|
|------|-----|-----|
|443|ssl/http| Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

So with have a single http/ssl port open and visiting `https://10.10.11.145` returns 404 that strange, there is a certificate with the name `atsserver.acute.local`. I’ll add that to the `/etc/hosts` file:

> echo 10.10.11.145     atsserver.acute.local

so we got a hit back on `https://atsserver.acute.local/`

![web page](/img/webpage.png)
### Web page enumeration

The about page may have some useful usernames under the `who we work with` headline.

![employees names](/img/who_we_work_with.png)

save them on a file list we may need them:
```
Awallace
Chall
Edavies
Imonks
Jmorgan
Lhopkins
```
```bash
echo "Awallace\nChall\nEdavies\nImonks\nJmorgan\nLhopkins" > users.enum
```

we also have a doc file:
![docx](/img/docx.png)

let's take a look
,there is a bunch of information.
- two links for staff inducation pages both returns 404
- there is a interesting section `IT overview` that gives a default password `Password1!`, and even mentions that some staff are not changing it:

    ![default pwd](/img/default_pwd.png)

we also have a windows PowerShell Web Access (PWSA) in the `Induction meetings with management staff` section:

![pwsa_link](/img/pwsa.png)

that goes to `https://atsserver.acute.local/Acute_Staff_Access`

if we check the metadata for the doc file we catch up in the description a hostname `Acute-PC01` that may be created in and the creator name `FCastle` and last the modified by `Daniel`

let's give all these information we got a try to login on that web powershell.

After some blind trys we got a valind request:
![vlid login](/img/pwsa_valid_login.png)

and we are in as edavies!

![](/img/pshell.png)