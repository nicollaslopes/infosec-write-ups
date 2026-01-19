# Retro

#Windows #CVE-2019-1388 #Wordpress 
## Recon

```
$ nmap -sV -Pn 10.64.140.140
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 05:23 -0500
Nmap scan report for 10.64.140.140
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.63 seconds
```


```
$ ffuf -u http://10.64.140.140/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.140.140/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

retro                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 296ms]
```

```
$ ffuf -u http://10.64.140.140/retro/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.64.140.140/retro/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

LICENSE.txt             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 270ms]
readme.html             [Status: 200, Size: 7447, Words: 761, Lines: 99, Duration: 128ms]
license.txt             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 129ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 1409ms]
wp-login.php            [Status: 200, Size: 2743, Words: 152, Lines: 69, Duration: 1569ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 1778ms]
wp-config.php           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1391ms]
wp-trackback.php        [Status: 200, Size: 135, Words: 11, Lines: 5, Duration: 1463ms]
wp-settings.php         [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 624ms]
.                       [Status: 200, Size: 30515, Words: 2531, Lines: 546, Duration: 1346ms]
wp-mail.php             [Status: 403, Size: 2759, Words: 220, Lines: 123, Duration: 1479ms]
wp-cron.php             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1648ms]
wp-blog-header.php      [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1342ms]
wp-links-opml.php       [Status: 200, Size: 229, Words: 13, Lines: 12, Duration: 1444ms]
wp-load.php             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1325ms]
wp-signup.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1328ms]
wp-activate.php         [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1356ms]
README.html             [Status: 200, Size: 7447, Words: 761, Lines: 99, Duration: 129ms]
Index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 1323ms]
LICENSE.TXT             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 127ms]
License.txt             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 127ms]
index.Php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 1333ms]
:: Progress: [37050/37050] :: Job [1/1] :: 311 req/sec :: Duration: [0:02:03] :: Errors: 0 ::
```


```
https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f
```