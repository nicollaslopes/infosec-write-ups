# Relevant

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


```
$ enum4linux -a 10.66.181.111
"my" variable $which_output masks earlier declaration in same scope at ./enum4linux.pl line 280.
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Dec 14 09:45:18 2025

 =========================================( Target Information )=========================================

Target ........... 10.66.181.111
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.66.181.111 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.66.181.111 )===============================

Looking up status of 10.66.181.111
No reply from 10.66.181.111

 ===================================( Session Check on 10.66.181.111 )===================================



```


```
$ nmap --script smb-vuln* -p 445 10.66.177.88
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-14 10:44 -03
Nmap scan report for 10.66.177.88
Host is up (0.14s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 14.48 seconds
```