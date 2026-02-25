# Year of the Jellyfish


## Reconnaissance 

```
$ nmap -p- -sV -sC 10.64.95.248
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-25 05:50 -0500
Nmap scan report for robyns-petshop.thm (10.64.95.248)
Host is up (0.14s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  2048 46:b2:81:be:e0:bc:a7:86:39:39:82:5b:bf:e5:65:58 (RSA)
80/tcp    open  http     Apache httpd 2.4.29
|_http-title: Did not follow redirect to https://robyns-petshop.thm/
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp   open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Robyn&#039;s Pet Shop
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
| Not valid before: 2026-02-25T10:47:32
|_Not valid after:  2027-02-25T10:47:32
|_http-server-header: Apache/2.4.29 (Ubuntu)
8000/tcp  open  http-alt
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 15
|_    Request
8096/tcp  open  http     Microsoft Kestrel httpd
|_http-server-header: Kestrel
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Jellyfin
|_Requested resource was /web/index.html
22222/tcp open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:99:92:52:8e:73:ed:91:01:d3:a7:a0:87:37:f0:4f (RSA)
|   256 5a:c0:cc:a1:a8:79:eb:fd:6f:cf:f8:78:0d:2f:5d:db (ECDSA)
|_  256 0a:ca:b8:39:4e:ca:e3:cf:86:5c:88:b9:2e:25:7a:1b (ED25519)
```


```
  
## Address
470 High Street,<br>
Bristol,<br>
BS1 1LJ<br>

## Contact Details
Phone: 01174962854<br>
Email: [staff@robyns-petshop.thm](mailto:staff@robyns-petshop.thm)
```