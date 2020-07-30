---
title: "Vulnhub Toppo 1 write up"
date: 2018-07-14T21:20:49-04:00
categories: ["ctf writeups"]
tags: ["ctf","writeup"]
draft: false
---

# Introduction
Link to machine: [https://www.vulnhub.com/entry/toppo-1,245/](https://www.vulnhub.com/entry/toppo-1,245/)

User Difficulty: 1/10

Root Difficulty: 4/10

# Gaining user level access

## Information gathering

standard nmap scan.

![nmap](../images/nmap.png "title")

There's very little services running on this machine. Only a web server (port 80), ssh server (port 22) and rpc service (only status, probably not useful)

Browsing the web hosted on target machine shows that it is a static html site. Unlikely to be vulnerable to remote attacks.

The ssh server is running on an unexploitable version as well.

To broaden the attack surface, I decided to run dirb on the target.

```text
$dirb http://192.168.56.1010
--------------------snip----------------------
---- Scanning URL: http://192.168.56.101/ ----
==> DIRECTORY: http://192.168.56.101/admin/
==> DIRECTORY: http://192.168.56.101/css/
==> DIRECTORY: http://192.168.56.101/img/
+ http://192.168.56.101/index.html (CODE:200|SIZE:6437)
--------------------snip-----------------------
```
Sure enough, we found an interesting directory at /admin.
Browsing it and we find a note.
```text
Note to myself :

I need to change my password :/ 12345ted123 is too outdated but the technology isn't my thing i 
prefer go fishing or watching soccer .
```
## Gaining access to ssh server
Now we have a password that the admin is too lazy to change.

Since the website has no login page, the only place this password can be used is the ssh server. But we still need to know the username. Browsing the site gives no hint about what the user could be. We have to make educated guesses.

From the password itself, we can guess that user is ted. I also tried admin and root just to be sure. And I managed to gain ssh access to the server as ted.

# Privilege Escalation

This actually took quite a bit of my time. 32-bit Debian 8.10 with Linux kernel 3.16. It is released on 2017-12-13. So I would assume a lot of the kernel exploits are patched. Furthermore, the server has no compiler. After much struggle with compiling potential exploits locally and transfer it on server, I gave up this route.

So I decided to check for SUID binaries. [source](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
```bash
# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```
![SGID SUID](../images/find.png)

Clearly, python has a misconfigured permission. I can just spawn a root shell using the following:

```bash
python -c "import pty; pty.spawn('/bin/sh');"
```

Annnnnnnnnd, we gained root.

