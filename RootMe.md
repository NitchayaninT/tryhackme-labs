# RootMe
## Reconnaissance
- Scan the machine, how many ports are open?
	- Command : `nmap -p- -T4 10.10.101.198`
- What version of Apache is running?
	- Command : `nmap -sV 10.10.101.198`

![Pasted image 20251003202250.png](thm_pics/Pasted%20image%2020251003202250.png)

	- Apache httpd 2.4.41
- What service is running on port 22?
	- OpenSSH
- Find directories on the web server using the GoBuster tool.
	- Command : `gobuster dir -u http://10.10.101.198 -w /usr/share/wordlists/dirb/common.txt`

![Pasted image 20251003202603.png](thm_pics/Pasted%20image%2020251003202603.png)

- What is the hidden directory?
	- /panel/
## Getting a Shell
Find a form to upload and get a reverse shell, and find the flag.

![Pasted image 20251003202714.png](thm_pics/Pasted%20image%2020251003202714.png)

- Here's where we upload the file
- I tried uploading SIMPLE php file, didnt work because **target wouldnt allow me to upload php payload**

![Pasted image 20251003212025.png](thm_pics/Pasted%20image%2020251003212025.png)

- Is there a way to bypass that?
- So i tried BurpSuite to intercept the traffic when uploading a file

![Pasted image 20251003213304.png](thm_pics/Pasted%20image%2020251003213304.png)

- i tried changing from filename="shell.php" to filename="**shell.phtml**"
- On many Apache/PHP setups the server is configured to treat `.phtml` files as PHP files (the same way it treats `.php`)

![Pasted image 20251003214925.png](thm_pics/Pasted%20image%2020251003214925.png)

![Pasted image 20251003214953.png](thm_pics/Pasted%20image%2020251003214953.png)

- seems like it succeeded

![Pasted image 20251003215019.png](thm_pics/Pasted%20image%2020251003215019.png)

- So i tried executing commands

![Pasted image 20251003215045.png](thm_pics/Pasted%20image%2020251003215045.png)

- Seems like **it works!**
- Now i will try to upload actual php reverse payload
- Location : `/usr/share/webshells/php`
- edit the payload to change LPORT and LHOST

![Pasted image 20251003215442.png](thm_pics/Pasted%20image%2020251003215442.png)

- set up simple listener at port 1234
- repeat the steps above to bypass php in burpsuite

![Pasted image 20251003215734.png](thm_pics/Pasted%20image%2020251003215734.png)

![Pasted image 20251003215754.png](thm_pics/Pasted%20image%2020251003215754.png)

- WE got the shell!!!
- Now, lets find the flag
- Command : `find / -name "user.txt"`

![Pasted image 20251003220005.png](thm_pics/Pasted%20image%2020251003220005.png)

- got the flag!

## Privilege Escalation
Search for files with SUID permission, which file is weird?
- Command : `find / -type f -perm -04000 -ls 2>/dev/null`

![Pasted image 20251003220222.png](thm_pics/Pasted%20image%2020251003220222.png)

- Classic pkexec, i have done this before in Ignite lab
- It somehow isnt the right answer, lets take a closer look

![Pasted image 20251003222302.png](thm_pics/Pasted%20image%2020251003222302.png)

- python2.7 also seems weird, and its correct
- Exploit it by : `/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh -p")'`
- Python executes the code inside the quotes
- `os.system()` spawns a shell (`/bin/sh`) to run commands and `-p` option instructs the shell to **preserve privileges**

![Pasted image 20251003222546.png](thm_pics/Pasted%20image%2020251003222546.png)

- It worked! so i basically changed the uid to root (it worked because python2.7 has SUID bit set, when any user executes this binary, the kernel runs the binary with **effective SUID = owner = root**)
- Which means we ran the command as root

![Pasted image 20251003222820.png](thm_pics/Pasted%20image%2020251003222820.png)

- Found root.txt!