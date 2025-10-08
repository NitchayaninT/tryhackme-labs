# Ice
Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

## Recon

Since target blocks ICMP ping, i will use this nmap command instead
- `nmap -Pn -sV -sC 10.10.103.186`

![Pasted image 20251008204749.png](thm_pics/Pasted%20image%2020251008204749.png)

![Pasted image 20251008204810.png](thm_pics/Pasted%20image%2020251008204810.png)

- ports 135, 139, 445, 3389, 5357, 8000, 49152, 49153, 49154, 49158, 49159, 49160 are open
- What does Nmap identify as the hostname of the machine?
Answer : **DARK-PC**

## Gain Access
Now that we've identified some interesting services running on our target machine, let's do a little bit of research into one of the weirder services identified: Icecast. Icecast, or well at least this version running on our target, is heavily flawed and has a high level vulnerability with a score of 7.5 (7.4 depending on where you view it). What is the **Impact Score** for this vulnerability? Use [https://www.cvedetails.com](https://www.cvedetails.com/cve/CVE-2004-1561/) for this question and the next.
Answer : 6.4
CVE number : # [CVE-2004-1561](https://www.cvedetails.com/cve/CVE-2004-1561/ "CVE-2004-1561 security vulnerability details")

![Pasted image 20251008205516.png](thm_pics/Pasted%20image%2020251008205516.png)

- use this exploit, set RHOSTS, LHOST and now we got the shell

![Pasted image 20251008205646.png](thm_pics/Pasted%20image%2020251008205646.png)

## Escalate
What user was running that Icecast process? 
- Command : getuid
- Answer : Dark
What build of Windows is the system?
- Command : sysinfo
- Answer : 7601

![Pasted image 20251008210027.png](thm_pics/Pasted%20image%2020251008210027.png)

Now that we know some of the finer details of the system we are working with, let's start escalating our privileges. First, what is the architecture of the process we're running?
Answer : x64

Now that we know the architecture of the process, let's perform some further recon. While this doesn't work the best on x64 machines, let's now run the following command `run post/multi/recon/local_exploit_suggester`. *This can appear to hang as it tests exploits and might take several minutes to complete*

Answer : exploit/windows/local/bypassuac_eventvwr

Go ahead and select our previously found local exploit for use using the command `use FULL_PATH_FOR_EXPLOIT`

We can now verify that we have expanded permissions using the command `getprivs`. What permission listed **allows us to take ownership of files**?

![Pasted image 20251008215113.png](thm_pics/Pasted%20image%2020251008215113.png)

## Looting
Prior to further action, we need to move to a process that actually has the permissions that we need to interact with the lsass service, the service responsible for authentication within Windows. First, let's list the processes using the command `ps`. Note, we can see processes being run by NT AUTHORITY\SYSTEM as we have escalated permissions (even though our process doesn't).

In order to **interact with lsass** we need to be **'living in' a process that is the same architecture as the lsass service** (x64 in the case of this machine) and a process that has the same permissions as lsass. T**he printer spool service happens to meet our needs perfectly for this** and it'll restart if we crash it! What's the name of the printer service?
Answer : spoolsv.exe, migrate

Mentioned within this question is the term 'living in' a process. Often when we take over a running program we ultimately load another shared library into the program (a dll) which includes our malicious code. From this, we can spawn a new thread that hosts our shell.

![Pasted image 20251008215413.png](thm_pics/Pasted%20image%2020251008215413.png)

- Migrate to this process by using : `migrate -N spoolsv.exe`

Let's check what user we are now with the command `getuid`. What user is listed?
Answer : NT AUTHORITY\SYSTEM

Now that we've made our way to full administrator permissions we'll set our sights on looting. Mimikatz is a rather infamous password dumping tool that is incredibly useful. Load it now using the command `load kiwi` (Kiwi is the updated version of Mimikatz)

Loading kiwi into our meterpreter session will expand our help menu, take a look at the newly added section of the help menu now via the command `help`.

Which command allows up to retrieve all credentials?
Answer : creds_all

![Pasted image 20251008215732.png](thm_pics/Pasted%20image%2020251008215732.png)

![Pasted image 20251008215803.png](thm_pics/Pasted%20image%2020251008215803.png)

What is Dark's password?
Password01

![Pasted image 20251008215838.png](thm_pics/Pasted%20image%2020251008215838.png)

## Post-Exploitation
- Command : hashdump

![Pasted image 20251008220000.png](thm_pics/Pasted%20image%2020251008220000.png)

While more useful when interacting with a machine being used, what command allows us to watch the remote user's desktop in real time?
- Answer :  screenshare

How about if we wanted to record from a microphone attached to the system?
- Answer : record_mic

To complicate forensics efforts **we can modify timestamps of files on the system**. What command allows us to do this? Don't ever do this on a pentest unless you're explicitly allowed to do so! This is not beneficial to the defending team as they try to breakdown the events of the pentest after the fact.
- Answer : timestomp

Mimikatz allows us to create what's called a `golden ticket`, allowing us to authenticate anywhere with ease. What command allows us to do this?

Golden ticket attacks are a function within Mimikatz which **abuses a component to Kerberos** (the authentication system in Windows domains), the ticket-granting ticket. In short, **golden ticket attacks allow us to maintain persistence** and **authenticate as any user on the domain**.
- Answer : golden_ticket_create

One last thing to note. As we have the password for the user 'Dark' we can now authenticate to the machine and access it via remote desktop (MSRDP). As this is a workstation, we'd likely kick whatever user is signed onto it off if we connect to it, however, it's always interesting to remote into machines and view them as their users do. If this hasn't already been enabled, we can enable it via the following Metasploit module: `run post/windows/manage/enable_rdp`

- since rdp is already enabled, lets try connecting to it using xfreerdp

![Pasted image 20251008222114.png](thm_pics/Pasted%20image%2020251008222114.png)

- it has problems with certificate stuff (it has to do with the ssl certificate)
- someone in hackthebox says its because **the target is an older windows version** which uses SHA1 for certs
- i will use rdesktop instead : `rdesktop -u Dark -p 'Password01!' 10.10.242.138`

![Pasted image 20251008222218.png](thm_pics/Pasted%20image%2020251008222218.png)

- wow windows 7...good old days