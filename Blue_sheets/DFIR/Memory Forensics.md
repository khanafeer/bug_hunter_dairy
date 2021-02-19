### First Step - Imageinfo

```powershell
c:\> volatility.exe -f .\cridex.vmem imageinfo
c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 kdbgscan
```



### Process and DLL

```powershell
c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 xxxx

xxx
#Processes
pslist
pstree
psscan
psdispscan

#To display a process's loaded DLLs
dlllist
dlllist -p 1892
dlllist --offset=0x04a291a8 # hidden process --> psscan then copy offset

#Dump DLL
dlldump -D dlls/
dlldump -p 1892 -D dlls/
dlldump --offset=0x04a291a8 -D dlls/

#Handles
handles
handles -p 296 -t Process #filter by object types

#others
cmdscan
consols
privs
envars
verinfo

#Dump
memdump -p 4 -D dump/
procdump -D dump/ -p 296

```



### Dump Memory Or Process

```powershell
c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 memdump -p 4 -D dump/

c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 procdump -D dump/ -p 296
```





### Networking

```powershell
c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 XXX

#connections
connections
connscan

#Listening sockets
sockets
sockscan
netscan
```



### Registry

```powershell
c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 hivelist

c:\> volatility.exe -f .\cridex.vmem --profile=WinXPSP2x86 printkey -K "Microsoft\Security Center\Svc"


hivedump #To recursively list all subkeys in a hive

hashdump #To extract and decrypt cached domain credentials stored in the registry

lsadump #To dump LSA secrets from the registry

dumpregistry -D output #dump a registry hive to disk

```

