# RE Malwares

[TOC]

## Executables

### Basic Static Analysis

- Identify language (PEiD.exe, EXEinfo)
- Check Strings
- PE Headers (PEView, CFF, )
- Import table
- Resource Section

### Static Code Analysis

- Analyzing Source Code (IDA Pro, )



### Dynamic Analysis

- Debugging Application



### Behavioral Analysis

- Monitoring Registry, Processes, APIs, Autoruns (sysinternals)
- Sandboxing
- Network Analysis



### Executable Case Study

**Identification Phase**

```
use PEid to check language, If packed unpack
```

**Basic Static Phase**

```powershell
1. strings.exe <mal.exe> OR floss.exe <mal.exe> #for strings and stack strings
2. #PE header, import and export table
3. resourceHacker.exe #check resources
```

**Behavioral Phase**

```powershell
1. Analyze Network Communication and requested domains
2. get files created and modified, registry, mutexes, processes created or accessed
3. check APIs got called
4. get memory dump (to bypass packing/encryption)
```

**Code Analysis**

```powershell
1. Search for interesting functions (upload, download, C2, ...)
```



## PCAP Analysis

I use [Brim](https://github.com/brimsec/brim) to convert large PCAPs to zeek logs

```bash
_path="dns" | count() by query

172.16.165.132 _path="files"
```









