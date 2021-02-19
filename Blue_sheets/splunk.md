### Common Searches

```bash
| eventcount summarize=false index=* | dedup index | fields index
```

```python
| metadata type=sourcetypes index=botsv1
```

````python
`sysmon` | stats count by EventID, EventDescription
````

```bash
| tstats <stats-function> from datamodel=<datamodel-name> where <where-conditions> by <field-list> 


```



```python
`sysmon` Image=”*\\powershell.exe” OR Image=”*\\msbuild.exe” OR Image=”*\\psexec.exe” OR Image=”*\\at.exe” OR Image=”*\\schtasks.exe” OR Image=”*\\net.exe” OR Image=”*\\vssadmin.exe” OR Image=”*\\utilman.exe” OR Image=”*\\wmic.exe” OR Image=”*\\mshta.exe” OR Image=”*\\wscript.exe” OR Image=”*\\cscript.exe” OR Image=”*\\cmd.exe” OR Image=”*\\whoami.exe” OR Image=”*\\mmc.exe” OR Image=”*\\systeminfo.exe” OR Image=”*\\csvde.exe” OR Image=”*\\certutil.exe” | stats values(CommandLine) by Image



```

```
`sysmon` Image=”*\\powershell.exe” OR Image=”*\\msbuild.exe” OR Image=”*\\psexec.exe” OR Image=”*\\at.exe” OR Image=”*\\schtasks.exe” OR Image=”*\\net.exe” OR Image=”*\\vssadmin.exe” OR Image=”*\\utilman.exe” OR Image=”*\\wmic.exe” OR Image=”*\\mshta.exe” OR Image=”*\\wscript.exe” OR Image=”*\\cscript.exe” OR Image=”*\\cmd.exe” OR Image=”*\\whoami.exe” OR Image=”*\\mmc.exe” OR Image=”*\\systeminfo.exe” OR Image=”*\\csvde.exe” OR Image=”*\\certutil.exe” | stats values(CommandLine) by host

```

```
`sysmon` host=we8105desk | stats values(CommandLine) by Image _time
```

 ```
`sysmon` EventID=3 host=WE9041SRV | stats values(DestinationPort) by DestinationHostname
 ```





### Time Diff (first and last event)

```python
| stats max(_time) as maxtime min(_time) as mintime 
| eval difference=maxtime-mintime
```

```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| stats count by _time, status, form_data
| reverse
| head 2
| stats max(_time) as maxtime min(_time) as mintime 
| eval difference=maxtime-mintime
```



### Extract Text as field

```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| rex field=form_data "passwd=(?<p>\w+)" 
| dedup p 
| stats count by _time, status, form_data,p
```



```bash
index=botsv1 imreallynotbatman.com form_data="username=admin&*" sourcetype="stream:http" http_method=POST
| rex field=form_data "Signature string:(?<p>\w+)" 
| dedup p 
| stats count by _time, status, form_data,p



```



```
index=* EventCode=4724 |table user, host , _time | dedup user

```



### Extract fields by split

```bash
index=av eventtype=symantec_ep_security
| eval fields=split(_raw,",") | eval signature=mvindex(fields,3)
| top limit=50 signature
```



## Use Cases

logon from Multipe IPs

```bash
| tstats count values(Authentication.Source_Network_Address) as multiple_src dc(Authentication.Source_Network_Address) as src_count from datamodel="Authentication"."Authentication" WHERE  (Authentication.signature_id=4624 OR Authentication.signature_id=528) Authentication.Logon_Type=2 OR Authentication.Logon_Type=10 OR Authentication.Logon_Type=3 by  Authentication.user Authentication.signature  | rename "Authentication.*" as * | search src_count>1 count >2 | search multiple_src!=unknown multiple_src!="-"
```

logon from Multipe HOSTs

```bash
| tstats count values(Authentication.Workstation_Name) as multiple_src dc(Authentication.Workstation_Name) as src_count from datamodel="Authentication"."Authentication" WHERE  (Authentication.signature_id=4624 OR Authentication.signature_id=528) Authentication.Logon_Type=2 OR Authentication.Logon_Type=10 OR Authentication.Logon_Type=3 by  Authentication.user Authentication.signature  | rename "Authentication.*" as * | search src_count>1 count >2 | search multiple_src!=unknown multiple_src!="-"
```



```bash
| tstats `summariesonly` count from datamodel=Intrusion_Detection.IDS_Attacks where IDS_Attacks.severity=high OR IDS_Attacks.severity=critical by IDS_Attacks.src, IDS_Attacks.dest, IDS_Attacks.signature, IDS_Attacks.severity 
```

```bash
| tstats summariesonly=false values(Authentication.tag) as tag, 
values(Authentication.app) as app, 
count(eval('Authentication.action'=="failure")) as failure, 
count(eval('Authentication.action'=="success")) 
as success from datamodel=Authentication by Authentication.src 
| search success>0 | 
where failure > 5 
| `settags("access")` 
| `drop_dm_object_name("Authentication")`
```



```
(index=dns)  reply_code!=NOERROR |search (action=failure OR action=blocked)  |stats count by src query  |where count>50
```



