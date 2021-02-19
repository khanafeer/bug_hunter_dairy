# AQL

```sql
SELECT * FROM events LAST 10 MINUTES
SELECT sourceip,destinationip FROM events LAST 24 HOURS
SELECT * FROM events START '2017 01 01 9:00:00' STOP '2017 01 01 10:20:00'


SELECT * FROM events limit 5 LAST 24 HOURS
SELECT * FROM events ORDER BY magnitude DESC LAST 24 HOURS
SELECT * FROM events WHERE magnitude >= 3 


SELECT * FROM events WHERE sourceip = '192.0.2.0' AND destinationip = '198.51.100.0' START '2017 01 01 9:00:00' STOP '2017 01 01 10:20:00'
SELECT * FROM events WHERE INCIDR('192.0.2.0/24',sourceip)


SELECT * FROM events WHERE username LIKE '%roul%'  #CaseSensetive
SELECT * FROM events WHERE username ILIKE '%ROUL%' #CaseInsensetive


SELECT sourceip,category,credibility FROM events WHERE (severity > 3 AND category = 5018)OR (severity < 3 AND credibility > 8)


SELECT * FROM events WHERE TEXT SEARCH 'firewall' #have "firewall" text in search


#Aggregations
SELECT sourceip, AVG(magnitude)FROM events GROUP BY sourceip
SELECT sourceip, FIRST(magnitude)FROM events GROUP BY sourceip #first entry of the rows in the aggregate.

#functions
SELECT APPLICATIONNAME(applicationid) AS 'Name of App' FROM flows

ASSETHOSTNAME(sourceip)
ASSETHOSTNAME(sourceip, domainid)
SELECT ASSETHOSTNAME(destinationip, NOW()) AS 'Host Name' FROM events

ASSETPROPERTY('Unified Name', sourceIP, domainId)
SELECT ASSETPROPERTY('Location',sourceip) AS Asset_location,COUNT(*) AS 'event count' FROM eventsGROUP BY Asset_locationLAST 1 days

SELECT logsourceid, LOGSOURCENAME(logsourceid) AS 'Name of log source', LOGSOURCEGROUPNAME(devicegrouplist) AS 'Group Names', LOGSOURCETYPENAME(devicetype) AS 'Devices' FROM events GROUP BY logsourceid

```





# Examples AQL

EPS for Each data source

```sql
SELECT LOGSOURCENAME(logsourceid) AS "Log Source", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / 300 AS "EPS in Interval" FROM events GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC LAST 5 MINUTES
```



EPS for some log sources

```sql
SELECT LOGSOURCENAME(logsourceid) AS "Log Source",DATEFORMAT( devicetime, 'dd-MM-yyyy') AS "Date_log", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / 86400 AS "EPS in Interval" FROM events WHERE "Log Source" ILIKE '%office%' OR "Log Source" ILIKE '%etokai%' GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC LAST 24 HOURS

```

```sql
SELECT DATEFORMAT( devicetime, 'dd-MM-yyyy') AS "Date_log", LOGSOURCENAME(logsourceid) AS "Log Source", SUM(eventcount) AS "Event Count" FROM events WHERE "Log Source" ILIKE '%office%' OR "Log Source" ILIKE '%etokai%' GROUP BY "Date_log","Log Source" ORDER BY "Date_log" START '2021-01-01 00:00:00' STOP '2021-02-10 00:00:00'

```



EPS for EventIDs

```sql
SELECT QIDNAME(qid) AS 'Event Name' ,"EventID" As 'Event ID', SUM(eventcount) As 'Count of events', SUM(eventcount) / 300 As 'EPS for EID' from events GROUP BY  QIDNAME(qid) ORDER BY "EPS for EID" DESC last 60 minutes
```



Subquey

```sql
SELECT * FROM events WHERE username IN (SELECT username FROM events LIMIT 10 LAST 5 MINUTES) LAST 24 HOURS

SELECT * FROM EVENTS WHERE sourceip IN (SELECT destinationip FROM events)
```



