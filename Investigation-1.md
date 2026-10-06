Investigation: Multiple Failed Login Attempts
1. Investigation Objective
Field	Details
Investigation Type	Brute-Force / Password-Spraying Detection
SIEM	Splunk Enterprise
Log Source	Windows Security Events
Event ID	4625 – Failed Logon
Related Event ID	4624 – Successful Logon
Source IP	10.10.10.50
Host	Likhi
Investigation Goal	Identify suspicious repeated authentication failures and determine whether a successful login followed them


2. SPL Query
index=main EventCode=4625 src_ip=10.10.10.50
| table _time user src_ip host
| sort _time

3. Investigation Results
Time	EventCode	User	Source IP	Host
01:30:00	4625	admin	10.10.10.50	Likhi
01:30:10	4625	john	10.10.10.50	Likhi
01:30:20	4625	backup	10.10.10.50	Likhi
01:31:00	4625	admin	10.10.10.50	Likhi
01:31:10	4625	john	10.10.10.50	Likhi
01:31:20	4625	backup	10.10.10.50	Likhi
01:32:00	4625	admin	10.10.10.50	Likhi
01:32:10	4625	john	10.10.10.50	Likhi
01:32:20	4625	backup	10.10.10.50	Likhi
...	...	...	...	...
01:39:00	4625	admin	10.10.10.50	Likhi
01:39:10	4625	john	10.10.10.50	Likhi
01:39:20	4625	backup	10.10.10.50	Likhi


Total failed authentication events: 30
4. Successful Login Check
I then investigated Event ID 4624 from the same source IP:
index=main EventCode=4624 src_ip=10.10.10.50
| table _time user src_ip host
| sort _time

Time	EventCode	User	Source IP	Host
01:41:00	4624	admin	10.10.10.50	Likhi
01:42:00	4624	admin	10.10.10.50	Likhi
01:43:00	4624	admin	10.10.10.50	Likhi
01:44:00	4624	admin	10.10.10.50	Likhi


5. Findings
Indicator	Observation
Failed attempts	30
Targeted accounts	3 – admin, john, backup
Source IP	10.10.10.50
Target host	Likhi
Failure period	Approximately 9 minutes
Successful logins	4
Successful account	admin
Suspicious pattern	Multiple accounts targeted from one source
Risk	High


6. Conclusion
Conclusion
The investigation identified 30 failed authentication attempts against three different accounts from the same source IP 10.10.10.50. Shortly after the failed attempts, successful authentication events for the admin account were observed. This pattern is suspicious and could indicate password spraying or brute-force activity followed by successful account compromise. Further investigation should examine the successful login, endpoint activity, source IP reputation, and subsequent actions performed by the admin account.

