# Investigation #1 — Multiple Failed Login Attempts

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Brute-Force / Password-Spraying Detection |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Failed Logon Event | **4625** |
| Related Successful Logon Event | **4624** |
| Source IP | `10.10.10.50` |
| Target Host | `Likhi` |
| Targeted Accounts | `admin`, `john`, `backup` |
| Investigation Goal | Identify suspicious repeated authentication failures and determine whether a successful login followed them |

---

## 2. Investigation Question

> **Is the source IP `10.10.10.50` generating repeated failed authentication attempts against multiple user accounts?**

---

## 3. SPL Query — Failed Authentication Analysis

```spl
index=main EventCode=4625 src_ip=10.10.10.50
| table _time user src_ip host
| sort _time

4. Investigation Timeline
Time	EventCode	User	Source IP	Host	Interpretation
01:30:00	4625	admin	10.10.10.50	Likhi	Failed login
01:30:10	4625	john	10.10.10.50	Likhi	Failed login
01:30:20	4625	backup	10.10.10.50	Likhi	Failed login
01:31:00	4625	admin	10.10.10.50	Likhi	Failed login
01:31:10	4625	john	10.10.10.50	Likhi	Failed login
01:31:20	4625	backup	10.10.10.50	Likhi	Failed login
01:32:00	4625	admin	10.10.10.50	Likhi	Failed login
01:32:10	4625	john	10.10.10.50	Likhi	Failed login
01:32:20	4625	backup	10.10.10.50	Likhi	Failed login
...	...	...	...	...	Repeated failures
01:39:00	4625	admin	10.10.10.50	Likhi	Failed login
01:39:10	4625	john	10.10.10.50	Likhi	Failed login
01:39:20	4625	backup	10.10.10.50	Likhi	Failed login


Total failed authentication events: 30
5. Successful Login Check
After identifying the repeated failed authentication attempts, I investigated Event ID 4624 from the same source IP.
SPL Query
index=main EventCode=4624 src_ip=10.10.10.50
| table _time user src_ip host
| sort _time

Successful Authentication Results
Time	EventCode	User	Source IP	Host	Interpretation
01:41:00	4624	admin	10.10.10.50	Likhi	Successful login
01:42:00	4624	admin	10.10.10.50	Likhi	Successful login
01:43:00	4624	admin	10.10.10.50	Likhi	Successful login
01:44:00	4624	admin	10.10.10.50	Likhi	Successful login


6. Investigation Results
Indicator	Observation
Failed authentication events	30
Targeted accounts	3
Targeted users	admin, john, backup
Source IP	10.10.10.50
Target host	Likhi
Failure period	Approximately 9 minutes 20 seconds
Successful authentication events	4
Successful account	admin
First successful login	01:41:00
Suspicious pattern	Multiple accounts targeted from one source IP
Risk Assessment	HIGH


7. Findings
The investigation identified 30 failed authentication attempts originating from the source IP 10.10.10.50.
The attempts targeted three different accounts:
- admin
- john
- backup
The repeated failures occurred over approximately 9 minutes and 20 seconds.
A subsequent investigation of Event ID 4624 identified four successful authentication events for the admin account from the same source IP.
The combination of repeated failures against multiple accounts and subsequent successful authentication makes the activity suspicious.
8. Conclusion
The observed authentication pattern is consistent with possible password-spraying or brute-force activity originating from 10.10.10.50.
The subsequent successful authentication of the admin account increases the severity of the activity.
However, the available authentication logs alone do not confirm account compromise.
Further investigation should examine:
- Admin account activity after the successful login
- Process creation events
- Network connections
- File and system changes
- Source IP reputation
- Additional Windows Security events
- Subsequent authentication activity
Final Assessment
Risk: HIGH — Further investigation required.

9. Evidence
Evidence 1 — Failed Authentication Activity
Splunk screenshot showing the Event ID 4625 failed authentication events from 10.10.10.50.
Evidence 2 — Successful Authentication Activity
Splunk screenshot showing the Event ID 4624 successful authentication events for the admin account.
Evidence 3 — Authentication Pattern
Splunk screenshots demonstrating the sequence of repeated failed authentication attempts followed by successful authentication from the same source IP.
10. Key Indicators
Indicator	Value
Source IP	10.10.10.50
Host	Likhi
Failed Event	4625
Successful Event	4624
Failed Attempts	30
Targeted Accounts	3
Successful Account	admin
Successful Logins	4
Risk	HIGH
