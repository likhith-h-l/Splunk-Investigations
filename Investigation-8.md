# Investigation #8 — Suspicious Remote Desktop (RDP) Login Activity

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Remote Access / Authentication Investigation |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Primary Event ID | **4624 – An Account Was Successfully Logged On** |
| Supporting Event IDs | **4625 – An Account Failed to Log On**, **4634 – An Account Was Logged Off** |
| Investigated Activity | Remote Desktop Protocol (RDP) Logins |
| Investigation Technique | Logon Type Analysis / Remote Access Monitoring |
| Target Host | `Likhi` (illustrative lab host) |
| Investigation Goal | Identify successful RDP logins and investigate unusual source IP addresses, user accounts, and remote access patterns |

---

## 2. Investigation Question

> **Are there successful Remote Desktop logins originating from unusual source IP addresses, unexpected user accounts, or suspicious authentication patterns that could indicate unauthorized remote access?**

---

## 3. SPL Query — Successful Logon Event Analysis

I started by checking whether Windows successful logon events were available in the Splunk dataset.

### SPL Query

```spl
index=main EventCode=4624
| stats count by host
| sort - count
```

This query identifies hosts generating successful authentication events.

It helps determine whether Event ID 4624 is available in the current dataset.

### SPL Query — Identify RDP Logins

```spl
index=main EventCode=4624 Logon_Type=10
| eval username=coalesce(TargetUserName, Account_Name, user)
| eval source_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval workstation=coalesce(WorkstationName, Workstation_Name)
| table _time host username source_ip workstation Logon_Type
| sort 0 _time
```

This query searches for successful Remote Desktop logins using Logon Type 10.

**Note:** Windows field names vary depending on the logging configuration. The logon type may be extracted as `Logon_Type` or `LogonType`. Inspect the raw event and adapt the field names accordingly.

---

