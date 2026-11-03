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

## 4. Investigation Timeline

The following is an **illustrative example of suspicious RDP login activity**, not a verified result from the current Splunk dataset.

| Time | EventCode | User | Source IP | Logon Type | Interpretation |
|---|---:|---|---|---:|---|
| 22:10:15 | 4624 | john | 185.XX.XX.XX | 10 | Successful remote interactive login |
| 22:12:30 | 4624 | administrator | 185.XX.XX.XX | 10 | Additional remote login requiring investigation |

### Example of Suspicious Remote Access Activity

An illustrative scenario might involve an administrator account logging in remotely from an unfamiliar external IP address.

```text
Username: administrator
Source IP: 185.XX.XX.XX
Destination Host: Likhi
Logon Type: 10
Authentication Status: Successful
Login Time: 22:10:15
```

This example contains indicators worth investigating:

- Logon Type 10 — Indicates a RemoteInteractive login, commonly associated with RDP.
- Unfamiliar source IP — May indicate remote access from an unauthorized location.
- Administrator account — Privileged account access requires additional scrutiny.
- Unusual login time — May indicate activity outside normal working hours.

These indicators do not automatically prove malicious activity. Authorized administrators and remote employees also use RDP.

---

## 5. SPL Query — Suspicious RDP Login Indicators

To identify potentially suspicious remote login patterns, I used the following query.

### SPL Query

```spl
index=main EventCode=4624
| eval logon_type=coalesce(Logon_Type, LogonType)
| eval username=coalesce(TargetUserName, Account_Name, user)
| eval source_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| where logon_type=10
| eval suspicious_indicator=case(
    username="administrator", "Privileged account RDP login - review",
    isnull(source_ip) OR source_ip="-", "Source IP unavailable - review",
    true(), "RDP login - review context"
)
| table _time host username source_ip logon_type suspicious_indicator
| sort 0 _time
```

This query identifies successful RDP logins and highlights privileged account usage and missing source IP information.

### SPL Query — Identify RDP Login Sources

```spl
index=main EventCode=4624
| eval logon_type=coalesce(Logon_Type, LogonType)
| eval username=coalesce(TargetUserName, Account_Name, user)
| eval source_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| where logon_type=10
| stats count as rdp_logins
    values(username) as usernames
    values(host) as destination_hosts
    by source_ip
| sort - rdp_logins
```

This query identifies source IP addresses associated with RDP logins and counts their occurrences.

It helps analysts identify frequently used remote access sources and investigate unfamiliar connections.

### What These Queries Do

| SPL Component | Purpose |
|---|---|
| `EventCode=4624` | Searches successful authentication events |
| `Logon_Type=10` | Identifies RemoteInteractive logons |
| `coalesce()` | Handles alternative field names |
| `where` | Filters RDP-related authentication events |
| `case()` | Classifies investigation indicators |
| `stats` | Aggregates RDP login activity |
| `values()` | Displays unique usernames and destination hosts |
| `sort` | Ranks results by login count |

The classification identifies events requiring review. It is not a definitive malicious activity verdict.

---


