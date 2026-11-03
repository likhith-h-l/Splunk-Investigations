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

## 6. Investigation Results

The following table describes the findings that should be recorded after running the queries. The example values are illustrative and must be replaced if the actual Splunk output differs.

| Indicator | Illustrative Observation |
|---|---|
| Primary Event ID | `4624` |
| Logon Type | `10` |
| Activity | Successful RDP Login |
| Username | `administrator` |
| Source IP | `185.XX.XX.XX` (illustrative) |
| Destination Host | `Likhi` |
| Login Time | `22:10:15` |
| Investigation Priority | Requires further investigation if the source is unauthorized |

### Evidence to Validate

- Whether Event ID 4624 is present in the actual dataset.
- Whether Logon Type 10 is present in the authentication events.
- The exact username associated with the remote session.
- The source IP address of the connection.
- The destination host receiving the connection.
- Whether the source IP belongs to an authorized network or VPN.
- Whether the login occurred during an expected time.
- Whether corresponding failed authentication events (4625) occurred.
- Whether the account has administrative privileges.
- Whether subsequent suspicious process activity occurred after login.

---

## 7. Findings

This investigation demonstrates a method for identifying and examining Remote Desktop login activity using Windows Security logs.

The analysis focuses on three important areas:

1. **Logon identification:** Determine whether successful authentication events involve RemoteInteractive logons.
2. **Source analysis:** Identify the IP address and workstation associated with the remote connection.
3. **Account analysis:** Examine which user account accessed the remote system and whether the activity was expected.

Successful RDP logins from unfamiliar sources, privileged accounts, or unusual time periods can indicate potentially unauthorized remote access.

However, RDP is a legitimate remote administration feature, and unusual login activity must be validated against authorized access records.

The final findings must be based on actual events returned by Splunk rather than on the illustrative examples in this report.

---
## 8. Conclusion

Remote Desktop Protocol provides administrators and authorized users with remote access to Windows systems.

However, attackers can abuse RDP to gain access to compromised systems and perform additional malicious activities.

Windows Security Event ID 4624 provides useful evidence about successful authentication. Logon Type 10 is particularly relevant because it identifies RemoteInteractive logons.

By analysing usernames, source IP addresses, destination hosts, and authentication timestamps, SOC analysts can identify potentially unauthorized remote access.

Further investigation should examine:

- Windows Event ID 4625 for failed remote authentication attempts.
- Windows Event ID 4624 for successful remote logins.
- Windows Event ID 4634 for logoff activity.
- Windows Event ID 4672 for special privileges assigned to new logon sessions.
- Source IP address reputation and ownership.
- VPN and firewall connection logs.
- Account privileges and authorized remote access policies.
- Process creation events (4688) following the remote login.
- Endpoint Detection and Response (EDR) alerts.
- Whether the remote session initiated suspicious commands or file transfers.

### Final Assessment

> **Assessment: Investigate successful RemoteInteractive logons by validating the source IP address, user account, destination host, and surrounding authentication activity before determining whether unauthorized remote access occurred.**

---
## 9. Evidence

### Evidence 1 — Successful Authentication Events

Add a Splunk screenshot showing available Event ID 4624 events.

### Evidence 2 — RDP Login Analysis

Add a screenshot showing successful logins filtered by Logon Type 10.

### Evidence 3 — Source IP Analysis

Add a screenshot showing the source IP addresses, usernames, and destination hosts associated with RDP activity.

### Evidence 4 — Failed Login Correlation

If available, add evidence showing Event ID 4625 events associated with the same accounts or source systems.

### Evidence 5 — Post-Login Activity

If available, add evidence from Event ID 4688 or EDR telemetry showing processes executed after the remote login.

---

## 10. Key Indicators

| Indicator | Value |
|---|---|
| Primary Windows Event ID | `4624` |
| Supporting Event IDs | `4625`, `4634`, `4672` |
| Logon Type | `10 – RemoteInteractive` |
| Activity of Interest | Remote Desktop Login |
| Key Fields | Username, Source IP, Destination Host, Logon Type, Timestamp |
| Investigation Technique | Remote Access Analysis |
| Detection Method | RDP Authentication Monitoring |
| Suspicious Patterns | Unfamiliar Source IPs, Privileged Account Logins, Unusual Login Times |
| Supporting Evidence | Windows Security Logs, VPN Logs, Firewall Logs, EDR Telemetry |
| Risk Decision | Based on validated evidence and investigation context |

---

**Investigation Status:** Pending validation against actual Splunk events.



