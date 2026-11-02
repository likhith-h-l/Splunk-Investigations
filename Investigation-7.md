# Investigation #7 — Suspicious Account Lockout Activity

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Account Lockout / Authentication Investigation |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Primary Event ID | **4740 – A User Account Was Locked Out** |
| Supporting Event IDs | **4625 – An Account Failed to Log On**, **4624 – An Account Was Successfully Logged On** |
| Investigated Activity | Repeated Authentication Failures / Account Lockouts |
| Investigation Technique | Authentication Analysis / Brute-Force Detection |
| Target Host | `Likhi` (illustrative lab host) |
| Investigation Goal | Identify locked accounts, investigate repeated authentication failures, and determine whether the activity indicates a possible brute-force attack or misconfigured application |

---

## 2. Investigation Question

> **Are there user accounts experiencing repeated authentication failures and account lockouts that could indicate brute-force activity, password spraying, or unauthorized login attempts?**

---

## 3. SPL Query — Account Lockout Event Analysis

I started by checking whether Windows account-lockout events were available in the Splunk dataset.

### SPL Query

```spl
index=main EventCode=4740
| stats count by host
| sort - count
```

This query identifies hosts generating account-lockout events.

It helps determine whether Event ID 4740 is available in the current dataset.

### SPL Query — Account Lockout Details

```spl
index=main EventCode=4740
| eval locked_account=coalesce(TargetUserName, Account_Name, user)
| eval caller_computer=coalesce(CallerComputerName, Caller_Computer_Name)
| table _time host locked_account caller_computer
| sort 0 _time
```

This query searches for account-lockout events and displays the affected account, caller computer, host, and timestamp.

**Note:** Windows field names vary depending on the logging configuration. Inspect the raw event if important fields are empty and adapt the field names accordingly.

---

## 4. Investigation Timeline

The following is an **illustrative example of suspicious account-lockout activity**, not a verified result from the current Splunk dataset.

| Time | EventCode | Account | Caller Computer | Interpretation |
|---|---:|---|---|---|
| 10:15:12 | 4740 | john | WORKSTATION-01 | Account locked out |
| 10:16:30 | 4740 | john | WORKSTATION-01 | Additional lockout event requiring correlation |
| 10:18:45 | 4740 | john | WORKSTATION-01 | Repeated account-lockout activity |

### Example of Suspicious Authentication Activity

An illustrative scenario might involve repeated failed login attempts against the same account.

```text
Account: john
Source: WORKSTATION-01
Failed Authentication Attempts: 15
Account Lockout: Yes
Time Window: 5 Minutes
```

This example contains indicators worth investigating:

- Repeated failed authentication attempts — may indicate password guessing.
- Multiple lockout events — may indicate continued authentication problems.
- Repeated activity from one computer — may indicate a compromised device or misconfigured application.
- Unexpected login activity — may indicate unauthorized access attempts.

These indicators do not automatically prove a brute-force attack. Incorrect passwords, expired credentials, stored credentials, and background services can also cause account lockouts.

---


## 5. SPL Query — Detect Repeated Failed Authentication Attempts

To identify accounts experiencing repeated failed logins, I used the following query.

### SPL Query

```spl
index=main EventCode=4625
| eval username=coalesce(TargetUserName, Account_Name, user)
| eval source_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval workstation=coalesce(WorkstationName, Workstation_Name)
| stats count as failed_attempts
    values(source_ip) as source_ips
    values(workstation) as workstations
    by username
| where failed_attempts >= 5
| sort - failed_attempts
```

This query identifies accounts with five or more failed authentication events.

### SPL Query — Correlate Account Lockouts with Failed Logins

```spl
index=main (EventCode=4625 OR EventCode=4740)
| eval username=if(
    EventCode=4740,
    coalesce(TargetUserName, Account_Name),
    coalesce(TargetUserName, Account_Name, user)
)
| eval source_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval event_type=case(
    EventCode=4625, "Failed Login",
    EventCode=4740, "Account Lockout"
)
| stats
    count(eval(EventCode=4625)) as failed_logins
    count(eval(EventCode=4740)) as lockout_events
    values(source_ip) as source_ips
    values(event_type) as event_types
    by username
| where failed_logins >= 5 OR lockout_events > 0
| sort - failed_logins
```

This query correlates failed authentication attempts with account-lockout events.

It helps identify accounts that experienced repeated login failures and subsequent lockout activity.

### What These Queries Do

| SPL Component | Purpose |
|---|---|
| `EventCode=4625` | Searches failed login events |
| `EventCode=4740` | Searches account-lockout events |
| `coalesce()` | Handles alternative field names |
| `eval` | Creates normalized investigation fields |
| `stats` | Aggregates authentication events |
| `values()` | Displays unique source IPs and workstations |
| `where` | Filters accounts requiring investigation |
| `sort` | Ranks accounts by failed attempts |

**Important:** The correlation query aggregates events across the selected search period. It does not establish that failed logins occurred immediately before a lockout. Use a narrower time window and chronological event analysis to validate the sequence.

---

