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
## 6. Investigation Results

The following table describes the findings that should be recorded after running the queries. The example values are illustrative and must be replaced if the actual Splunk output differs.

| Indicator | Illustrative Observation |
|---|---|
| Primary Event ID | `4740` |
| Supporting Event ID | `4625` |
| Affected Account | `john` |
| Failed Login Attempts | `15` |
| Caller Computer | `WORKSTATION-01` |
| Source IP | `192.168.1.105` (illustrative) |
| Account Lockout | Yes |
| Investigation Priority | Requires further investigation if activity is unauthorized |

### Evidence to Validate

- Whether Event ID 4740 is present in the actual dataset.
- Whether Event ID 4625 shows repeated failures against the same account.
- The exact affected username.
- The source IP address and workstation associated with the attempts.
- The failure status and substatus codes.
- Whether the attempts originated from one system or multiple systems.
- Whether a successful login (Event ID 4624) occurred after the failures.
- Whether the activity is associated with legitimate users, services, or stored credentials.

---

## 7. Findings

This investigation demonstrates a method for identifying and examining Windows account-lockout activity using Splunk.

The analysis focuses on three important areas:

1. **Account identification:** Determine which user account experienced repeated authentication failures or lockouts.
2. **Source analysis:** Identify the source IP address or workstation responsible for the authentication attempts.
3. **Authentication correlation:** Examine failed login events and account-lockout events to understand the activity sequence.

Repeated authentication failures followed by account lockouts can indicate password-guessing activity or a possible brute-force attempt.

However, account lockouts can also occur because of expired passwords, incorrect credentials, automated services, and applications using outdated stored passwords.

The final findings must be based on actual events returned by Splunk rather than on the illustrative examples in this report.

---
## 8. Conclusion

Account lockout activity is an important security indicator that SOC analysts monitor to identify potentially unauthorized authentication attempts.

Windows Security Event ID 4740 provides evidence of account-lockout activity, while Event ID 4625 provides information about failed authentication attempts.

By correlating these events and examining usernames, source IP addresses, workstation names, and timestamps, SOC analysts can identify suspicious authentication patterns.

Further investigation should examine:

- Windows Event ID 4625 for failed authentication attempts.
- Windows Event ID 4740 for account-lockout activity.
- Windows Event ID 4624 for successful authentication.
- Source IP addresses and workstation information.
- Authentication failure status and substatus codes.
- Whether multiple accounts are targeted from the same source.
- Whether one account is targeted from multiple sources.
- Active Directory authentication logs, where available.
- Whether legitimate services or applications are causing repeated failures.

### Final Assessment

> **Assessment: Investigate repeated authentication failures and account-lockout events by validating the affected accounts, source systems, and authentication timeline before determining whether the activity represents a brute-force attack or legitimate authentication problems.**

---

