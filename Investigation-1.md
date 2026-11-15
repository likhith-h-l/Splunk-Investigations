# Investigation 01 — Multiple Failed Login Attempts (Possible Brute Force)

## 1. Objective

Investigate repeated failed Windows authentication events, identify suspicious source IPs and targeted accounts, examine authentication timelines, and correlate failed logins with successful logins.

## 2. Environment

- SIEM: Splunk Enterprise
- Index: `main`
- Sourcetype: `csv`
- Event ID 4625: Failed logon
- Event ID 4624: Successful logon
- Dataset date: 2026-09-29

## 3. Initial Detection

The initial search identified **34 failed authentication events**.

### Failed logins by source IP

| Source IP | Failed attempts |
|---|---:|
| 10.10.10.50 | 30 |
| 10.10.10.60 | 4 |

The source IP `10.10.10.50` generated the highest number of failed authentication events.

## 4. Account Analysis

### Source IP: 10.10.10.50

| Username | Failed logins |
|---|---:|
| admin | 10 |
| john | 10 |
| backup | 10 |

All three accounts experienced repeated authentication failures.

### Timeline Analysis

Target system: `DC-01`

The events followed a repeating sequence:

- admin — every minute at second 00
- john — every minute at second 10
- backup — every minute at second 20

Time range: 01:30:00–01:39:20.

The consistent timing and repeating account sequence suggest automated or scripted authentication activity.

## 5. Successful Login Correlation

The investigation identified four successful authentication events from `10.10.10.50`.

| Username | Failed logins | Successful logins |
|---|---:|---:|
| admin | 10 | 4 |
| backup | 10 | 0 |
| john | 10 | 0 |

All four successful events involved `admin` on `DC-01`.

Successful login timestamps:

- 01:41:00
- 01:42:00
- 01:43:00
- 01:44:00

The successful authentication activity followed the repeated failed login sequence.

## 6. Secondary Source IP Analysis

### Source IP: 10.10.10.60

- Target system: `WS-01`
- Username: `alice`
- Failed logins: 4
- Successful logins: 4

The events alternated between failure and success:

| Time | Authentication result |
|---|---|
| 01:50:00 | Failed |
| 01:52:00 | Successful |
| 01:54:00 | Failed |
| 01:56:00 | Successful |
| 01:58:00 | Failed |
| 02:00:00 | Successful |
| 02:02:00 | Failed |
| 02:04:00 | Successful |

This pattern requires further validation to determine whether it represents legitimate retries or suspicious activity.

## 7. Key Findings

1. A total of 34 failed authentication events were identified.
2. The source IP `10.10.10.50` accounted for 30 failed attempts across three accounts.
3. Repeated authentication attempts followed a consistent timing pattern.
4. Four successful logins to the `admin` account followed the failed-login sequence.
5. The source IP `10.10.10.60` showed alternating failed and successful logins for `alice`.
6. Both source IPs require contextual validation before assigning malicious intent.

## 8. SOC Analyst Assessment

**Primary suspicious activity:** Repeated multi-account authentication failures from `10.10.10.50`, followed by successful authentication as `admin`.

**Secondary suspicious activity:** Alternating failed and successful authentication events from `10.10.10.60`.

**Assessment:** Possible automated credential attack or suspicious authentication activity.

**Confirmed account compromise:** Not established by the available evidence.

The investigation does not establish which passwords were attempted or whether the successful logins were unauthorized.

## 9. Recommended Further Investigation

1. Verify whether the successful `admin` logins were expected.
2. Identify the owner and role of source IP `10.10.10.50`.
3. Examine additional endpoint and authentication logs.
4. Review available logon types, authentication details and session identifiers.
5. Check subsequent activity performed by the `admin` account.
6. Validate whether the `alice` authentication pattern is normal for the user and workstation.

## 10. Conclusion

The investigation identified suspicious authentication patterns involving two source IPs.

The highest-priority finding was the sequence of 30 failed login attempts across three accounts from `10.10.10.50`, followed by four successful logins as `admin` on `DC-01`.

Further investigation is necessary to determine whether the activity represents an actual credential attack and whether unauthorized access occurred.

**Investigation Status:** Completed — initial authentication analysis.
