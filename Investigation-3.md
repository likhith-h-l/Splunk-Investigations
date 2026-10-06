# Investigation #3 — Rapid Authentication Activity Using Time-Based Correlation

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Time-Based Authentication Analysis |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Authentication Events | **4625 – Failed Logon**, **4624 – Successful Logon** |
| Source IP | `10.10.10.50` |
| Target Host | `Likhi` |
| Investigation Technique | Time-Based Correlation using `streamstats` |
| Investigation Goal | Identify authentication events occurring within a short time interval from the same source IP |

---

## 2. Investigation Question

> **Are multiple authentication events from the source IP `10.10.10.50` occurring within a short time interval, indicating rapid authentication activity?**

---

## 3. SPL Query — Time-Based Authentication Analysis

```spl
index=main (EventCode=4625 OR EventCode=4624) src_ip=10.10.10.50
| sort 0 _time
| streamstats current=f last(_time) as previous_time by src_ip
| eval time_difference = _time - previous_time
| where time_difference <= 60
| table _time EventCode user src_ip previous_time time_difference host
```

This query calculates the time difference between the current authentication event and the previous event from the same source IP.

The `current=f` option ensures that `previous_time` represents the timestamp of the **previous event**, allowing the time interval between authentication events to be calculated.

---

## 4. Investigation Timeline

Based on the authentication events observed from `10.10.10.50`, several events occurred within a short time interval.

| Time | EventCode | User | Source IP | Time Difference | Interpretation |
|---|---:|---|---|---:|---|
| 01:30:00 | 4625 | admin | 10.10.10.50 | — | First observed event |
| 01:30:10 | 4625 | john | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:30:20 | 4625 | backup | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:31:00 | 4625 | admin | 10.10.10.50 | 40 sec | Rapid authentication event |
| 01:31:10 | 4625 | john | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:31:20 | 4625 | backup | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:32:00 | 4625 | admin | 10.10.10.50 | 40 sec | Rapid authentication event |
| 01:32:10 | 4625 | john | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:32:20 | 4625 | backup | 10.10.10.50 | 10 sec | Rapid authentication event |
| ... | ... | ... | ... | ... | Continued rapid activity |
| 01:39:00 | 4625 | admin | 10.10.10.50 | 40 sec | Rapid authentication event |
| 01:39:10 | 4625 | john | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:39:20 | 4625 | backup | 10.10.10.50 | 10 sec | Rapid authentication event |
| 01:41:00 | 4624 | admin | 10.10.10.50 | 100 sec | Successful login after activity |
| 01:42:00 | 4624 | admin | 10.10.10.50 | 60 sec | Successful authentication |
| 01:43:00 | 4624 | admin | 10.10.10.50 | 60 sec | Successful authentication |
| 01:44:00 | 4624 | admin | 10.10.10.50 | 60 sec | Successful authentication |

---

## 5. Time-Based Correlation Results

The investigation used a **60-second threshold** to identify authentication events occurring within one minute of the previous event from the same source IP.

### SPL Query

```spl
index=main (EventCode=4625 OR EventCode=4624) src_ip=10.10.10.50
| sort 0 _time
| streamstats current=f last(_time) as previous_time by src_ip
| eval time_difference = _time - previous_time
| where time_difference <= 60
| table _time EventCode user src_ip previous_time time_difference host
```

### Correlation Logic

```text
Current Authentication Event
          ↓
Previous Event from Same IP
          ↓
Calculate Time Difference
          ↓
time_difference <= 60 seconds
          ↓
Rapid Authentication Activity
```

---

## 6. Investigation Results

| Indicator | Observation |
|---|---|
| Source IP | `10.10.10.50` |
| Target host | `Likhi` |
| Time correlation threshold | **60 seconds** |
| Authentication events analyzed | Event IDs **4625 and 4624** |
| Rapid authentication pattern | Multiple events occurred within **60 seconds** |
| Shortest observed interval | **10 seconds** |
| Failed authentication activity | Repeated 4625 events |
| Successful authentication activity | 4624 events for `admin` |
| Time-based pattern | Rapid authentication events from the same source IP |
| Risk Assessment | **MEDIUM-HIGH** |

---

## 7. Findings

The investigation identified multiple authentication events from the source IP `10.10.10.50` occurring within a short time interval.

Several authentication events occurred only **10 seconds apart**, while other events occurred within **40–60 seconds**.

The rapid sequence was primarily associated with repeated **4625 failed authentication events** targeting the `admin`, `john`, and `backup` accounts.

Following this activity, **4624 successful authentication events** for the `admin` account were also observed.

The time-based correlation demonstrates that the authentication activity was not isolated events spread across a long period, but instead occurred in a relatively rapid sequence.

---

## 8. Conclusion

The time-based analysis identified **rapid authentication activity** originating from `10.10.10.50`, with multiple authentication events occurring within a 60-second window.

The repeated short intervals between authentication events, combined with the previously observed failed authentication activity against multiple accounts, make the activity **suspicious and worthy of further investigation**.

The time-based analysis alone does **not confirm malicious activity or account compromise**.

Further investigation should examine:

- Authentication failure reasons
- Successful `admin` login activity
- Process creation events
- Network connections
- Source IP reputation
- Account activity following successful authentication
- Additional Windows Security events

### Final Assessment

> **Risk: MEDIUM-HIGH — Suspicious rapid authentication activity requires further investigation.**

---

## 9. Evidence

### Evidence 1 — Time-Based Correlation

Splunk screenshot showing the `time_difference` field calculated using `streamstats`.

### Evidence 2 — Rapid Authentication Events

Splunk screenshot showing multiple authentication events occurring within **60 seconds** from `10.10.10.50`.

### Evidence 3 — Authentication Sequence

Splunk screenshot showing the sequence of repeated **4625 failed logons** followed by **4624 successful authentication events**.

---

## 10. Key Indicators

| Indicator | Value |
|---|---|
| Source IP | `10.10.10.50` |
| Host | `Likhi` |
| Failed Event | `4625` |
| Successful Event | `4624` |
| Time Correlation Threshold | **60 seconds** |
| Shortest Observed Interval | **10 seconds** |
| Targeted Accounts | `admin`, `john`, `backup` |
| Successful Account | `admin` |
| Risk | **MEDIUM-HIGH** |
