# Investigation #4 — High-Volume Authentication Source Triage and Lookup Enrichment

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | High-Volume Authentication Activity Analysis |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Primary Event | **4625 – Failed Logon** |
| Analysis Techniques | `tstats`, `stats`, `lookup`, `fillnull`, `outputlookup`, `inputlookup` |
| Source IP | `10.10.10.50` |
| Target Host | `Likhi` |
| Investigation Goal | Identify high-volume authentication sources, enrich suspicious results with asset information, and save the findings for future investigations |

---

## 2. Investigation Question

> **Which hosts and source IPs are generating high-volume failed authentication activity, and can the suspicious results be enriched and saved for future investigation?**

---

## 3. SPL Query — Initial Host Activity Triage

To quickly identify hosts generating a high volume of events, I used the `tstats` command.

```spl
| tstats count where index=main by host
| sort - count
```

This provides a fast summary of event volume by host and can help prioritize hosts for further investigation.

### Failed Authentication Analysis

After identifying active hosts, I investigated failed authentication activity using Event ID **4625**.

```spl
index=main EventCode=4625
| stats count as failed_attempts dc(user) as unique_users values(user) as targeted_users by src_ip
| sort - failed_attempts
```

This query identifies source IPs generating large numbers of failed authentication attempts and shows how many different accounts were targeted.

---

## 4. Investigation Timeline

The failed authentication activity from the highest-volume suspicious source IP was reviewed chronologically.

| Time | EventCode | User | Source IP | Host | Interpretation |
|---|---:|---|---|---|---|
| 01:30:00 | 4625 | admin | 10.10.10.50 | Likhi | Failed authentication |
| 01:30:10 | 4625 | john | 10.10.10.50 | Likhi | Failed authentication |
| 01:30:20 | 4625 | backup | 10.10.10.50 | Likhi | Failed authentication |
| 01:31:00 | 4625 | admin | 10.10.10.50 | Likhi | Repeated failure |
| 01:31:10 | 4625 | john | 10.10.10.50 | Likhi | Repeated failure |
| 01:31:20 | 4625 | backup | 10.10.10.50 | Likhi | Repeated failure |
| 01:32:00 | 4625 | admin | 10.10.10.50 | Likhi | Repeated failure |
| 01:32:10 | 4625 | john | 10.10.10.50 | Likhi | Repeated failure |
| 01:32:20 | 4625 | backup | 10.10.10.50 | Likhi | Repeated failure |
| ... | ... | ... | ... | ... | Continued failed authentication |
| 01:39:00 | 4625 | admin | 10.10.10.50 | Likhi | Repeated failure |
| 01:39:10 | 4625 | john | 10.10.10.50 | Likhi | Repeated failure |
| 01:39:20 | 4625 | backup | 10.10.10.50 | Likhi | Repeated failure |

**Total failed authentication events: 30**

---

## 5. Lookup Enrichment

After identifying `10.10.10.50` as a high-volume authentication source, I used the `asset_inventory` lookup to enrich the event with additional asset information.

### SPL Query

```spl
index=main EventCode=4625 src_ip=10.10.10.50
| lookup asset_inventory src_ip OUTPUT department
| fillnull value="Unknown" department
| stats count as failed_attempts dc(user) as unique_users values(user) as targeted_users values(department) as department by src_ip
```

The `lookup` command attempts to associate the source IP with asset information, while `fillnull` ensures that missing department information is represented as `Unknown`.

### Expected Investigation Fields

| Field | Purpose |
|---|---|
| `src_ip` | Source generating the authentication attempts |
| `failed_attempts` | Total failed authentication attempts |
| `unique_users` | Number of different targeted accounts |
| `targeted_users` | Accounts targeted by the source |
| `department` | Asset context from the lookup |

---

## 6. Investigation Results

| Indicator | Observation |
|---|---|
| Source IP | `10.10.10.50` |
| Target host | `Likhi` |
| Failed authentication events | **30** |
| Targeted accounts | **3** |
| Targeted users | `admin`, `john`, `backup` |
| Authentication event | **4625** |
| Authentication pattern | High-volume repeated failures |
| Asset enrichment | `asset_inventory` lookup used |
| Missing lookup values | Replaced with `Unknown` using `fillnull` |
| Investigation Priority | **HIGH** |

---

## 7. Save Investigation Results

After identifying the suspicious authentication source, I created a reusable investigation dataset.

### SPL Query

```spl
index=main EventCode=4625 src_ip=10.10.10.50
| stats count as failed_attempts dc(user) as unique_users values(user) as targeted_users by src_ip
| eval risk=case(
    failed_attempts >= 100, "CRITICAL",
    failed_attempts >= 50, "HIGH",
    failed_attempts >= 20, "MEDIUM",
    true(), "LOW"
)
| outputlookup suspicious_authentication_ips.csv
```

This saves the suspicious source IP and investigation statistics into a lookup file for future analysis.

### Read the Saved Results

```spl
| inputlookup suspicious_authentication_ips.csv
```

The saved lookup can later be reused for:

- IOC matching
- Investigation enrichment
- Detection rules
- Repeated monitoring
- Future authentication investigations

---

## 8. Findings

The investigation identified `10.10.10.50` as a high-volume source of failed authentication activity.

A total of **30 Event ID 4625** failed authentication events were observed against three different accounts:

- `admin`
- `john`
- `backup`

The repeated attempts originated from the same source IP and targeted multiple accounts on the `Likhi` host.

The `asset_inventory` lookup was used to add contextual information to the source IP. The `fillnull` command was used to handle any missing lookup information without leaving blank values in the investigation results.

The suspicious authentication results were then saved using `outputlookup`, allowing the data to be reused in future investigations through `inputlookup`.

---

## 9. Conclusion

The investigation identified a **high-volume failed authentication source** generating repeated Event ID 4625 activity against multiple user accounts.

The activity is consistent with suspicious authentication behavior and may indicate **password-spraying or brute-force activity**.

This investigation also demonstrated how Splunk can be used not only to detect suspicious activity, but also to:

- Perform rapid statistical triage using `tstats`
- Enrich events using `lookup`
- Handle missing information using `fillnull`
- Save investigation results using `outputlookup`
- Reuse saved results using `inputlookup`

The authentication data alone does **not confirm account compromise**.

Further investigation should correlate these findings with successful authentication events, endpoint activity, network activity, and additional security logs.

### Final Assessment

> **Risk: HIGH — Suspicious high-volume authentication activity requires further investigation.**

---

