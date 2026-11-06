# Investigation #9 — Suspicious Windows Service Creation

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Persistence / Windows Service Investigation |
| SIEM | Splunk Enterprise |
| Log Source | Windows System Events |
| Primary Event ID | **7045 – A Service Was Installed in the System** |
| Supporting Event IDs | **4697 – A Service Was Installed in the System**, **7036 – A Service Entered a Running or Stopped State** |
| Investigated Activity | Windows Service Creation and Execution |
| Investigation Technique | Service Analysis / Persistence Detection |
| Target Host | `Likhi` (illustrative lab host) |
| Investigation Goal | Identify newly installed Windows services and investigate suspicious service names, executable paths, and service accounts |

---

## 2. Investigation Question

> **Are there newly installed Windows services with unusual names, suspicious executable paths, or unexpected service accounts that could indicate unauthorized persistence or malicious execution?**

---

## 3. SPL Query — Windows Service Creation Analysis

I started by checking whether Windows service installation events were available in the Splunk dataset.

### SPL Query

```spl
index=main EventCode=7045
| stats count by host
| sort - count
```

This query identifies hosts generating Windows service installation events.

It helps determine whether Event ID 7045 is available in the current dataset.

### SPL Query — Service Creation Details

```spl
index=main EventCode=7045
| eval service_name=coalesce(Service_Name, ServiceName)
| eval service_file=coalesce(ImagePath, Image_Path)
| eval service_account=coalesce(ServiceAccount, AccountName)
| table _time host service_name service_file service_account
| sort 0 _time
```

This query searches for newly installed services and displays the service name, executable path, associated account, host, and timestamp.

**Note:** Windows field names vary depending on the logging configuration. Inspect the raw event and adapt the field names if important columns are empty. Event ID 7045 is normally recorded in the Windows System log.

---
## 4. Investigation Timeline

The following is an **illustrative example of suspicious Windows service creation**, not a verified result from the current Splunk dataset.

| Time | EventCode | Service Name | Executable Path | Interpretation |
|---|---:|---|---|---|
| 01:20:15 | 7045 | WindowsUpdateService | `C:\Users\Public\update.exe` | Newly installed service requiring investigation |
| 01:21:10 | 7036 | WindowsUpdateService | Not applicable | Service entered running state |

### Example of a Suspicious Service Configuration

An illustrative service configuration might contain:

```text
Service Name: WindowsUpdateService
Image Path: C:\Users\Public\update.exe
Service Account: LocalSystem
Startup Type: Automatic
```

This example contains indicators worth investigating:

- Unusual executable location — An executable running from a publicly accessible directory may require additional scrutiny.
- Misleading service name — A service name resembling a legitimate Windows component may be used to avoid attention.
- LocalSystem account — The service operates with highly privileged system permissions.
- Automatic startup — The service may execute automatically when Windows starts.

These indicators do not automatically prove malicious activity. Legitimate software and administrative tools also create Windows services.

---

## 5. SPL Query — Suspicious Service Creation Indicators

To identify services with potentially suspicious executable paths and configurations, I used the following query.

### SPL Query

```spl
index=main EventCode=7045
| eval service_name=lower(coalesce(Service_Name, ServiceName))
| eval service_file=lower(coalesce(ImagePath, Image_Path))
| eval service_account=coalesce(ServiceAccount, AccountName)
| eval suspicious_indicator=case(
    like(service_file, "%\\users\\public\\%"),
        "Executable in Public directory - review",
    like(service_file, "%\\temp\\%"),
        "Executable in Temp directory - review",
    like(service_file, "%\\appdata\\%"),
        "Executable in AppData directory - review",
    like(service_file, "%powershell%"),
        "PowerShell service execution - review",
    like(service_file, "%cmd.exe%"),
        "Command interpreter execution - review",
    true(),
        "Service creation - review context"
)
| table _time host service_name service_file service_account suspicious_indicator
| sort 0 _time
```

This query identifies newly installed services and classifies potentially suspicious executable locations and execution patterns.

### SPL Query — Service Creation Frequency Analysis

```spl
index=main EventCode=7045
| eval service_name=coalesce(Service_Name, ServiceName)
| eval service_file=coalesce(ImagePath, Image_Path)
| stats count as service_creation_count
    values(service_file) as executable_paths
    by host service_name
| sort - service_creation_count
```

This query summarizes service creation activity by host and service name.

It helps identify repeated service installation activity and provides executable paths for further investigation.

### What These Queries Do

| SPL Component | Purpose |
|---|---|
| `EventCode=7045` | Searches Windows service installation events |
| `coalesce()` | Handles alternative field names |
| `lower()` | Converts text to lowercase |
| `like()` | Searches for suspicious executable paths |
| `case()` | Classifies potentially suspicious service configurations |
| `stats` | Aggregates service creation activity |
| `values()` | Displays unique executable paths |
| `table` | Displays investigation evidence |
| `sort` | Organizes results |

The classification identifies service configurations requiring review. It is a hunting aid, not a definitive malware verdict.

---
