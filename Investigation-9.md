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

