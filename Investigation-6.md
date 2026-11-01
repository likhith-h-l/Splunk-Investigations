# Investigation #6 — Suspicious Scheduled Task Creation

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Persistence / Scheduled Task Investigation |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Primary Event ID | **4698 – A Scheduled Task Was Created** |
| Supporting Event IDs | **4702 – A Scheduled Task Was Updated**, **4699 – A Scheduled Task Was Deleted** |
| Investigated Activity | Windows Scheduled Task Creation |
| Investigation Technique | Persistence Analysis / Task Command Analysis |
| Target Host | `Likhi` (illustrative lab host) |
| Investigation Goal | Identify newly created scheduled tasks and investigate suspicious task names, execution commands, and user accounts |

---

## 2. Investigation Question

> **Are there newly created scheduled tasks containing suspicious execution commands, unusual task names, or unexpected user activity that could indicate unauthorized persistence?**

---

## 3. SPL Query — Scheduled Task Event Analysis

I started by checking whether Windows scheduled-task creation events were available in the Splunk dataset.

### SPL Query

```spl
index=main EventCode=4698
| stats count by host
| sort - count
```

This query identifies hosts generating scheduled-task creation events.

It helps determine whether Event ID 4698 is available in the current dataset.

### SPL Query — Scheduled Task Creation Details

```spl
index=main EventCode=4698
| eval actor=coalesce(SubjectUserName, user, AccountName)
| eval task_name=coalesce(TaskName, Task_Name, taskname)
| eval task_content=coalesce(TaskContent, Task_Content, taskcontent)
| table _time host actor task_name task_content
| sort 0 _time
```

This query searches for scheduled-task creation events and displays the associated user, task name, task definition, host, and timestamp.

**Note:** Windows field names vary depending on the logging configuration. Inspect the raw event if important fields are empty and adapt the field names accordingly.

---

## 4. Investigation Timeline

The following is an **illustrative example of a suspicious scheduled-task creation event**, not a verified result from the current Splunk dataset.

| Time | EventCode | User | Task Name | Interpretation |
|---|---:|---|---|---|
| 03:15:22 | 4698 | john | `WindowsUpdateCheck` | Newly created task requiring investigation |

### Example of a Suspicious Task Command

An illustrative scheduled-task action might contain:

```text
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1
```

This example contains indicators worth investigating:

- `powershell.exe` — Executes PowerShell commands.
- `-WindowStyle Hidden` — Requests a hidden PowerShell window.
- `-ExecutionPolicy Bypass` — Bypasses the PowerShell execution policy for that process.
- `C:\Users\Public\update.ps1` — A script stored in a publicly accessible directory.

These indicators do not automatically prove malicious activity. Legitimate administrative tasks can also use PowerShell and scheduled execution.

---

## 5. SPL Query — Suspicious Scheduled Task Indicators

To identify scheduled tasks containing potentially suspicious execution patterns, I used the following query.

### SPL Query

```spl
index=main EventCode=4698
| eval actor=coalesce(SubjectUserName, user, AccountName)
| eval task_name=lower(coalesce(TaskName, Task_Name, taskname))
| eval task_content=lower(coalesce(TaskContent, Task_Content, taskcontent))
| eval suspicious_indicator=if(
    like(task_content, "%powershell%")
    OR like(task_content, "%-windowstyle hidden%")
    OR like(task_content, "%executionpolicy bypass%")
    OR like(task_content, "%-enc %")
    OR like(task_content, "%encodedcommand%")
    OR like(task_content, "%wscript.exe%")
    OR like(task_content, "%cscript.exe%")
    OR like(task_content, "%-downloadstring%"),
    "Suspicious execution indicator",
    "Scheduled task - review context"
)
| table _time host actor task_name task_content suspicious_indicator
| sort 0 _time
```

### What This Query Does

| SPL Component | Purpose |
|---|---|
| `EventCode=4698` | Searches scheduled-task creation events |
| `coalesce()` | Handles alternative field names |
| `lower()` | Converts text to lowercase |
| `like()` | Searches for suspicious command patterns |
| `eval` | Creates a classification field |
| `table` | Displays investigation evidence |
| `sort` | Organizes events chronologically |

The classification identifies potentially suspicious execution patterns. It is a hunting aid, not a definitive malware verdict.

---

## 6. Investigation Results

The following table describes the findings that should be recorded after running the queries. The example values are illustrative and must be replaced if the actual Splunk output differs.

| Indicator | Illustrative Observation |
|---|---|
| Event ID | `4698` |
| Activity | Scheduled Task Creation |
| Task Name | `WindowsUpdateCheck` |
| Executable | `powershell.exe` |
| Execution Option | Hidden Window / Execution Policy Bypass |
| Script Location | `C:\Users\Public\update.ps1` |
| User | `john` |
| Target Host | `Likhi` |
| Investigation Priority | Requires further investigation if the task is unauthorized |

### Evidence to Validate

- Whether Event ID 4698 is present in the actual dataset.
- The exact scheduled-task name.
- The account responsible for creating the task.
- The executable and arguments configured in the task.
- Whether the task runs at startup, logon, or a recurring interval.
- Whether the referenced executable or script exists.
- Whether the task is authorized by the system administrator.
- Whether related process-creation events or endpoint detection alerts exist.

---

## 7. Findings

This investigation demonstrates a method for identifying and examining scheduled-task creation events in Windows Security logs.

The analysis focuses on three important areas:

1. **Task identification:** Determine which scheduled task was created.
2. **Execution analysis:** Examine the executable, script path, and command-line arguments.
3. **User attribution:** Identify which account created the scheduled task.

An unexpected scheduled task combined with hidden PowerShell execution, suspicious script locations, or unauthorized user activity can indicate a possible persistence mechanism.

However, scheduled tasks are also commonly used by Windows and legitimate applications for routine maintenance.

The final findings must be based on actual events returned by Splunk rather than on the illustrative examples in this report.

---

## 8. Conclusion

Windows Scheduled Tasks provide a legitimate mechanism for automating recurring system operations.

However, attackers can abuse this functionality to maintain persistence and execute malicious programs automatically.

Windows Security Event ID 4698 provides useful evidence about scheduled-task creation. Analysing task names, execution commands, user accounts, and task definitions can help SOC analysts identify potentially unauthorized persistence mechanisms.

Further investigation should examine:

- The complete scheduled-task XML definition.
- The task's execution trigger and frequency.
- The executable or script referenced by the task.
- Windows process-creation events (Event ID 4688).
- PowerShell script-block logging (Event ID 4104), where available.
- Related file creation and modification events.
- Endpoint Detection and Response (EDR) alerts.
- Whether the task is associated with legitimate administrative activity.

### Final Assessment

> **Assessment: Investigate newly created scheduled tasks and validate their execution commands, associated user accounts, and task configurations before determining whether unauthorized persistence is present.**

---

## 9. Evidence

### Evidence 1 — Scheduled Task Creation Events

Add a Splunk screenshot showing available Event ID 4698 events.

### Evidence 2 — Scheduled Task Details

Add a screenshot showing the task name, associated user, and task definition.

### Evidence 3 — Suspicious Command Analysis

Add a screenshot showing potentially suspicious execution commands, including PowerShell arguments or script paths.

### Evidence 4 — Corroborating Activity

If available, add evidence from Event ID 4688, PowerShell Event ID 4104, or EDR telemetry.

---

## 10. Key Indicators

| Indicator | Value |
|---|---|
| Windows Event ID | `4698` |
| Supporting Event IDs | `4702`, `4699` |
| Activity of Interest | Scheduled Task Creation |
| Key Fields | Task Name, Task Content, User, Host, Timestamp |
| Investigation Technique | Persistence Analysis |
| Detection Method | Scheduled Task Command Analysis |
| Suspicious Patterns | Hidden PowerShell, Encoded Commands, Execution Policy Bypass |
| Supporting Evidence | Windows Security Logs, PowerShell Logs, EDR, Process Telemetry |
| Risk Decision | Based on validated evidence and investigation context |
