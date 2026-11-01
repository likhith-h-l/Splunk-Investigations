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
