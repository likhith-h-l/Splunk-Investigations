# Investigation #5 — Suspicious PowerShell Activity

## 1. Investigation Objective

| Field | Details |
|---|---|
| Investigation Type | Suspicious Process Creation / PowerShell Investigation |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Events |
| Primary Event ID | **4688 – A New Process Has Been Created** |
| Investigated Process | `powershell.exe` / `pwsh.exe` |
| Investigation Technique | Process Analysis / Command-Line Analysis |
| Target Host | `Likhi` (illustrative lab host) |
| Investigation Goal | Identify PowerShell process creation events and investigate potentially suspicious command-line arguments and parent processes |

---

## 2. Investigation Question

> **Are there PowerShell process-creation events with suspicious command-line arguments or unusual parent processes that require further investigation?**

---

## 3. SPL Query — Process Creation Analysis

I started by checking whether Windows process-creation events were available in the Splunk dataset.

### SPL Query

```spl
index=main EventCode=4688
| stats count by host
| sort - count
```

This query identifies hosts with Event ID 4688 events and helps determine whether process-creation activity is available for investigation.

### SPL Query — Search for PowerShell Activity

```spl
index=main EventCode=4688
| eval process=lower(coalesce(NewProcessName, New_Process_Name, process_name))
| eval parent_process=lower(coalesce(CreatorProcessName, ParentProcessName, parent_process_name))
| eval command_line=lower(coalesce(ProcessCommandLine, CommandLine, process_command_line))
| eval actor=coalesce(SubjectUserName, user, AccountName)
| where like(process, "%powershell.exe%")
    OR like(process, "%pwsh.exe%")
    OR like(command_line, "%powershell%")
    OR like(command_line, "%pwsh%")
| table _time host actor process parent_process command_line
| sort 0 _time
```

This query searches process-creation events for PowerShell activity and displays the available user, process, parent-process, command-line, host, and timestamp fields.

**Note:** Windows field names vary depending on the logging configuration. If the query returns no results or important columns are empty, inspect the raw event and adapt the field names.

---

## 4. Investigation Timeline

The following is an **illustrative example of a suspicious process-creation event**, not a verified result from the current Splunk dataset.

| Time | EventCode | User | Parent Process | Child Process | Interpretation |
|---|---:|---|---|---|---|
| 02:10:15 | 4688 | john | `WINWORD.EXE` | `powershell.exe` | Potentially suspicious process chain requiring investigation |

### Example of a Command-Line Indicator

An illustrative command line might contain:

```text
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <redacted>
```

This example contains indicators worth investigating:

- `-WindowStyle Hidden` — requests a hidden PowerShell window.
- `-EncodedCommand` — executes a command supplied in encoded form.
- An office application launching PowerShell — potentially unusual and deserving contextual analysis.

These indicators do not automatically prove malicious activity. Legitimate administrative scripts can also use some of these options.

---

## 5. SPL Query — Suspicious PowerShell Indicators

To identify PowerShell events containing commonly investigated command-line patterns, I used the following query.

```spl
index=main EventCode=4688
| eval process=lower(coalesce(NewProcessName, New_Process_Name, process_name))
| eval parent_process=lower(coalesce(CreatorProcessName, ParentProcessName, parent_process_name))
| eval command_line=lower(coalesce(ProcessCommandLine, CommandLine, process_command_line))
| eval actor=coalesce(SubjectUserName, user, AccountName)
| where like(process, "%powershell.exe%")
    OR like(process, "%pwsh.exe%")
    OR like(command_line, "%powershell%")
    OR like(command_line, "%pwsh%")
| eval suspicious_indicator=if(
    like(command_line, "%encodedcommand%")
    OR like(command_line, "%-enc %")
    OR like(command_line, "%windowstyle hidden%")
    OR like(command_line, "%-w hidden%")
    OR like(command_line, "%executionpolicy bypass%")
    OR like(command_line, "%-ep bypass%")
    OR like(command_line, "%downloadstring%")
    OR like(command_line, "%frombase64string%")
    OR like(command_line, "%invoke-expression%")
    OR like(command_line, "%iex %"),
    "Suspicious command-line indicator",
    "PowerShell activity - review context"
)
| table _time host actor process parent_process command_line suspicious_indicator
| sort 0 _time
```

### What This Query Does

| SPL Component | Purpose |
|---|---|
| `EventCode=4688` | Searches process-creation events |
| `coalesce()` | Normalizes fields when alternative field names exist |
| `lower()` | Makes text comparisons case-insensitive |
| `like()` | Checks for matching text patterns |
| `eval` | Creates the classification field |
| `table` | Displays the investigation evidence |
| `sort` | Organizes events chronologically |

The classification identifies command-line indicators for review. It is a hunting aid, not a definitive malware verdict.

---

## 6. Investigation Results

The following table describes the findings that should be recorded after running the queries. The example values are illustrative and must be replaced if the actual Splunk output differs.

| Indicator | Illustrative Observation |
|---|---|
| Event ID | `4688` |
| Process of interest | `powershell.exe` |
| Parent process | `WINWORD.EXE` |
| Command-line indicator | Encoded command / hidden window |
| User | `john` |
| Target host | `Likhi` |
| Investigation priority | High-priority review if the process chain and command line are confirmed |

### Evidence to Validate

- Whether Event ID 4688 is present in the actual dataset.
- The exact executable path and parent process.
- The complete command line, if process command-line auditing is enabled.
- The user and host associated with the event.
- Whether related PowerShell script-block logs or EDR events exist.

---

## 7. Findings

This investigation demonstrates a method for identifying and examining PowerShell process-creation events in Windows Security logs.

The analysis focuses on three important areas:

1. **Process identity:** Determine which executable was launched.
2. **Parent-child relationship:** Determine which process started PowerShell.
3. **Command-line arguments:** Identify execution options that may warrant additional investigation.

An event involving PowerShell is not inherently malicious. However, an unexpected parent process combined with encoded commands, hidden execution, or suspicious network activity can increase the level of concern.

The final findings must be based on the actual events returned by Splunk rather than on the illustrative example in this report.

---

## 8. Conclusion

PowerShell is a legitimate Windows administration and automation tool, but it can also be abused to execute malicious commands.

Event ID 4688 provides useful evidence about process creation. When the necessary fields are available, analysing the executable path, parent process, command line, user, and timestamp can help identify suspicious activity.

The search patterns in this investigation support **PowerShell threat hunting**, but a command-line match alone does not confirm malware or compromise.

Further investigation should examine:

- PowerShell script-block logging, particularly Event ID 4104 where available.
- Related process-creation events.
- Network connections made by the process.
- File creation and modification.
- Endpoint detection and response alerts.
- The user's activity before and after process execution.
- The reputation of any discovered domains, IPs, or file hashes.

### Final Assessment

> **Assessment: Investigate suspicious PowerShell indicators and validate the process chain before determining whether the activity is malicious.**

---

## 9. Evidence

###
