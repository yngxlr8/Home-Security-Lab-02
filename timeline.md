# Home Security Lab 02 — Investigation Timeline

**Date:** 21 October 2026  
**Time zone:** CEST (UTC+02:00), unless explicitly shown otherwise  
**Endpoint:** `WIN11` (`192.168.56.103`)  
**Test client:** `Kali` (`192.168.56.102`)  
**Scope:** Authorized home-lab activity
**Lab tests and investigation made by:** Szymon Orzeł (yngxlr8)

This timeline reconstructs three exercises using Windows logs, endpoint commands, Nmap, Wireshark, firewall logs, and local file artifacts. It records **what the evidence shows**, not an assumed attack story. 

## Timeline

| Time (CEST)                                                 | Host / direction          | Account or context                                                                   | Evidence and screenshot                                                                                                                                                                               | Event                                                                                       | Observation / conclusion                                                                                                                                                                                                                    |
| ----------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **09:58:56**                                                | WIN11                     | Target account: `observer`                                                           | `observer-logons.evtx` - [screenshot](screenshots/failedlogon19034.png)                                                                                                                               | Security **4625**, Record **19034**                                                         | Failed interactive logon (Type 2). Substatus `0xC000006A` indicates an incorrect password. Source address: `127.0.0.1`.                                                                                                                     |
| **09:58:57**                                                | WIN11                     | Target account: `observer`                                                           | `observer-logons.evtx` -[screenshot](screenshots/failedlogon19036.png)                                                                                                                                | Security **4625**, Record **19036**                                                         | Second failed interactive logon. The same wrong-password substatus appears.                                                                                                                                                                 |
| **09:59:01**                                                | WIN11                     | Logged-on account: `observer`                                                        | `observer-logons.evtx` - [screenshot](screenshots/successfullogon19039.png)                                                                                                                           | Security **4624**, Record **19039**                                                         | Successful local interactive logon (Type 2). The record shows account activity, not the identity of the person using the account.                                                                                                           |
| **Time not established; listener observed during the test** | WIN11                     | `analyst` / `powershell.exe`                                                         | `Get-NetTCPConnection`, `Get-Process` - [screenshot](screenshots/tcpcon-getprocess.png)                                                                                                               | N/A                                                                                         | `powershell.exe`, PID **10356**, was listening on `192.168.56.103:8080`. The screenshot does not establish when listening began.                                                                                                            |
| **About 11:10**                                             | Kali → WIN11              | Kali test client                                                                     | Nmap + Wireshark -[screenshot](screenshots/nmap-filtered.png)                                                                                                                                         | N/A                                                                                         | `nmap -sT -Pn -p 8080 192.168.56.103` returned **filtered**. Wireshark showed SYN attempts without a response, so the TCP handshake did not complete.                                                                                       |
| **11:10:15**                                                | Kali → WIN11              | Network traffic; no Windows user attribution                                         | `pfirewall.log` -[screenshot](screenshots/pfirewalllog.png)                                                                                                                                           | Firewall **DROP**                                                                           | Windows Firewall dropped TCP traffic from `192.168.56.102:51540` to `192.168.56.103:8080`. This supports the first Nmap result.                                                                                                             |
| **Between the scans; exact time not established**           | WIN11                     | Administrative firewall change; actor not independently identified by the screenshot | Firewall command/result - [screenshot](screenshots/tcp8080.png)                                                                                                                                       | N/A                                                                                         | Created inbound Allow rule `tcp8080`: local address `192.168.56.103`, local port TCP/8080, permitted remote address `192.168.56.102`.                                                                                                       |
| **About 11:16**                                             | Kali → WIN11              | Kali test client                                                                     | Nmap + Wireshark - [screenshot](screenshots/nmap-open.png)                                                                                                                                            | N/A                                                                                         | The next scan returned **open**. PCAP frames **43–45** showed SYN, SYN/ACK, ACK for `192.168.56.102:56408 → 192.168.56.103:8080`; frame **46** showed Kali sending RST,ACK.                                                                 |
| **11:16:48.137**                                            | WIN11 receiving from Kali | `powershell.exe` TCP listener                                                        | `tcp-fixture.log` - [screenshot](screenshots/tcpfixture.png)                                                                                                                                          | Application log entry                                                                       | The listener recorded `accepted 192.168.56.102:56408`. The address and port match the TCP connection in the capture. The log timestamp includes `+02:00`.                                                                                   |
| **12:26:12**                                                | WIN11                     | PowerShell command executed as `analyst`                                             | `lab02-powershell.evtx` - [screenshot](screenshots/scriptblock4758.png); marker  -[screenshot](screenshots/psmarkerss.png)                                                                            | PowerShell **4104**, Record **4758**                                                        | Script Block Logging recorded code writing `LAB02-PS-MARKER` to `lab02-ps-marker.txt`. The file contained the expected marker when checked. Its exact write timestamp was not separately captured.                                          |
| **13:27:22**                                                | WIN11                     | Task registered by `analyst`                                                         | `lab02-security.evtx` - [screenshot](screenshots/newevent20017.png); `lab02-taskscheduler.evtx` - [screenshot](screenshots/taskscheduler3463.png); task XML - [screenshot](screenshots/markerxml.png) | Security **4698**, Record **20017**; Task Scheduler **106**, Record **3463**                | The task `\Lab02-Marker` was registered. Its action used `cmd.exe /c echo` to append `LAB02-TASK-MARKER` to a file. This proves registration, **not execution**.                                                                            |
| **13:43:42**                                                | WIN11                     | Task instance for `analyst`                                                          | `lab02-taskscheduler.evtx` - [screenshot](screenshots/task110,325.png)                                                                                                                                | Task Scheduler **325**, Record **3470**; **110**, Record **3471**                           | The task instance was queued, then launched by Task Scheduler. These records refer to the same scheduled-task execution.                                                                                                                    |
| **13:43:42**                                                | WIN11                     | Task instance for `analyst`                                                          | `lab02-taskscheduler.evtx` - [screenshot](screenshots/task129,100,200.png)                                                                                                                            | Task Scheduler **129**, Record **3472**; **100**, Record **3473**; **200**, Record **3474** | Task Scheduler reported a `cmd.exe` process (PID **9460**), task start, and action start.                                                                                                                                                   |
| **13:43:42**                                                | WIN11                     | Creator Subject: `SYSTEM`; Target Subject: `analyst`                                 | `lab02-security.evtx` - [screenshot](screenshots/processcreate.png)                                                                                                                                   | Security **4688**, Record **20051**                                                         | Windows recorded a new `C:\Windows\System32\cmd.exe` process. Its PID was `0x24f4` (**9460** in decimal), matching Task Scheduler Event 129. The parent/creator process was `svchost.exe`, and the command line contained the marker write. |
| **13:43:43**                                                | WIN11                     | Task instance for `analyst`                                                          | `lab02-taskscheduler.evtx` - [screenshot](screenshots/task201,102.png)                                                                                                                                | Task Scheduler **201**, Record **3475**; **102**, Record **3476**                           | The action finished with return code **0**, and Task Scheduler reported successful task completion.                                                                                                                                         |
| **After execution; exact inspection time not established**  | WIN11                     | Inspection as `analyst`                                                              | `Get-ScheduledTaskInfo` - [screenshot](screenshots/taskinfo.png); file content - [screenshot](screenshots/taskmarkerss.png)                                                                           | N/A                                                                                         | `LastRunTime` was **13:43:42**, `LastTaskResult` was **0**, and `lab02-task-marker.txt` contained `LAB02-TASK-MARKER`. These artifacts support successful execution.                                                                        |

## Key evidence correlations

### 1. Authentication: failures followed by success

- `4625 / 19034` → failed interactive logon.
- `4625 / 19036` → second failed interactive logon.
- `4624 / 19039` → successful interactive logon.

All three records concern `observer`. The screenshots show local interactive activity; they do not show a remote login from Kali.

### 2. Network: blocked connection followed by an accepted connection

**Before the firewall rule:**

- Nmap reported `filtered`.
- Wireshark showed TCP SYN attempts with no response.
- Windows Firewall recorded `DROP TCP` for destination port 8080.

**After the firewall rule:**

- Nmap reported `open`.
- Wireshark frames 43–45 showed a completed TCP handshake.
- The Windows application log recorded the connection from `192.168.56.102:56408` at `11:16:48.137+02:00`.

### 3. Scheduled task: registration versus execution

**Registration:** Security 4698 and Task Scheduler 106 recorded the task configuration at 13:27:22.

**Execution:** Task Scheduler 129 and Security 4688 both identified the launched process:

```text
Task Scheduler Event 129: PID 9460
Windows Security Event 4688: New Process ID 0x24f4
0x24f4 (hex) = 9460 (decimal)
Process: C:\Windows\System32\cmd.exe
```

**Result:** Task Scheduler 201/102, result `0`, and the marker file support successful completion.

## Confidence and limitations

- **High confidence:** The three logon records, the firewall DROP, the completed TCP handshake, the accepted connection, the task registration, and the process/task execution are supported by the listed evidence.
- **Time not established:** Listener startup, firewall rule creation, and the exact creation time of each marker file.
- **Not established:** A causal connection between the `observer` logon and the later network or scheduled-task activity.
- **Not established:** The identity of a person based on an account name or system event alone.
- **Scope:** Known, authorized lab activity; this is not evidence of a real compromise.

The test task, listener, and temporary firewall rule were cleaned up after evidence collection.

---

Back to [README.md](README.md).
