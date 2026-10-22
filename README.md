# Home Security Lab 02 — Windows Security Investigation

**Project type:** Home lab / SOC analyst practice  
**Date:** 21 October 2026  
**Time zone:** CEST (UTC+02:00)  
**Lab setup and investigation by:** Szymon Orzeł (yngxlr8)

## 1. Overview

In this project, I created three controlled activities on a Windows 11 virtual machine and investigated their traces:

1. **Authentication:** two failed logons followed by a successful logon.
2. **Network activity:** a simple PowerShell TCP listener, an Nmap scan, Windows Firewall filtering, and a successful TCP connection.
3. **Execution:** a PowerShell file-write command and a scheduled task that launched `cmd.exe`.

My goal was to connect **what happened**, **which evidence was created**, and **what a SOC analyst could conclude**. All activity was authorized and took place in my own lab.

A detailed event-by-event record is available in **[timeline.md](timeline.md)**.

## 2. Lab environment

| System                   | Role                           | Lab IP address   |
| ------------------------ | ------------------------------ | ---------------- |
| Windows 11 Pro (`WIN11`) | Investigated endpoint          | `192.168.56.103` |
| Kali Linux (`Kali`)      | Test client and packet capture | `192.168.56.102` |

The machines communicated over a VirtualBox host-only network (`192.168.56.0/24`). The Windows endpoint used separate local accounts: `observer`, `analyst`, and `labadmin`.
Kali test client used account: `Kali`.

Relevant auditing was enabled for process creation and scheduled-task creation. PowerShell Script Block Logging and Task Scheduler operational history were also enabled.

Tools and evidence sources used:

- Windows Event Log: `Security`, `Microsoft-Windows-PowerShell/Operational`, and `Microsoft-Windows-TaskScheduler/Operational`
- Windows PowerShell 5.1 and Windows Task Scheduler
- Windows Defender Firewall and `pfirewall.log`
- `Get-NetTCPConnection`, `Get-Process`, `Get-WinEvent`, and `Get-ScheduledTaskInfo`
- Nmap and Wireshark on Kali Linux
- Local text files created during the tests

#### TCP Listener

For the purpose of the **Network Activity Test**, I used a **simple TCP Listener**.

I created a simple TCP Listener using Powershell and the .NET Tcplistener class. It was configured to listen on 192.168.56.103:8080 and record incoming TCP connections.

**Source code:** [PowerShell TCP Listener](scripts/tcp-listener.ps1)

#### Reproducing the TCP Test

This test demonstrates how Windows Firewall affects access to a TCP listener.

The experiment was performed in an isolated VirtualBox host-only network.

**Requirements:**
- Windows 11 with PowerShell 5.1
- Kali Linux (or other linux distro) with Nmap and Wireshark
- Both machines connected to the same host-only network
- Administrator access on Windows to configure the firewall

**Step 1 — Start the TCP listener**

On Windows, create the log directory. For example:

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\CyberLab" -Force | Out-Null
```

Check the IP address configured in `scripts/tcp-listener.ps1` and change it if necessary.

Run the script from the repository directory:

```powershell
.\scripts\tcp-listener.ps1
```

The listener uses TCP port 8080 and records accepted connections in `tcp-fixture.log`.

**Step 2 — Test connectivity from Kali**

Start Wireshark on the Kali host-only network interface before running the first Nmap scan. Keep the capture running during both tests to compare the blocked and successful connection attempts.

Wireshark display filter:

```text
tcp.port == 8080
```

Run the following Nmap scan:

```bash
nmap -sT -Pn -p 8080 192.168.56.103
```

In my experiment, Nmap initially reported `filtered` because Windows Firewall blocked incoming TCP connections.

The result may be different depending on the current firewall configuration.

**Step 3 — Allow the connection through Windows Firewall**

Open PowerShell as Administrator on Windows:

```powershell
New-NetFirewallRule `
    -Name 'tcp8080' `
    -DisplayName 'Lab TCP 8080' `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress '192.168.56.103' `
    -LocalPort 8080 `
    -RemoteAddress '192.168.56.102' `
    -Profile Any
```

This rule allows incoming TCP connections to port 8080 only from the Kali machine.

**Step 4 — Repeat the scan and inspect the traffic**

Run the Nmap scan again:

```bash
nmap -sT -Pn -p 8080 192.168.56.103
```

In my experiment, Nmap now reported `open`.

Use an already running Wireshark on the Kali host-only network interface to capture the traffic.

Look for the TCP three-way handshake:

1. SYN — Kali sends a connection request.
2. SYN/ACK — Windows responds.
3. ACK — Kali completes the handshake.

On Windows, check the listener log. In this case:

```powershell
Get-Content "$env:USERPROFILE\CyberLab\tcp-fixture.log" -Tail 5
```

The log should contain an entry showing an accepted connection from Kali.

**Step 5 — Cleanup**

Stop the listener with `Ctrl+C`.

Remove the temporary firewall rule from an elevated PowerShell session:

```powershell
Remove-NetFirewallRule -Name 'tcp8080'
```

The original investigation results, screenshots, and packet analysis are documented in [timeline.md](timeline.md).

**Note:** Run this experiment only in an authorized lab environment.

## 3. Investigation method

For each test, I followed the same process:

1. Perform a known action in the lab.
2. Identify the expected logs, packets, and files.
3. Collect evidence from the endpoint and, where relevant, from Kali.
4. Compare timestamps, accounts, IP addresses, process IDs, and command lines.
5. Separate confirmed observations from possible explanations.

The table in [timeline.md](timeline.md) uses local time (CEST). When an exact time was not recorded, I marked it as **not established**.

## 4. Findings

### A. Local authentication

Windows Security recorded two failed interactive logons to `WIN11\observer`, followed by a successful interactive logon:

| Time (CEST) | Event | Record ID | Result |
|---|---|---|---|
| 09:58:56 | Security `4625` | `19034` | Failed logon |
| 09:58:57 | Security `4625` | `19036` | Failed logon |
| 09:59:01 | Security `4624` | `19039` | Successful logon |

The failed attempts had **Logon Type 2** and substatus `0xC000006A`, consistent with a wrong password. The source network address shown in the records was `127.0.0.1`. These records do **not** show a remote logon from Kali.

**Evidence:** `observer-logons.evtx`

**Screenshots:** [First failed logon](screenshots/failedlogon19034.png), [Second failed logon](screenshots/failedlogon19036.png), [Successful logon](screenshots/successfullogon19039.png).

**Assessment:** The sequence is consistent with the deliberate login test. The logon records identify the account involved, not the physical person at the keyboard.

### B. TCP listener, Nmap, and Windows Firewall

On Windows, I observed a PowerShell process listening on `192.168.56.103:8080`:

- Process: `powershell.exe`
- PID: `10356`
- State: `Listen`

**Evidence:** [Get-NetTCPConnection/Get-Process](screenshots/tcpcon-getprocess.png).

I then tested connectivity from Kali with:

```bash
nmap -sT -Pn -p 8080 192.168.56.103
```

At approximately **11:10**, Nmap reported `8080/tcp filtered`. Wireshark showed SYN packets without a TCP response. At **11:10:15**, `pfirewall.log` recorded a `DROP TCP` entry for traffic from `192.168.56.102:51540` to `192.168.56.103:8080`.

**Evidence:** [Nmap/Wireshark](screenshots/nmap-filtered.png), [Log pfirewall](screenshots/pfirewalllog.png).

A Windows inbound firewall rule named `tcp8080` was then created. It allowed TCP traffic to `192.168.56.103:8080` **only from** `192.168.56.102`.

**Evidence:** [Adding Firewall rule](screenshots/tcp8080.png).

At approximately **11:16**, a second Nmap scan reported `8080/tcp open`. Wireshark showed the TCP three-way handshake:

| PCAP frame | Direction | TCP flags |
|---|---|---|
| 43 | Kali → Windows | SYN |
| 44 | Windows → Kali | SYN, ACK |
| 45 | Kali → Windows | ACK |
| 46 | Kali → Windows | RST, ACK |

The traffic used `192.168.56.102:56408 → 192.168.56.103:8080`. At **11:16:48.137 CEST**, the Windows listener logged that it accepted a connection from `192.168.56.102:56408`.

**Evidence:** `tcp-fixture.log` 

**Screenshots:** [Log tcp-fixture](screenshots/tcpfixture.png), [Nmap/Wireshark](screenshots/nmap-open.png)

**Assessment:** A local listening socket did not guarantee remote access. The firewall blocked the first connection attempts. After the rule change, the TCP handshake completed and the listener accepted a connection. The service name `http-proxy` in Nmap output is a port-based label; it does not prove that an HTTP proxy was running.

### C. PowerShell activity and scheduled-task execution

#### PowerShell Script Block Logging

At **12:26:12**, PowerShell Operational Event **4104**, Record ID **4758**, recorded a command that wrote `LAB02-PS-MARKER` to `lab02-ps-marker.txt`. I also verified the text in that file.

**Evidence:** `lab02-powershell.evtx`

**Screenshots:** [Event 4104](screenshots/scriptblock4758.png), [Powershell marker](screenshots/psmarkerss.png).

Event 4104 shows the script block that PowerShell processed. The file content provides separate evidence of the expected result.

#### Task registration

At **13:27:22**, `WIN11\analyst` registered a scheduled task named `\Lab02-Marker`:

- Security **4698**, Record ID **20017**
- Task Scheduler **106**, Record ID **3463**
- Action: run `C:\Windows\System32\cmd.exe` with arguments to append `LAB02-TASK-MARKER` to a text file

**Evidence:** `lab02-security.evtx`, `lab02-taskscheduler.evtx`, exported `Lab02-Marker.xml`

**Screenshots:** [Event 4698](screenshots/newevent20017.png), [Event 106](screenshots/taskscheduler3463.png), [Task XML](screenshots/markerxml.png).

Registration alone does not prove that a task ran.

#### Task execution

At **13:43:42**, Task Scheduler recorded the task being queued and launched. Security Event **4688**, Record ID **20051**, recorded the creation of `cmd.exe` with the expected marker command line.

A key correlation was the process ID:

- Security 4688: `0x24f4` (hexadecimal)
- Task Scheduler 129: `9460` (decimal)
- **`0x24f4` = `9460`** — the same process ID in two number formats

Security 4688 showed `SYSTEM` under **Creator Subject** and `analyst` under **Target Subject**. The creator process was `svchost.exe`. The fields should not be treated as proof that the operator was logged on as SYSTEM.

At **13:43:43**, Task Scheduler Events **201** and **102** recorded successful completion. `Get-ScheduledTaskInfo` reported `LastTaskResult = 0`, and the file contained `LAB02-TASK-MARKER`.

**Evidence:** `lab02-security.evtx`, `lab02-taskscheduler.evtx`

**Screenshots:** [Event 110](screenshots/task110,325.png), [Events: 129/100/200](screenshots/task129,100,200.png), [Event 4688](screenshots/processcreate.png), [Events 201/102](screenshots/task201,102.png), [Task info](screenshots/taskinfo.png), [Task marker](screenshots/taskmarkerss.png).

**Assessment:** The matching task name, time, process ID, command line, completion records, and text-file marker strongly support that the scheduled action ran successfully.

## 5. SOC assessment

These were **three separate, authorized lab tests**. The collected records do not establish a causal link between the `observer` logon, the TCP listener, and the scheduled task created by `analyst`.

- The successful `observer` logon was local and interactive.
- The network test used Kali as a client and PowerShell as a listener on Windows.
- The scheduled task was registered for `analyst` and ran in that user's context.

A shared endpoint and nearby timestamps are not enough to prove a single attack chain. **No unauthorized activity was established by the evidence in this lab.**

## 6. Detection opportunities (ideas, not implemented rules)

These are simple ideas for future SOC monitoring. I have **not** created or tested SIEM detection rules in this project.

| Activity to watch | Possible data source | What an analyst should check |
|---|---|---|
| Several failed logons followed by success | Security `4625`, `4624` | Account, logon type, time window, source, expected user activity |
| Unusual PowerShell script content | PowerShell Operational `4104` | Script content, user context, file changes, other related events |
| New scheduled task | Security `4698`, Task Scheduler `106` | Task name, action, command line, user, expected administrative activity |
| Scheduled task launching a process | Security `4688`, Task Scheduler `129`, `200` | Matching PID, path, arguments, task name and time |
| Unexpected listening port or firewall rule | Endpoint network telemetry and firewall configuration monitoring | Listening process, remote reachability, allowed source addresses and approved changes |

**Important:** None of these events is malicious by itself. Normal user mistakes, software updates, and administrator activity can produce similar records. Alerts require investigation and context.

## 7. Evidence files and screenshot index

Raw EVTX and packet-capture data are kept **locally**, not published in this repository.

| Local evidence                       | Screenshots to reference (in /screenshots directory)                      |
| ------------------------------------ | ------------------------------------------------------------------------- |
| `observer-logons.evtx`               | `failedlogon19034.png`, `failedlogon19036.png`, `successfullogon19039.png` |
| Windows listening socket and process | `tcpcon-getprocess.png`                                                   |
| First Nmap scan and SYN attempts     | `nmap-filtered.png`                                                       |
| `pfirewall.log` DROP entry           | `pfirewalllog.png`                                                        |
| Firewall rule configuration          | `tcp8080.png`                                                             |
| Second Nmap scan and TCP handshake   | `nmap-open.png`                                                           |
| `tcp-fixture.log`, 21 October entry  | `tcpfixture.png`                                                          |
| `lab02-powershell.evtx` (4104)       | `scriptblock4758.png`                                                     |
| PowerShell marker file               | `psmarkerss.png`                                                          |
| `lab02-security.evtx` (4698)         | `newevent20017.png`                                                       |
| `lab02-taskscheduler.evtx` (106)     | `taskscheduler3463.png`                                                   |
| Scheduled task configuration XML     | `markerxml.png`                                                           |
| Task Scheduler (110, 325)            | `task110,325.png`                                                         |
| Task Scheduler (129, 100, 200)       | `task129,100,200.png`                                                     |
| `lab02-security.evtx` (4688)         | `processcreate.png`                                                       |
| Task Scheduler (201, 102)            | `task201,102.png`                                                         |
| Task completion status               | `taskinfo.png`                                                            |
| Scheduled-task marker file           | `taskmarkerss.png`                                                        |

## 8. Limitations

- The exact startup time of the TCP listener was not established.
- The exact time of the firewall rule change was not recorded; it took place between the two scans.
- The connection attempt and acceptance were correlated using IP addresses, ports, and the relevant time.

## 9. Cleanup and lessons learned

After exporting the relevant evidence and task XML, I removed the test scheduled task, stopped the TCP listener, and removed the temporary firewall rule. 

This project taught me to:

- Interpret Windows authentication and process-creation events.
- Distinguish a listening service from a remotely reachable port.
- Connect Nmap results to packet captures and firewall logs.
- Correlate Windows Security records with Task Scheduler history using time, task name, PID, and command line.
- Avoid claiming a connection between events without supporting evidence.

**Detailed timeline:** [timeline.md](timeline.md)
