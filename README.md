# Security Information & Event Management (SIEM)

Log aggregation, detection engineering, alert management, and security analytics.

## SIEM Investigations

Enterprise-scale investigations correlating logs from multiple sources.

| Case ID | Type | Log Sources | MITRE Techniques |
|---------|------|-------------|------------------|
| SIEM-001 | Brute Force → Exfiltration | Windows, Firewall, Web | T1110, T1078, T1041 |
| SIEM-002 | PowerShell Malware | Windows, Sysmon | T1059, T1027, T1005 |
| SIEM-003 | Privilege Escalation | Windows, AD | T1078, T1098, T1484 |

**Investigation Workflow:**
1. Alert received from detection rule
2. Initial triage — severity, affected assets, user context
3. Log correlation across data sources
4. Timeline reconstruction
5. IOC extraction
6. Impact assessment
7. Containment decision

## Splunk Queries

Production-tested SPL (Search Processing Language) queries for threat detection.

### Authentication Analysis
```spl
# Brute force detection with risk scoring
index=wineventlog EventCode=4625 OR EventCode=4624 
| stats count(eval(EventCode=4625)) as failed, count(eval(EventCode=4624)) as success by src_ip, user 
| where failed > 10 AND success > 0 
| eval risk_score=failed*success 
| sort - risk_score

# Service account abuse detection
index=wineventlog EventCode=4624 
| where match(user, "svc_.*") OR match(user, ".*_svc$") 
| eval is_interactive=if(LogonType=10 OR LogonType=2, "yes", "no") 
| where is_interactive="yes" 
| stats count by user, ComputerName, src_ip

# After-hours authentication
index=wineventlog EventCode=4624 
| eval hour=strftime(_time, "%H") 
| where hour < 6 OR hour > 22 
| stats count by user, ComputerName, hour 
| where count > 5
```

### Lateral Movement Detection
```spl
# NTLM authentication without Kerberos
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM 
| stats count by src_ip, dest_ip, user 
| where count > 10

# Pass-the-Hash indicators
index=wineventlog EventCode=4624 LogonType=3 
| eval is_pth=if(ProcessName="svchost.exe" AND AuthenticationPackageName="NTLM", "possible", "normal") 
| where is_pth="possible"
```

### Data Exfiltration Detection
```spl
# Large outbound transfers
index=firewall action=allow 
| stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port 
| where total_out > 104857600 
| eval mb_out=round(total_out/1048576,2) 
| sort - mb_out

# Unusual HTTPS destinations
index=proxy 
| lookup alexa_top_1m domain as dest_host OUTPUT rank 
| where isnull(rank) AND dest_port=443 
| stats count by src_ip, dest_host 
| where count > 100
```

### PowerShell Abuse
```spl
# Encoded command execution
index=sysmon EventCode=1 
| where match(CommandLine, "(?i)-enc") OR match(CommandLine, "(?i)-encodedcommand") 
| stats count by Computer, User, CommandLine

# Download cradle detection
index=sysmon EventCode=1 
| where match(CommandLine, "(?i)New-Object Net.WebClient") OR match(CommandLine, "(?i)Invoke-WebRequest") 
| stats count by Computer, User, ParentImage, CommandLine
```

## Sigma Rules

Detection-as-code rules for portable threat detection.

### Rule Inventory

| Rule | Technique | Log Source | Status |
|------|-----------|------------|--------|
| [Excessive Failed Logons](./sigma-rules/SIGMA-001-Bruteforce.yml) | T1110 | Windows Security | Production |
| [Encoded PowerShell](./sigma-rules/SIGMA-002-Encoded-PowerShell.yml) | T1059.001 | Sysmon | Production |
| [Domain Admin Addition](./sigma-rules/SIGMA-003-Domain-Admin-Addition.yml) | T1098 | Windows Security | Production |
| [Office Macro Exec](./sigma-rules/office_macro_exec.yml) | T1204.002 | Sysmon | Testing |
| [Suspicious Rundll32](./sigma-rules/suspicious_rundll32.yml) | T1218.011 | Sysmon | Testing |
| [LSASS Dump](./sigma-rules/lsass_dump.yml) | T1003.001 | Sysmon | Production |
| [DNS Tunneling](./sigma-rules/dns_tunneling.yml) | T1071.004 | DNS | Testing |
| [Scheduled Task Persist](./sigma-rules/scheduled_task_persist.yml) | T1053.005 | Windows Security | Testing |
| [Named Pipe Abuse](./sigma-rules/named_pipe_abuse.yml) | T1021.002 | Sysmon | Testing |

### Rule Testing

Each rule includes:
- Test data (positive and negative cases)
- False positive analysis
- Tuning recommendations
- Backend conversion (Splunk SPL, Elastic DSL)

**Testing Process:**
1. Deploy rule in monitoring mode
2. Collect 7 days of alert data
3. Analyse false positive rate
4. Tune thresholds or add exclusions
5. Promote to blocking/enforcing mode

## Alert Triage

Systematic alert validation and prioritisation.

**Triage Criteria:**
| Factor | High Priority | Medium Priority | Low Priority |
|--------|--------------|-----------------|--------------|
| Asset | Domain Controller, Executive | Standard workstation | Test environment |
| User | Domain Admin, Service Account | Standard user | Guest accounts |
| Technique | Credential theft, Lateral movement | Persistence, Discovery | Reconnaissance |
| Prevalence | Single host | Multiple hosts | Wide spread |
| Time | After hours, weekend | Business hours | Known maintenance |

**SLA Targets:**
- Critical: 15 minutes
- High: 1 hour
- Medium: 4 hours
- Low: 24 hours

## Dashboards

Security operations visualisations and metrics.

**Dashboard Examples:**
- Authentication anomalies (failed logins, after-hours access)
- Top alerts by category and severity
- Endpoint health and agent coverage
- Network traffic anomalies
- Incident status and queue depth
- MTTD/MTTR metrics

---

*A SIEM is only as good as the detection logic and the analysts operating it. Both require continuous refinement.*
