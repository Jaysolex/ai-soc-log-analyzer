# AI SOC Log Analyzer — Production Grade

Serverless AI-powered Security Operations Center built on AWS Lambda with real-time threat detection, multi-source threat intelligence enrichment, automated alerting, auto-remediation via AWS WAF, and persistent S3 storage.

## Architecture
```
Log Input → AWS Lambda → Modular Detection Engine → MITRE ATT&CK Mapping → Threat Intel Enrichment → CloudWatch Logs + SNS Email + Slack Alert + WAF Auto-Block + S3 Storage
```

## Features

- 6 modular detection engines covering the full attack chain
- MITRE ATT&CK technique mapping across 5 tactics
- Real-time threat intel enrichment via AbuseIPDB, VirusTotal, and Shodan
- Structured CloudWatch logging with full IOC breakdown
- SNS email alerts for High and Critical severity findings
- Slack alerts to #soc-alerts channel
- CloudTrail integration for real AWS activity monitoring
- Auto-remediation via AWS WAF — automatically blocks malicious IPs on Critical findings
- S3 persistent storage for all findings with date-based organization
- Live CloudWatch dashboard for SOC pipeline monitoring
- Serverless — runs on AWS Lambda, costs pennies per execution

## Detection Modules

| Module | Description | MITRE Technique | Tactic |
|--------|-------------|-----------------|--------|
| [process_behavior.py](detections/process_behavior.py) | Detects suspicious PowerShell execution | T1059.001 | Execution |
| [network_anomalies.py](detections/network_anomalies.py) | Detects port scanning activity | T1046 | Discovery |
| [cloud_identity.py](detections/cloud_identity.py) | Detects identity anomalies | T1078 | Defense Evasion |
| [ransomware.py](detections/ransomware.py) | Detects ransomware behavior | T1486 | Impact |
| [exfiltration.py](detections/exfiltration.py) | Detects data exfiltration attempts | T1041 | Exfiltration |
| [lateral_movement.py](detections/lateral_movement.py) | Detects lateral movement (PsExec, Mimikatz, RDP) | T1021 | Lateral Movement |
| [enrichment.py](detections/enrichment.py) | AbuseIPDB, VirusTotal, Shodan enrichment | N/A | N/A |
| [automation.py](detections/automation.py) | Correlates and deduplicates findings | N/A | N/A |

## Core Files

| File | Description |
|------|-------------|
| [lambda_function.py](lambda_function.py) | Main Lambda handler with SNS + Slack + WAF + S3 |
| [mitre_mapping.json](mitre_mapping.json) | MITRE ATT&CK technique definitions |
| [test_logs.json](test_logs.json) | Sample test log events |

## Threat Intelligence

| Source | Data Returned |
|--------|--------------|
| AbuseIPDB | Abuse score, country, total reports, Tor exit node |
| VirusTotal | Malicious, suspicious, harmless vendor counts |
| Shodan | Open ports, org, country, known vulnerabilities |

## Alerting

| Channel | Trigger |
|---------|---------|
| CloudWatch Logs | Every Lambda execution |
| SNS Email | High and Critical severity findings |
| Slack #soc-alerts | High and Critical severity findings |
| AWS WAF Auto-Block | Critical severity findings — IP blocked automatically |
| S3 Storage | Every execution — findings saved as JSON |

## Full Attack Chain Simulation

The system was tested using a simulated APT attack log triggering all 6 detection modules simultaneously.

### Test Input
```json
{
  "log": "2026-03-22T15:00:00Z user=admin src_ip=185.22.45.90 dst=badsite.ru powershell -nop -w hidden vssadmin delete shadows bcdedit /set recoveryenabled no wmic shadowcopy delete psexec mimikatz net use curl -d pastebin.com nmap rdesktop"
}
```

### Detection Results

| Finding | Severity | Technique | Phase | Alert |
|---------|----------|-----------|-------|-------|
| PowerShell execution | High | T1059.001 | Execution | SNS + Slack |
| Port scanning | Medium | T1046 | Discovery | — |
| Identity check | Informational | — | — | — |
| Ransomware behavior | Critical | T1486 | Impact | SNS + Slack + WAF Block |
| Data exfiltration | Critical | T1041 | Exfiltration | SNS + Slack + WAF Block |
| Lateral movement | Critical | T1021 | Lateral Movement | SNS + Slack + WAF Block |

### Full Attack Chain Detected
```
Execution → Discovery → Lateral Movement → Exfiltration → Ransomware (Impact)
```

## CloudTrail Integration

The SOC pipeline is connected to AWS CloudTrail for real-time monitoring of all AWS account activity. Every API call, role assumption, and service event is automatically ingested and analyzed by the detection engine.
```
AWS Account Activity → CloudTrail → CloudWatch Logs → Lambda → Detection + Alerting
```

This means the SOC now monitors real production AWS events including console logins, IAM role assumptions, Lambda invocations, KMS decryption events, and EC2 activity — not just simulated test logs.

## Auto-Remediation

When a Critical severity finding is detected, the SOC automatically blocks the malicious IP address in AWS WAF without any human intervention.
```
Critical Finding Detected → Extract IOCs → Block IP in WAF IP Set → Log Action
```

This reduces attacker dwell time from hours to milliseconds — a key L3 SOC capability. The system is smart enough to check if an IP is already blocked before attempting to add it, preventing duplicate entries.

## S3 Findings Storage

Every SOC analysis result is automatically persisted to Amazon S3 in structured JSON format, organized by date for easy retrieval and future analysis.
```
Detection Complete → Save JSON to S3 → soc-findings/YYYY/MM/DD/HH-MM-SS.json
```

This creates a permanent audit trail of all detections and enables future integration with analytics tools like AWS Athena or QuickSight.

## Live SOC Dashboard

A CloudWatch dashboard provides real-time visibility into SOC pipeline health and activity across Lambda executions, SNS alerts, and invocation trends.

### Metrics Monitored
- Lambda invocations, errors, and duration
- SNS messages published and delivered
- Invocation trends over time

## Environment Variables

| Key | Description |
|-----|-------------|
| ABUSEIPDB_KEY | AbuseIPDB API key |
| VIRUSTOTAL_KEY | VirusTotal API key |
| SHODAN_KEY | Shodan API key |
| SNS_TOPIC_ARN | AWS SNS topic ARN for email alerts |
| SLACK_WEBHOOK_URL | Slack incoming webhook URL |
| WAF_IP_SET_ID | AWS WAF IP set ID for auto-blocking |
| WAF_IP_SET_ARN | AWS WAF IP set ARN |
| S3_BUCKET | S3 bucket name for findings storage |

## Execution Evidence

### Lambda Test Success
![Lambda test success](screenshots/Lambda%20test%20success%20response.png)

### Lambda Environment Variables
![Lambda environment variables](screenshots/Environment%20variables%20(7)_Updated.png)

### CloudTrail Trail Active and Logging
![CloudTrail trail active](screenshots/cloudtrail_soc_trail_active.png)

### Lambda CloudTrail Trigger Connected
![Lambda CloudTrail trigger](screenshots/lambda_cloudtrail_trigger_connected.png)

### Real CloudTrail Events Flowing into CloudWatch
![CloudTrail live events](screenshots/cloudwatch_cloudtrail_events_live.png)

### CloudWatch Critical Detections
![CloudWatch critical](screenshots/Cloudwatch_Critical%20.png)

### CloudWatch Structured Logs
![CloudWatch logs A](screenshots/CloudWatch%20logs%20structured%20output%20A.png)
![CloudWatch logs B](screenshots/CloudWatch%20logs%20structured%20output%20B.png)
![CloudWatch logs C](screenshots/CloudWatch%20logs%20structured%20output%20C.png)
![CloudWatch logs D](screenshots/CloudWatch%20logs%20structured%20output%20D.png)

### Gmail Alerts
![Gmail HIGH SEVERITY alert](screenshots/Gmail%20HIGH%20SEVERITY%20alert.png)
![Gmail full alert](screenshots/Gmail%20Full%20Alert.png)

### Slack #soc-alerts
![Slack alert](screenshots/Slack%20%23soc-alerts%20alert%20.png)
![Slack full alert](screenshots/SLACK%20ALART%20full.png)

### WAF Auto-Remediation — 5 IPs Blocked Automatically
![WAF auto-remediation](screenshots/waf_blocked_ip_auto_remediation.png)

### S3 Findings — Auto-Saved Per Execution
![S3 findings saved](screenshots/s3_soc_findings_saved.png)

### SOC Live Dashboard
![CloudWatch SOC dashboard](screenshots/cloudwatch_soc_dashboard.png)

## SOC Value

- Detects full APT attack chain from execution to impact in a single log analysis
- Automatically blocks malicious IPs in AWS WAF on Critical findings
- Monitors real AWS account activity via CloudTrail integration
- Persists all findings to S3 for audit trail and future analysis
- Reduces analyst triage time through automated IOC extraction
- Enhances detection accuracy using three threat intelligence sources
- Produces structured output suitable for SIEM ingestion and correlation
- Real-time alerting via email and Slack for immediate SOC response
- Aligns detections with MITRE ATT&CK for standardized threat classification
- Fully serverless — no infrastructure to manage

## Summary

This project demonstrates a production-grade cloud native SOC pipeline capable of automated log ingestion, modular detection engineering across 6 attack techniques, multi-source threat intelligence enrichment, real-time CloudTrail monitoring, automated alerting, auto-remediation via AWS WAF, and persistent S3 storage — fully aligned with enterprise L2/L3 SOC operations.

## Author
Solomon James — CyberSOLEX
