# AI SOC Log Analyzer — Production Grade

Serverless AI-powered Security Operations Center built on AWS Lambda with real-time threat detection, multi-source threat intelligence enrichment, and automated alerting across email and Slack.

## Architecture
```
Log Input → AWS Lambda → Modular Detection Engine → MITRE ATT&CK Mapping → Threat Intel Enrichment → CloudWatch Logs + SNS Email + Slack Alert
```

## Features

- Modular detection engine across process behavior, network anomalies, and cloud identity
- MITRE ATT&CK technique mapping (T1059.001, T1046)
- Real-time threat intel enrichment via AbuseIPDB, VirusTotal, and Shodan
- Structured CloudWatch logging with full IOC breakdown
- SNS email alerts for High severity findings
- Slack alerts to #soc-alerts channel
- Serverless — runs on AWS Lambda, costs pennies per execution

## Detection Modules

| Module | Description | MITRE Technique |
|--------|-------------|-----------------|
| process_behavior.py | Detects suspicious PowerShell execution | T1059.001 |
| network_anomalies.py | Detects port scanning activity | T1046 |
| cloud_identity.py | Detects identity anomalies | T1078 |
| enrichment.py | AbuseIPDB, VirusTotal, Shodan enrichment | N/A |
| automation.py | Correlates and deduplicates findings | N/A |

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
| SNS Email | High severity findings |
| Slack #soc-alerts | High severity findings |

## Example Test Input
```json
{
  "log": "2026-03-22T04:00:00Z CRITICAL user=admin src_ip=185.22.45.90 dst=badsite.ru action=ConsoleLogin status=Failed attempts=10 process=powershell.exe args='-nop -w hidden -enc JABjAGwAaQBlAG4AdA' child_process=nmap parent=cmd.exe country=RU"
}
```

## Example Output
```json
{
  "statusCode": 200,
  "summary": {
    "timestamp": "2026-03-22T13:33:59",
    "total_findings": 3
  },
  "results": [
    {
      "severity": "High",
      "technique": "T1059.001",
      "description": "Suspicious PowerShell execution with obfuscation or encoded command.",
      "mitre_phase": "Execution",
      "threat_intel": {
        "185.22.45.90": {
          "abuseipdb": {"abuse_score": 0, "country": "DE", "total_reports": 0, "is_tor": false},
          "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 0}
        },
        "badsite.ru": {
          "virustotal": {"malicious": 0, "suspicious": 1, "harmless": 58}
        }
      }
    }
  ]
}
```

## Environment Variables

| Key | Description |
|-----|-------------|
| ABUSEIPDB_KEY | AbuseIPDB API key |
| VIRUSTOTAL_KEY | VirusTotal API key |
| SHODAN_KEY | Shodan API key |
| SNS_TOPIC_ARN | AWS SNS topic ARN for email alerts |
| SLACK_WEBHOOK_URL | Slack incoming webhook URL |

## Execution Evidence

### Lambda Test Success
![Lambda test success](screenshots/Lambda%20test%20success%20response.png)

### Lambda Environment Variables
![Lambda environment variables](screenshots/Lambda%20environment%20variables%20showing%20all%20API%20keys%20configured.png)

### CloudWatch Structured Logs
![CloudWatch logs A](screenshots/CloudWatch%20logs%20structured%20output%20A.png)
![CloudWatch logs B](screenshots/CloudWatch%20logs%20structured%20output%20B.png)
![CloudWatch logs C](screenshots/CloudWatch%20logs%20structured%20output%20C.png)
![CloudWatch logs D](screenshots/CloudWatch%20logs%20structured%20output%20D.png)

### Gmail HIGH SEVERITY Alert
![Gmail alert](screenshots/Gmail%20HIGH%20SEVERITY%20alert.png)

### Slack #soc-alerts Alert
![Slack alert](screenshots/Slack%20%23soc-alerts%20alert%20.png)

## SOC Value

- Reduces analyst triage time through automated IOC extraction
- Enhances detection accuracy using three threat intelligence sources
- Produces structured output suitable for SIEM ingestion and correlation
- Real-time alerting via email and Slack for immediate response
- Aligns detections with MITRE ATT&CK for standardized threat classification
- Fully serverless — no infrastructure to manage

## Summary

This project demonstrates a production-grade cloud native SOC pipeline capable of automated log ingestion, modular detection engineering, multi-source threat intelligence enrichment, and real-time alerting aligned with enterprise SOC operations.

## Author
Solomon James — CyberSOLEX
