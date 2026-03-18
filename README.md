# AI SOC Log Analyzer

This project implements a serverless SOC (Security Operations Center) log analysis pipeline using AWS Lambda and CloudWatch.

It processes log events, extracts Indicators of Compromise (IOCs), maps activity to MITRE ATT&CK techniques, and enriches findings using the VirusTotal API.

---

## Overview

The Lambda function performs:

- IOC extraction (IP addresses, domains, file hashes)
- MITRE ATT&CK technique mapping
- Threat intelligence enrichment via VirusTotal
- Structured JSON output for analysis and logging

The system is triggered automatically by CloudWatch Logs, simulating a real SOC ingestion pipeline.

---

## Project Structure

| File | Description |
|------|------------|
| `lambda_function.py` | Core Lambda logic (IOC extraction, MITRE mapping, VT enrichment) |
| `test_logs.json` | Sample input events for testing |
| `README.md` | Project documentation |
| `screenshots/` | Execution and validation evidence |

---

## Example Input

```json
{
  "log": "powershell -nop connecting to 8.8.8.8 domain example.com hash d41d8cd98f00b204e9800998ecf8427e"
}
```

Example Output

```
{
  "severity": "Informational",
  "technique": "Unknown",
  "summary": "SOC analysis with threat intel enrichment",
  "iocs": {
    "ips": ["8.8.8.8"],
    "domains": ["example.com"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
  },
  "threat_intel": {
    "8.8.8.8": {
      "malicious": 0,
      "suspicious": 0,
      "reputation": "clean"
    }
  },
  "timestamp": "2026-03-17T..."
}
```
## CloudWatch Integration

A CloudWatch log group (/aws/soc/logs) is configured to trigger the Lambda function automatically.

This enables real-time processing of incoming log events without manual execution.

## Execution Evidence
Lambda Execution (Start)

Threat Intelligence Output

These logs confirm:

Successful Lambda invocation

IOC extraction and parsing

VirusTotal enrichment

Structured output generation

Threat Intelligence Integration

The function integrates with the VirusTotal v3 API to enrich detected IOCs.

## Configuration

Set the following environment variable in Lambda:

Key	Value
VT_API_KEY	Your VirusTotal API key

## Enrichment Output

Each IOC is evaluated and assigned:

malicious (number of vendor detections)

suspicious (number of suspicious flags)

reputation (clean, suspicious, or malicious)
