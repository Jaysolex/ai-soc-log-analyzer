
# AI SOC Log Analyzer

This project implements a serverless SOC log analysis pipeline using AWS Lambda and CloudWatch. It processes log events, extracts indicators of compromise, maps activity to MITRE ATT&CK techniques, and enriches findings using the VirusTotal API. The pipeline simulates real world SOC workflows including detection, triage, and threat intelligence integration. and Reducing MTTR, faster IOC indications and reducing manual SOC tasks

## Overview

The Lambda function performs automated analysis of incoming log data with the following capabilities:

- IOC extraction including IP addresses, domains, and file hashes  
- MITRE ATT and CK technique mapping based on behavioral indicators  
- Threat intelligence enrichment using VirusTotal  
- Structured JSON output for downstream analysis and logging  

The system is triggered automatically by CloudWatch Logs, enabling real time log ingestion and processing without manual intervention.

## Architecture

CloudWatch Logs to AWS Lambda to IOC extraction to MITRE mapping to VirusTotal enrichment to structured JSON output to S3 storage

This architecture simulates a cloud native SOC pipeline for ingestion, detection, enrichment, and storage.

## Detection and Analysis Logic

Detection logic is based on identifying suspicious behavior and mapping it to known adversary techniques:

- PowerShell execution with suspicious flags such as nop and hidden mapped to T1059.001  
- Detection of known malicious file hashes indicating confirmed compromise  
- Identification of suspicious IP addresses and domains as network indicators  

Severity is assigned based on risk:

- Informational for clean indicators  
- Medium for suspicious activity  
- High for confirmed malicious indicators  
- Critical for multiple high confidence indicators such as malicious hash and command and control IP  

## Project Structure

| File | Description |
|------|------------|
| lambda_function.py | Core Lambda logic for IOC extraction, MITRE mapping, and threat intelligence enrichment |
| test_logs.json | Sample input events for testing |
| README.md | Project documentation |
| screenshots | Execution and validation evidence |

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
  "timestamp": "2026-03-17T"
}
```
## CloudWatch Integration

A CloudWatch log group (/aws/soc/logs) is configured to trigger the Lambda function automatically.
This enables real-time processing of incoming log events without manual execution.

## Threat Intelligence Integration
The pipeline integrates with the VirusTotal API to enrich detected indicators. Each IOC is evaluated and assigned:
Malicious count based on vendor detections
Suspicious count
Reputation classification such as clean, suspicious, or malicious

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

##Critical Threat Detection Simulation
The system was tested using a simulated attack containing PowerShell execution, malicious hash values, and suspicious network indicators.

## Configuration

Set the following environment variable in Lambda:

Key	Value
VT_API_KEY	Your VirusTotal API key

## Enrichment Output

Each IOC is evaluated and assigned:
malicious (number of vendor detections)
suspicious (number of suspicious flags)

reputation (clean, suspicious, or malicious)



## Critical Threat Detection (SOC Simulation)
The system was tested using a simulated attack log containing PowerShell execution, a known malicious hash, and suspicious network indicators.

## Detection Result
```
{
  "severity": "Critical",
  "technique": "T1059.001",
  "iocs": {
    "ips": ["185.220.101.1"],
    "domains": ["badsite.ru"],
    "hashes": ["44d88612fea8a8f36de82e1278abb02f"]
  },
  "threat_intel": {
    "185.220.101.1": {
      "malicious": 15,
      "suspicious": 3,
      "reputation": "malicious"
    },
    "44d88612fea8a8f36de82e1278abb02f": {
      "malicious": 67,
      "suspicious": 0,
      "reputation": "malicious"
    }
  },
  "s3_upload": {
    "status": "saved"
  }
}

```
## Key Outcomes

- Detected suspicious PowerShell activity mapped to MITRE ATT&CK (T1059.001)
- Extracted multiple IOCs (IP, domain, file hash)
- Enriched indicators using VirusTotal threat intelligence
- Identified high-confidence malicious hash (67 vendor detections)
- Automatically escalated severity to Critical
- Persisted results to Amazon S3 for further analysis
=======
## SOC Value

- Reduces analyst triage time through automated IOC extraction
- Enhances detection accuracy using threat intelligence enrichment
- Produces structured output suitable for SIEM ingestion and correlation
- Simulates a real SOC pipeline from ingestion to detection and response
- Aligns alerts with MITRE ATT and CK for standardized threat classification

  

## Summary

This project demonstrates a cloud native SOC pipeline capable of automated log ingestion, detection engineering, threat intelligence enrichment, and structured alert generation aligned with enterprise SOC operations.
