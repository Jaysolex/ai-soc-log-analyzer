import json
import logging
import os
import boto3
import urllib.request
import base64
import gzip
import process_behavior
import network_anomalies
import cloud_identity
import ransomware
import exfiltration
import lateral_movement
import enrichment
import automation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

def decode_cloudwatch_event(event):
    try:
        compressed = base64.b64decode(event["awslogs"]["data"])
        decompressed = gzip.decompress(compressed)
        log_data = json.loads(decompressed)
        logs = [e["message"] for e in log_data.get("logEvents", [])]
        return " ".join(logs)
    except Exception:
        return event.get("log", "")

def send_slack_alert(finding):
    try:
        message = {
            "text": ":rotating_light: *HIGH SEVERITY SOC ALERT*",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Severity", "value": finding.get("severity"), "short": True},
                        {"title": "Technique", "value": finding.get("technique", "N/A"), "short": True},
                        {"title": "Description", "value": finding.get("description", "N/A"), "short": False},
                        {"title": "IOCs", "value": json.dumps(finding.get("iocs", {})), "short": False}
                    ]
                }
            ]
        }
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(message).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
        logger.info("Slack alert sent!")
    except Exception as e:
        logger.error(f"Slack error: {str(e)}")

def send_alert(finding):
    severity = finding.get("severity")
    if severity in ["High", "Critical"]:
        if SNS_TOPIC_ARN:
            sns = boto3.client("sns")
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"{severity.upper()} SEVERITY SOC ALERT",
                Message=f"Severity: {finding.get('severity')}\nTechnique: {finding.get('technique')}\nDescription: {finding.get('description')}\nMITRE Phase: {finding.get('mitre_phase', 'N/A')}\nThreat Intel: {json.dumps(finding.get('threat_intel', {}), indent=2)}"
            )
            logger.info("SNS alert sent!")
        if SLACK_WEBHOOK_URL:
            send_slack_alert(finding)

def lambda_handler(event, context):
    if "awslogs" in event:
        log = decode_cloudwatch_event(event)
        logger.info("CloudTrail event received")
    else:
        log = event.get("log", "")
        logger.info("Manual test event received")

    results = []
    results += process_behavior.analyze(log)
    results += network_anomalies.analyze(log)
    results += cloud_identity.analyze(log)
    results += ransomware.analyze(log)
    results += exfiltration.analyze(log)
    results += lateral_movement.analyze(log)

    enriched = enrichment.enrich(results)
    deduped, report = automation.correlate(enriched)

    logger.info("=== SOC REPORT ===")
    logger.info(f"Timestamp: {report['timestamp']}")
    logger.info(f"Total Findings: {report['total_findings']}")

    for i, finding in enumerate(deduped, 1):
        logger.info(f"--- Finding {i} ---")
        logger.info(f"Severity: {finding.get('severity', 'N/A')}")
        logger.info(f"Technique: {finding.get('technique', 'N/A')}")
        logger.info(f"Phase: {finding.get('mitre_phase', 'N/A')}")
        logger.info(f"Description: {finding.get('description', 'N/A')}")
        intel = finding.get("threat_intel", {})
        for ioc, data in intel.items():
            logger.info(f"  IOC: {ioc}")
            if isinstance(data, dict):
                for source, result in data.items():
                    logger.info(f"    {source}: {json.dumps(result)}")
            else:
                logger.info(f"    value: {json.dumps(data)}")
        send_alert(finding)

    return {
        "statusCode": 200,
        "summary": report,
        "results": deduped
    }
