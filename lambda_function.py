import json
from detections import process_behavior, network_anomalies, cloud_identity, enrichment, automation

def lambda_handler(event, context):
    log = event.get("log", "")

    results = []
    results += process_behavior.analyze(log)
    results += network_anomalies.analyze(log)
    results += cloud_identity.analyze(log)

    enriched = enrichment.enrich(results)
    deduped, report = automation.correlate(enriched)

    return {
        "statusCode": 200,
        "summary": report,
        "results": deduped
    }
