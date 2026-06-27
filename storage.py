import json
import os
from datetime import datetime
import uuid

HISTORY_FILE = "history.json"


def initialize_file():
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w") as f:
            json.dump([], f)
    else:
        try:
            with open(HISTORY_FILE, "r") as f:
                content = f.read().strip()
                if not content:
                    with open(HISTORY_FILE, "w") as fw:
                        json.dump([], fw)
        except json.JSONDecodeError:
            with open(HISTORY_FILE, "w") as f:
                json.dump([], f)


def read_history():
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def write_history(data):
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def save_analysis(email_request, analysis_response):
    analysis_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "id": analysis_id,
        "sender": email_request.sender,
        "subject": email_request.subject,
        "body": email_request.body,
        "verdict": analysis_response.verdict,
        "risk_score": analysis_response.risk_score,
        "confidence": analysis_response.confidence,
        "behavioral_triggers": [
            t.model_dump() for t in analysis_response.behavioral_triggers
        ],
        "rule_based_flags": analysis_response.rule_based_flags,
        "ai_analysis": analysis_response.ai_analysis.model_dump(),
        "analyzed_at": timestamp
    }

    history = read_history()
    history.insert(0, record)
    write_history(history)

    return analysis_id, timestamp


def get_all_history():
    history = read_history()
    summary = []
    for record in history:
        summary.append({
            "id": record["id"],
            "sender": record["sender"],
            "subject": record["subject"],
            "verdict": record["verdict"],
            "risk_score": record["risk_score"],
            "analyzed_at": record["analyzed_at"]
        })
    return summary


def get_by_id(analysis_id):
    history = read_history()
    for record in history:
        if record["id"] == analysis_id:
            return record
    return None


def get_stats():
    history = read_history()

    if not history:
        return {
            "total_analyzed": 0,
            "phishing_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "average_risk_score": 0.0
        }

    phishing_count = len([r for r in history if r["verdict"] == "phishing"])
    suspicious_count = len([r for r in history if r["verdict"] == "suspicious"])
    safe_count = len([r for r in history if r["verdict"] == "safe"])

    all_scores = [r["risk_score"] for r in history]
    average_score = round(sum(all_scores) / len(all_scores), 2)

    return {
        "total_analyzed": len(history),
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "average_risk_score": average_score
    }


def clear_history():
    write_history([])
    return {"message": "History cleared successfully"}