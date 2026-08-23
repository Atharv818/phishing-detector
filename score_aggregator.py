def calculate_ai_boost(ai_analysis):
    tactic_count = len(ai_analysis.psychological_tactics)
    boost = min(tactic_count * 8, 30)

    dangerous_intents = [
        "credential", "password", "steal", "harvest",
        "malware", "scam", "fraud", "financial", "personal data"
    ]

    intent_lower = ai_analysis.intent.lower()

    if any(word in intent_lower for word in dangerous_intents):
        boost += 10

    return min(boost, 30)


def determine_verdict(final_score):
    if final_score >= 70:
        return "phishing"
    elif final_score >= 40:
        return "suspicious"
    else:
        return "safe"


def determine_confidence(rule_score, ai_boost, trigger_count):
    if rule_score >= 50 and ai_boost >= 15 and trigger_count >= 3:
        return "high"

    if rule_score <= 10 and ai_boost <= 5 and trigger_count == 0:
        return "high"

    if rule_score >= 25 or ai_boost >= 10 or trigger_count >= 1:
        return "medium"

    return "low"


def aggregate_scores(rule_score, triggers, ai_analysis):
    ai_boost = calculate_ai_boost(ai_analysis)
    final_score = min(rule_score + ai_boost, 100)
    verdict = determine_verdict(final_score)
    confidence = determine_confidence(
        rule_score=rule_score,
        ai_boost=ai_boost,
        trigger_count=len(triggers)
    )

    return {
        "final_score": final_score,
        "verdict": verdict,
        "confidence": confidence
    }
