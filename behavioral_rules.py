import re
from models import BehavioralTrigger

URGENCY_KEYWORDS = [
    "urgent", "immediately", "expires", "expiring",
    "act now", "limited time", "24 hours", "48 hours",
    "today only", "right now", "don't delay", "asap",
    "last chance", "final notice", "account suspended",
    "suspended", "suspension", "deadline", "overdue"
]

FEAR_KEYWORDS = [
    "unauthorized", "suspicious activity", "security alert",
    "security breach", "hacked", "compromised", "detected",
    "warning", "blocked", "locked", "verify immediately",
    "unusual login", "failed attempt", "risk", "danger",
    "violation", "illegal", "fraud detected"
]

AUTHORITY_KEYWORDS = [
    "it department", "it team", "helpdesk", "support team",
    "security team", "microsoft", "google", "apple", "amazon",
    "paypal", "bank", "irs", "government", "ceo", "management",
    "hr department", "official", "admin", "administrator",
    "your bank", "customer support", "tech support"
]

GREED_KEYWORDS = [
    "winner", "won", "prize", "reward", "free", "gift",
    "claim now", "selected", "lucky", "congratulations",
    "bonus", "cash", "money", "inheritance", "lottery",
    "investment", "profit", "earn", "million", "thousand",
    "refund", "cashback", "voucher", "discount"
]

CURIOSITY_KEYWORDS = [
    "you won't believe", "check this out", "see what happened",
    "someone shared", "you have been mentioned", "look at this",
    "shocking", "secret", "confidential", "private",
    "don't miss", "exclusive", "hidden"
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".click", ".link", ".work", ".party"
]

IMPERSONATED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "netflix", "facebook", "instagram", "twitter",
    "whatsapp", "hdfc", "sbi", "icici", "axis"
]


def check_keywords(text, keyword_list):
    text_lower = text.lower()
    found = [kw for kw in keyword_list if kw in text_lower]
    return found


def analyze_sender(sender):
    flags = []
    score = 0
    sender_lower = sender.lower()

    for domain in SUSPICIOUS_DOMAINS:
        if sender_lower.endswith(domain):
            flags.append(f"Suspicious domain extension: {domain}")
            score += 20
            break

    for brand in IMPERSONATED_BRANDS:
        if brand in sender_lower:
            if f"@{brand}.com" not in sender_lower:
                flags.append(f"Possible brand impersonation: {brand}")
                score += 25
                break

    free_providers = ["gmail.com", "yahoo.com", "hotmail.com",
                      "outlook.com", "rediffmail.com"]
    for provider in free_providers:
        if provider in sender_lower:
            flags.append(f"Official-sounding email from free provider: {provider}")
            score += 10
            break

    if re.search(r'[0-9]', sender_lower.split('@')[-1].split('.')[0]):
        flags.append("Domain contains numbers — possible typosquatting")
        score += 15

    return flags, score


def run_behavioral_analysis(sender, subject, body):
    triggers = []
    flags = []
    rule_score = 0

    full_text = f"{subject} {body}"

    urgency_found = check_keywords(full_text, URGENCY_KEYWORDS)
    if urgency_found:
        evidence = next(
            (line for line in full_text.split('.')
             if any(kw in line.lower() for kw in urgency_found)),
            urgency_found[0]
        )
        triggers.append(BehavioralTrigger(
            trigger="Urgency",
            evidence=evidence.strip(),
            severity="high" if len(urgency_found) >= 2 else "medium"
        ))
        flags.append(f"Urgency keywords detected: {', '.join(urgency_found[:3])}")
        rule_score += min(25, len(urgency_found) * 5)

    fear_found = check_keywords(full_text, FEAR_KEYWORDS)
    if fear_found:
        evidence = next(
            (line for line in full_text.split('.')
             if any(kw in line.lower() for kw in fear_found)),
            fear_found[0]
        )
        triggers.append(BehavioralTrigger(
            trigger="Fear",
            evidence=evidence.strip(),
            severity="high" if len(fear_found) >= 2 else "medium"
        ))
        flags.append(f"Fear-based language detected: {', '.join(fear_found[:3])}")
        rule_score += min(25, len(fear_found) * 5)

    authority_found = check_keywords(full_text, AUTHORITY_KEYWORDS)
    if authority_found:
        evidence = next(
            (line for line in full_text.split('.')
             if any(kw in line.lower() for kw in authority_found)),
            authority_found[0]
        )
        triggers.append(BehavioralTrigger(
            trigger="Authority Bias",
            evidence=evidence.strip(),
            severity="high"
        ))
        flags.append(f"Authority impersonation detected: {', '.join(authority_found[:3])}")
        rule_score += 20

    greed_found = check_keywords(full_text, GREED_KEYWORDS)
    if greed_found:
        evidence = next(
            (line for line in full_text.split('.')
             if any(kw in line.lower() for kw in greed_found)),
            greed_found[0]
        )
        triggers.append(BehavioralTrigger(
            trigger="Greed",
            evidence=evidence.strip(),
            severity="medium"
        ))
        flags.append(f"Reward/greed bait detected: {', '.join(greed_found[:3])}")
        rule_score += 15

    curiosity_found = check_keywords(full_text, CURIOSITY_KEYWORDS)
    if curiosity_found:
        triggers.append(BehavioralTrigger(
            trigger="Curiosity Exploitation",
            evidence=curiosity_found[0],
            severity="low"
        ))
        flags.append(f"Curiosity manipulation detected: {', '.join(curiosity_found[:2])}")
        rule_score += 10

    sender_flags, sender_score = analyze_sender(sender)
    flags.extend(sender_flags)
    rule_score += sender_score

    urls = re.findall(r'http[s]?://\S+', body)
    if urls:
        for url in urls:
            if url.startswith("http://"):
                flags.append(f"Insecure HTTP link found: {url[:50]}")
                rule_score += 10
            for sus_domain in SUSPICIOUS_DOMAINS:
                if sus_domain in url:
                    flags.append(f"Suspicious domain in link: {url[:50]}")
                    rule_score += 15
                    break

    if not body.strip():
        flags.append("Empty email body — suspicious")
        rule_score += 10

    rule_score = min(rule_score, 100)

    return triggers, flags, rule_score
