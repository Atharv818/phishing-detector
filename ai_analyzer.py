import os
import json
from dotenv import load_dotenv
from groq import Groq
from models import AIAnalysis

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """
You are an expert cybersecurity analyst specializing in 
phishing detection and behavioral psychology.
...
You must ALWAYS respond in valid JSON format only.
No extra text, no explanation outside JSON.
No markdown, no code blocks, just raw JSON.
"""

def build_prompt(sender, subject, body, rule_flags):
    flags_text = "\n".join(rule_flags) if rule_flags else "None detected"
    prompt = f"""
Analyze the email for phishing and psychological manipulation:

SENDER : {sender}
SUBJECT : {subject}
BODY:
{body}

RULE-BASED FLAGS ALREADY DETECTED:
{flags_text}

Based on your analysis, respond with ONLY this JSON structure:
{{
    "psychological_tactics":[...],
    "intent":"...",
    "reasoning":"...",
    "recommendation":"..."
}}
"""
    return prompt

async def analyze_with_ai(sender, subject, body, rule_flags):
    prompt = build_prompt(sender, subject, body, rule_flags)

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=1024,
            temperature=0.3
        )

        raw_content = response.choices[0].message.content

        cleaned = raw_content.strip()
        if cleaned.startswith("```"):
            cleaned = "\n".join(cleaned.split("\n")[1:-1])

        parsed = json.loads(cleaned)

        return AIAnalysis(
            psychological_tactics=parsed.get(
                "psychological_tactics", ["Unable to determine"]
            ),
            intent=parsed.get(
                "intent", "Unable to determine"
            ),
            reasoning=parsed.get(
                "reasoning", "Analysis unavailable"
            ),
            recommendation=parsed.get(
                "recommendation", "Exercise caution with this email"
            )
        )

    except json.JSONDecodeError:
        return AIAnalysis(
            psychological_tactics=["Analysis parsing failed"],
            intent="Unable to parse AI response",
            reasoning=raw_content,
            recommendation="Treat with caution — manual review recommended"
        )

    except Exception as e:
        return AIAnalysis(
            psychological_tactics=["AI analysis unavailable"],
            intent="Service error",
            reasoning=f"AI analysis failed: {str(e)}",
            recommendation="Rule-based analysis still available above"
        )