# 🛡️ Phishing Email Detector — Behavioral AI

A production-style REST API that detects phishing emails using a 
two-layer pipeline combining **behavioral science pattern matching** 
with **LLM-powered psychological analysis** via Groq (Llama 3.3 70B).

Built with FastAPI · Groq API · Llama 3.3 70B · Python · Pydantic

---

## 🧠 How It Works

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Analyze an email for phishing |
| `GET` | `/history` | View all past analyses |
| `GET` | `/history/{id}` | View one specific analysis |
| `GET` | `/stats` | View detection statistics |
| `DELETE` | `/history` | Clear all history |

---

## 📊 Sample Response

```json
{
  "id": "6021134f",
  "verdict": "phishing",
  "risk_score": 100,
  "confidence": "high",
  "behavioral_triggers": [
    {
      "trigger": "Urgency",
      "evidence": "Your account will be suspended within 24 hours",
      "severity": "high"
    },
    {
      "trigger": "Fear",
      "evidence": "Unauthorized access detected on your account",
      "severity": "high"
    },
    {
      "trigger": "Authority Bias",
      "evidence": "IT Security Team - PayPal Support",
      "severity": "high"
    }
  ],
  "rule_based_flags": [
    "Urgency keywords detected: urgent, immediately, act now",
    "Fear-based language detected: unauthorized, suspicious activity",
    "Authority impersonation detected: security team, paypal",
    "Suspicious domain extension: .xyz",
    "Domain contains numbers — possible typosquatting",
    "Insecure HTTP link found: http://paypal-secure-login.xyz/..."
  ],
  "ai_analysis": {
    "psychological_tactics": [
      "urgency creation",
      "fear induction",
      "authority impersonation",
      "scarcity exploitation"
    ],
    "intent": "credential harvesting",
    "reasoning": "This email uses a classic fear-urgency combination...",
    "recommendation": "Do not interact. Report to legitimate support."
  },
  "analyzed_at": "2026-06-27 17:55:09"
}
```

---

## 🧪 Psychological Triggers Detected

| Trigger | What it detects |
|---------|----------------|
| **Urgency** | Time pressure tactics — "act now", "24 hours", "expires" |
| **Fear** | Threat language — "unauthorized", "suspended", "hacked" |
| **Authority Bias** | Impersonation — "IT Team", "PayPal", "Microsoft", "Bank" |
| **Greed** | Reward bait — "winner", "prize", "free gift", "lottery" |
| **Curiosity** | Click-bait — "shocking", "secret", "you won't believe" |

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **FastAPI** | REST API framework |
| **Groq API** | LLM inference provider |
| **Llama 3.3 70B** | Language model for deep analysis |
| **Pydantic** | Request/response validation |
| **Python** | Core language |
| **JSON** | Lightweight history storage |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- Groq API key (free at [console.groq.com](https://console.groq.com))

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Atharv818/phishing-detector.git
cd phishing-detector
```

**2. Create and activate virtual environment**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up environment variables**

Create a `.env` file in the root directory:


**5. Run the API**
```bash
uvicorn main:app --reload
```

**6. Open the interactive docs**
---

## 📁 Project Structure

---

## 🔬 Domain

This project sits at the intersection of:
- **Cybersecurity** — phishing and social engineering detection
- **Behavioral Science** — cognitive bias exploitation patterns
- **Artificial Intelligence** — LLM-powered reasoning and classification

---

## ⚙️ Environment Variables

| Variable | Description |
|----------|-------------|
| `GROQ_API_KEY` | Your Groq API key from console.groq.com |

---

## 👤 Author

**Atharv Mandhare**
- GitHub: [@Atharv818](https://github.com/Atharv818)
- LinkedIn: [atharv-mandhare](https://linkedin.com/in/atharv-mandhare)
- Email: atharvmandhare78@gmail.com