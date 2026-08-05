# Import tools from pydantic and python libraries
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# Request Model - what user send to API
class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str

# Reprsent ONE bahavioral trigger found in the email
class BehavioralTrigger(BaseModel):
    trigger: str        # Name: "Urgency", "Fear", etc.
    evidence: str      # The exact text that triggered it
    severity: str      # "high", "medium", "low"

# hods everything API found about the mail
class AIAnalysis(BaseModel):
    psychological_tactics: List[str]        # List of tactics used
    intent: str                            # What attackers wants
    reasoning: str                           # Detailed explanation
    recommendation: str                     # what user should do

# Full response model - what API sends Back
class EmailAnalysisResponse(BaseModel):
    id: str                                 # Unique ID for this analysis
    verdict: str                            # "phishing", "suspicious", "safe"
    risk_score: int                         # 0 to 100
    confidence: str                         # "high", "medium", "low"
    behavioral_triggers: List[BehavioralTrigger]    # All triggers found
    rule_based_flags: List[str]             # Simple flag messages
    ai_analysis: AIAnalysis                 # Full AI breakdown
    analyzed_at: str                        # Timestamp

# Simple models for other endpoints
class HistoryItem(BaseModel):
    id: str
    sender: str
    subject: str
    verdict: str
    risk_score: int
    analyzed_at: str

class StatsResponse(BaseModel):
    total_analyzed: int
    phishing_count: int
    suspicious_count: int
    safe_count: int
    average_risk_score: float        
    
