from fastapi import FastAPI, HTTPException
from models import (
    EmailRequest,
    EmailAnalysisResponse,
    HistoryItem,
    StatsResponse
)
from behavioral_rules import run_behavioral_analysis
from ai_analyzer import analyze_with_ai
from score_aggregator import aggregate_scores
from storage import (
    initialize_file,
    save_analysis,
    get_all_history,
    get_by_id,
    get_stats,
    clear_history
)

app = FastAPI(
    title="Phishing Email Detector",
    description="Behavioral AI-powered phishing detection API using Groq + Llama 3.3",
    version="1.0.0"
)


@app.on_event("startup")
async def startup_event():
    initialize_file()
    print("✅ Phishing Detector API started successfully!")
    print("📖 Docs available at: http://127.0.0.1:8000/docs")


@app.get("/")
async def root():
    return {
        "message": "Phishing Email Detector API is running!",
        "version": "1.0.0",
        "docs": "Visit /docs to test the API"
    }


@app.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(email: EmailRequest):
    triggers, flags, rule_score = run_behavioral_analysis(
        sender=email.sender,
        subject=email.subject,
        body=email.body
    )

    ai_analysis = await analyze_with_ai(
        sender=email.sender,
        subject=email.subject,
        body=email.body,
        rule_flags=flags
    )

    result = aggregate_scores(
        rule_score=rule_score,
        triggers=triggers,
        ai_analysis=ai_analysis
    )

    response = EmailAnalysisResponse(
        id="temp",
        verdict=result["verdict"],
        risk_score=result["final_score"],
        confidence=result["confidence"],
        behavioral_triggers=triggers,
        rule_based_flags=flags,
        ai_analysis=ai_analysis,
        analyzed_at="temp"
    )

    analysis_id, timestamp = save_analysis(email, response)

    final_response = EmailAnalysisResponse(
        id=analysis_id,
        verdict=result["verdict"],
        risk_score=result["final_score"],
        confidence=result["confidence"],
        behavioral_triggers=triggers,
        rule_based_flags=flags,
        ai_analysis=ai_analysis,
        analyzed_at=timestamp
    )

    return final_response


@app.get("/history")
async def get_history():
    history = get_all_history()
    if not history:
        return {
            "message": "No analyses yet",
            "history": []
        }
    return {
        "total": len(history),
        "history": history
    }


@app.get("/history/{analysis_id}")
async def get_single_analysis(analysis_id: str):
    record = get_by_id(analysis_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis with ID '{analysis_id}' not found"
        )
    return record


@app.get("/stats", response_model=StatsResponse)
async def get_statistics():
    stats = get_stats()
    return stats


@app.delete("/history")
async def delete_history():
    result = clear_history()
    return result
