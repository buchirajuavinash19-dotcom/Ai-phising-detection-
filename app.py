from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import uvicorn
import logging

from services.url_analyzer import URLAnalyzer
from services.email_analyzer import EmailAnalyzer

# ─── Setup ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Detection ML Service",
    description="AI-powered phishing detection using ML models",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzers
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()

# ─── Schemas ─────────────────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str
    scan_id: Optional[str] = None

class EmailRequest(BaseModel):
    subject: str
    sender: str
    body: str
    headers: Optional[Dict] = {}
    scan_id: Optional[str] = None

class BatchRequest(BaseModel):
    urls: Optional[List[str]] = []
    emails: Optional[List[EmailRequest]] = []
    batch_id: Optional[str] = None

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "models_loaded": True}


@app.post("/predict/url")
async def predict_url(request: URLRequest):
    try:
        result = url_analyzer.analyze(request.url)
        return result
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/email")
async def predict_email(request: EmailRequest):
    try:
        result = email_analyzer.analyze(
            subject=request.subject,
            sender=request.sender,
            body=request.body,
            headers=request.headers,
        )
        return result
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
async def predict_batch(request: BatchRequest):
    results = []

    for url in (request.urls or []):
        try:
            r = url_analyzer.analyze(url)
            results.append({"type": "url", "input": url, **r})
        except Exception as e:
            results.append({"type": "url", "input": url, "error": str(e)})

    for email in (request.emails or []):
        try:
            r = email_analyzer.analyze(
                subject=email.subject,
                sender=email.sender,
                body=email.body,
                headers=email.headers,
            )
            results.append({"type": "email", "input": email.sender, **r})
        except Exception as e:
            results.append({"type": "email", "input": email.sender, "error": str(e)})

    return {"results": results}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
