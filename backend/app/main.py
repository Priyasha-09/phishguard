from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.url_analyzer import analyze_url


app = FastAPI(
    title="PhishGuard API",
    description="An explainable phishing URL and scam message analysis API.",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL to analyze.",
    )


@app.get("/")
def root():
    return {
        "message": "Welcome to PhishGuard API",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1")
def api_info():
    return {
        "name": "PhishGuard API",
        "version": "0.1.0",
        "available_endpoints": [
            "/",
            "/health",
            "/api/v1",
            "/api/v1/analyze/url",
            "/docs",
        ],
    }


@app.post("/api/v1/analyze/url")
def analyze_url_endpoint(request: URLAnalysisRequest):
    try:
        return analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
