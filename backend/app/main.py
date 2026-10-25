from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database import (
    get_scans,
    initialize_database,
    save_scan,
)
from app.ml_analyzer import analyze_message_ml
from app.message_analyzer import analyze_message
from app.url_analyzer import analyze_url


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="PhishGuard API",
    description=(
        "An explainable phishing URL and scam message "
        "analysis API with persistent scan history."
    ),
    version="0.3.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
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


class MessageAnalysisRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The message to analyze.",
    )


@app.get("/")
def root():
    return {
        "message": "Welcome to PhishGuard API",
        "status": "running",
        "version": "0.3.0",
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
        "version": "0.3.0",
        "available_endpoints": [
            "/",
            "/health",
            "/api/v1",
            "/api/v1/analyze/url",
            "/api/v1/analyze/message",
            "/api/v1/analyze/message/ml",
            "/api/v1/history",
            "/docs",
        ],
    }



@app.post("/api/v1/analyze/url")
def analyze_url_endpoint(request: URLAnalysisRequest):
    try:
        result = analyze_url(request.url)

        save_scan(
            scan_type="url",
            input_text=request.url,
            result=result,
        )

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/analyze/message")
def analyze_message_endpoint(
    request: MessageAnalysisRequest,
):
    try:
        result = analyze_message(request.message)

        save_scan(
            scan_type="message",
            input_text=request.message,
            result=result,
        )

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.get("/api/v1/history")
def scan_history(
    limit: int = Query(default=50, ge=1, le=100),
):
    return {
        "total_returned": 0,
        "scans": [],
    } | {
        "total_returned": len(scans := get_scans(limit)),
        "scans": scans,
    }

@app.post("/api/v1/analyze/message/ml")
def analyze_message_ml_endpoint(
    request: MessageAnalysisRequest,
):
    try:
        result = analyze_message_ml(request.message)

        save_scan(
            scan_type="message_ml",
            input_text=request.message,
            result=result,
        )

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
