import os
import time
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from typing import Optional
from engine import run_scan

app = FastAPI(
    title="Aethelstan API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://aethelstan.co",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Rate Limiting Config
# -------------------------
RATE_LIMIT = 10
RATE_WINDOW = 60
request_log = defaultdict(lambda: deque())


class ScanRequest(BaseModel):
    domain: str


# =========================
# v1 ROUTES
# =========================

@app.get("/v1/health")
def health():
    return {
        "status": "ok",
        "version": "v1"
    }


@app.post("/v1/scan")
async def scan(
    request: ScanRequest,
    request_obj: Request
):

    # -------------------------
    # Rate Limiting
    # -------------------------
    client_ip = request_obj.client.host
    now = time.time()
    timestamps = request_log[client_ip]

    while timestamps and now - timestamps[0] > RATE_WINDOW:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    timestamps.append(now)

    # -------------------------
    # Run diagnostic
    # -------------------------
    try:
        result = await run_in_threadpool(run_scan, request.domain)
        return result

    except Exception as e:
        return {
            "status": "error",
            "error_code": "ENGINE_FAILURE",
            "message": str(e)
        }
