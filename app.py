import os
import time
from collections import defaultdict, deque
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from engine import run_scan

app = FastAPI(
    title="Aethelstan API",
    version="1.0.0"
)

API_KEY = os.getenv("API_KEY")

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
def scan(
    request: ScanRequest,
    request_obj: Request,
    x_api_key: Optional[str] = Header(None)
):
    # API Key Check
    if API_KEY is None:
        raise HTTPException(status_code=500)

    if x_api_key != API_KEY:
        raise HTTPException(status_code=403)

    # Rate Limiting
    client_ip = request_obj.client.host
    now = time.time()

    timestamps = request_log[client_ip]

    while timestamps and now - timestamps[0] > RATE_WINDOW:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    timestamps.append(now)

    result = run_scan(request.domain)

    return result
