import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

from engine import run_scan

app = FastAPI(title="Aethelstan API")

API_KEY = os.getenv("API_KEY")


class ScanRequest(BaseModel):
    domain: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(
    request: ScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    if API_KEY is None:
        raise HTTPException(status_code=500)

    if x_api_key != API_KEY:
        raise HTTPException(status_code=403)

    result = run_scan(request.domain)

    return result
