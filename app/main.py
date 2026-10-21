"""HTTP interface for the local VeritasPack demo."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .core import ProtocolError, Store

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("VERITAS_DB", str(ROOT / "data" / "veritas.db")))
DATA.parent.mkdir(parents=True, exist_ok=True)
store = Store(DATA)
store.seed()
app = FastAPI(title="VeritasPack", version="1.0.0", docs_url="/api/docs", redoc_url=None)


class ScanInput(BaseModel):
    product_id: str = Field(max_length=64)
    uid: str = Field(max_length=64)
    counter: int
    challenge: str = Field(max_length=64)
    tamper: bool
    mac: str = Field(max_length=128)


class DemoInput(BaseModel):
    product_id: str = Field(max_length=64)
    scenario: str = Field(pattern="^(authentic|replay|clone|tamper)$")


def local_only(request: Request):
    host = request.client.host if request.client else ""
    hostname = request.url.hostname
    if host not in ("127.0.0.1", "::1") or hostname not in ("127.0.0.1", "localhost"):
        raise HTTPException(403, "Local demo actions require a loopback connection")
    origin = request.headers.get("origin")
    if origin and origin not in ("http://127.0.0.1:8000", "http://localhost:8000"):
        raise HTTPException(403, "Invalid origin")


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/style.css")
def style():
    return FileResponse(ROOT / "web" / "style.css", media_type="text/css")


@app.get("/app.js")
def javascript():
    return FileResponse(ROOT / "web" / "app.js", media_type="text/javascript")


@app.get("/favicon.svg")
def favicon():
    return FileResponse(ROOT / "web" / "favicon.svg", media_type="image/svg+xml")


@app.get("/api/overview")
def overview():
    with store.lock:
        products = store.products()
        return {"products": products, "events": store.events(limit=100), "ledger_valid": store.ledger_valid(),
            "ledger_height": store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "authenticated_scans": store.db.execute("SELECT COUNT(*) FROM events WHERE kind IN ('AUTHENTICATED','TAMPER_DETECTED')").fetchone()[0],
            "latest_hash": store.db.execute("SELECT hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()[0]}


@app.get("/api/products/{pid}")
def product(pid: str):
    try:
        return {"product": store.product(pid), "events": store.events(pid, limit=30)}
    except ProtocolError as exc:
        raise HTTPException(404, {"code": exc.code, "message": exc.detail}) from exc


@app.get("/api/verify/{pid}")
def public_verify(pid: str):
    try:
        product = store.product(pid)
        return {"product_id": pid, "name": product["name"], "sku": product["sku"],
                "batch": product["batch"], "seal": "TRIPPED" if product["tampered"] else "INTACT",
                "last_authenticated_scan": product["last_seen"], "ledger_valid": store.ledger_valid(),
                "note": "A product ID alone does not authenticate a physical item. Use a secure-tag scan."}
    except ProtocolError as exc:
        raise HTTPException(404, {"code": exc.code, "message": exc.detail}) from exc


@app.post("/api/challenge/{pid}")
def challenge(pid: str):
    try:
        return {"challenge": store.challenge(pid), "expires_in_seconds": 60}
    except ProtocolError as exc:
        raise HTTPException(404, {"code": exc.code, "message": exc.detail}) from exc


@app.post("/api/scan")
def scan(body: ScanInput):
    try:
        return store.verify_scan(body.product_id, body.uid, body.counter, body.challenge, body.tamper, body.mac)
    except ProtocolError as exc:
        raise HTTPException(400, {"code": exc.code, "message": exc.detail}) from exc


@app.post("/api/demo/scan")
def demo_scan(body: DemoInput, request: Request):
    local_only(request)
    try:
        pid = body.product_id
        if body.scenario == "replay" and store.product(pid)["counter"] == 0:
            first = store.virtual_proof(pid, store.challenge(pid))
            store.verify_scan(**first)
        nonce = store.challenge(pid)
        proof = store.virtual_proof(pid, nonce, tamper=body.scenario == "tamper",
                                    counter=store.product(pid)["counter"] if body.scenario == "replay" else None)
        if body.scenario == "clone":
            proof["mac"] = "00" * 32  # copied UID without the secure tag key
        try:
            result = store.verify_scan(**proof)
            return {"accepted": True, "code": "TAMPER_DETECTED" if result["tampered"] else "AUTHENTICATED",
                    "message": "Secure tag authenticated. Seal is tripped." if result["tampered"] else "Secure tag authenticated. Seal intact.",
                    "result": result}
        except ProtocolError as exc:
            return {"accepted": False, "code": exc.code, "message": exc.detail}
    except ProtocolError as exc:
        raise HTTPException(400, {"code": exc.code, "message": exc.detail}) from exc


@app.post("/api/demo/reset")
def reset(request: Request):
    local_only(request)
    store.reset()
    return {"ok": True}
