"""
NEXUS Gateway — Unified secure front door for all NEXUS services.
Single login, JWT cookie shared across *.praxiumholdings.com subdomains.
"""

import os
import time
from pathlib import Path

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

ADMIN_USER = "admin"
ADMIN_PASSWORD = os.environ.get("NEXUS_ADMIN_PASSWORD", "")
JWT_SECRET = os.environ.get("NEXUS_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY = 43200  # 12 hours
COOKIE_DOMAIN = ".praxiumholdings.com"

SERVICES = {
    "core": "https://core.praxiumholdings.com",
    "execution": "https://execution.praxiumholdings.com",
    "trading": "https://trading.praxiumholdings.com",
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ── Security Middleware ───────────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.praxiumholdings\.com",
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── JWT Helpers ───────────────────────────────────────────────────────────────
def _create_token(username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXPIRY,
        "iss": "nexus-gateway",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _verify_token(request: Request) -> dict:
    token = request.cookies.get("nexus_session")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if "sub" not in payload or "exp" not in payload or "iss" not in payload:
            return None
        return payload
    except JWTError:
        return None


def require_auth(request: Request):
    payload = _verify_token(request)
    if not payload:
        raise HTTPException(status_code=401, detail="unauthorized")
    return payload


# ── Public Routes ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    payload = _verify_token(request)
    if payload:
        return FileResponse(str(static_dir / "index.html"))
    return FileResponse(str(static_dir / "login.html"))


@app.post("/auth/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USER or password != ADMIN_PASSWORD:
        return HTMLResponse(
            content=open(str(static_dir / "login.html")).read().replace(
                "<!-- ERROR_MSG -->",
                '<div class="error">Invalid credentials</div>'
            ),
            status_code=401,
        )
    token = _create_token(username)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="nexus_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=COOKIE_DOMAIN,
        path="/",
        max_age=JWT_EXPIRY,
    )
    return resp


@app.get("/auth/logout")
def logout():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(
        key="nexus_session",
        domain=COOKIE_DOMAIN,
        path="/",
    )
    return resp


# ── Protected Routes ──────────────────────────────────────────────────────────
@app.get("/api/service-status")
def service_status(user=Depends(require_auth)):
    results = {}
    for name, url in SERVICES.items():
        try:
            r = httpx.get(f"{url}/api/health", timeout=5)
            if r.status_code == 200:
                results[name] = "ok"
            else:
                results[name] = "down"
        except Exception:
            results[name] = "down"
    return results


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
