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

ADMIN_USER = "NexusOps"
ADMIN_PASSWORD = os.environ.get("NEXUS_ADMIN_PASSWORD", "")
JWT_SECRET = os.environ.get("NEXUS_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY = 43200  # 12 hours
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", ".praxiumholdings.com")

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
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'"
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
        accept = request.headers.get("Accept", "")
        if "text/html" in accept:
            raise HTTPException(status_code=303, detail="redirect",
                                headers={"Location": "/unauthorized"})
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
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
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
    # Use .praxiumholdings.com domain for custom domain, omit domain for Railway URLs
    host = request.headers.get("host", "")
    cookie_domain = COOKIE_DOMAIN if "praxiumholdings.com" in host else None
    resp.set_cookie(
        key="nexus_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=cookie_domain,
        path="/",
        max_age=JWT_EXPIRY,
    )
    return resp


@app.get("/command", response_class=HTMLResponse)
def command_center(request: Request):
    payload = _verify_token(request)
    if not payload:
        return RedirectResponse(url="/", status_code=303)
    return FileResponse(str(static_dir / "command.html"))


@app.get("/unauthorized", response_class=HTMLResponse)
def unauthorized_page():
    return FileResponse(str(static_dir / "unauthorized.html"))


@app.get("/auth/logout")
def logout(request: Request):
    resp = RedirectResponse(url="/", status_code=303)
    host = request.headers.get("host", "")
    cookie_domain = COOKIE_DOMAIN if "praxiumholdings.com" in host else None
    resp.delete_cookie(key="nexus_session", domain=cookie_domain, path="/")
    # Also clear without domain for Railway URLs
    if cookie_domain:
        resp.delete_cookie(key="nexus_session", path="/")
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


# ── NEXUS Proxy Endpoints (all data flows through gateway) ────────────────────
# Backend services require JWT auth — gateway forwards the cookie as Bearer token.

def _proxy(request: Request, service: str, path: str):
    """Proxy a request to a backend service, forwarding JWT auth."""
    url = SERVICES.get(service, "")
    if not url:
        return {"error": "unknown service", "data": None}
    # Forward JWT from cookie as Bearer token to backend
    token = request.cookies.get("nexus_session", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = httpx.get(f"{url}{path}", headers=headers, timeout=10)
        if r.status_code == 401:
            return {"error": "backend auth failed", "data": None}
        return r.json()
    except Exception as e:
        return {"error": f"service unavailable: {str(e)[:100]}", "data": None}


@app.get("/api/nexus/stats")
def nexus_stats(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/stats")


@app.get("/api/nexus/positions")
def nexus_positions(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/positions")


@app.get("/api/nexus/pipeline")
def nexus_pipeline(request: Request, user=Depends(require_auth)):
    return _proxy(request, "core", "/api/pipeline-stats")


@app.get("/api/nexus/signal")
def nexus_signal(request: Request, user=Depends(require_auth)):
    return _proxy(request, "core", "/api/primary-signal")


@app.get("/api/nexus/closed")
def nexus_closed(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/trades/today")


@app.get("/api/nexus/account")
def nexus_account(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/account")


@app.get("/api/nexus/agent")
def nexus_agent(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/agent/status")


@app.get("/api/nexus/system-stats")
def nexus_system_stats(request: Request, user=Depends(require_auth)):
    return _proxy(request, "trading", "/api/system-stats")


@app.get("/api/nexus/debug")
def nexus_debug(request: Request, user=Depends(require_auth)):
    """Temporary debug endpoint — verify proxy chain is working."""
    token = request.cookies.get("nexus_session", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = {"services_config": SERVICES, "has_token": bool(token)}
    for name, url in SERVICES.items():
        try:
            r = httpx.get(f"{url}/api/health", headers=headers, timeout=5)
            results[f"{name}_health"] = {"status": r.status_code, "body": r.json()}
        except Exception as e:
            results[f"{name}_health"] = {"status": "error", "body": str(e)[:100]}
    # Test one protected endpoint
    try:
        r = httpx.get(f"{SERVICES['trading']}/api/account", headers=headers, timeout=5)
        results["trading_account_test"] = {"status": r.status_code, "body": r.json() if r.status_code == 200 else r.text[:200]}
    except Exception as e:
        results["trading_account_test"] = {"status": "error", "body": str(e)[:100]}
    return results


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
