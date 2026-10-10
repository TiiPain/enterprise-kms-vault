"""Enterprise Key Management Service (KMS) & Secret Vault Application Entrypoint."""

import os
from contextlib import asynccontextmanager
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from app.api import auth, keys, secrets, audit
from app.api.keys import serialize_wrapped_key
from app.config import settings
from app.crypto.audit_chain import record_audit_event
from app.crypto.envelope import EnvelopeCryptoEngine
from app.models.database import MasterKey, SessionLocal, engine, init_db


def seed_default_master_key():
    """Ensure at least one active Master Key (KEK) exists upon server initialization."""
    db = SessionLocal()
    try:
        existing_key = db.execute(
            select(MasterKey).where(MasterKey.status == "ACTIVE")
        ).scalar_one_or_none()

        if not existing_key:
            # Generate and wrap default Master Key
            raw_kek = EnvelopeCryptoEngine.generate_kek()
            root_kek = settings.get_root_kek_bytes()
            wrapped_envelope = EnvelopeCryptoEngine.wrap_key(kek=root_kek, target_key=raw_kek)
            del raw_kek

            default_key = MasterKey(
                id="k-default-root-v1",
                key_name="default-system-kek",
                key_version=1,
                encrypted_key_bytes=serialize_wrapped_key(wrapped_envelope),
                status="ACTIVE",
            )
            db.add(default_key)
            db.commit()

            record_audit_event(
                db,
                actor_id="SYSTEM_INIT",
                action="KEY_GEN",
                resource_id=default_key.id,
            )
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context: initialize database schema and seed root keys."""
    init_db(engine)
    seed_default_master_key()
    yield


app = FastAPI(
    title="Authenticated Enterprise Key Management Service (KMS) & Secret Vault",
    description=(
        "Production-grade KMS & Vault implementing Two-Tier Envelope Encryption (AES-256-GCM), "
        "Argon2id password hashing, 15-minute brute-force lockout defenses, Zero-Knowledge RBAC, "
        "and Tamper-Evident SHA-256/HMAC audit log chaining."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for defense demo and frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Inject enterprise security headers into every HTTP response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: https:;"
    )
    return response


@app.exception_handler(InvalidTag)
async def invalid_tag_exception_handler(request: Request, exc: InvalidTag):
    """Global handler ensuring cryptographic tag verification failures return safe 400 responses."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Cryptographic integrity failure: ciphertext or authentication tag was tampered with."},
    )


# API v1 Router
api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth.router)
api_v1_router.include_router(keys.router)
api_v1_router.include_router(secrets.router)
api_v1_router.include_router(audit.router)

app.include_router(api_v1_router)

# Mount static web dashboard assets
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", tags=["Dashboard"], include_in_schema=False)
def serve_dashboard():
    """Serve the interactive single-page Web UI security dashboard."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Authenticated Enterprise KMS & Secret Vault API Online"}


@app.get("/health", tags=["System Health"])
def health_check():
    """Healthcheck endpoint for monitoring system availability."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
