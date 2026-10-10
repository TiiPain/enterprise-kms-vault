"""Enterprise Key Management Service (KMS) & Secret Vault Application Entrypoint."""

from contextlib import asynccontextmanager
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
