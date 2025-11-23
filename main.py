"""
FastAPI Application with Email OTP and GitHub OAuth2
====================================================

Installation:
pip install fastapi uvicorn python-dotenv httpx pyjwt mailjet-rest redis pydantic[email]

Run:
python main.py

Or with uvicorn:
uvicorn main:app --reload --host 0.0.0.0 --port 9000
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import routers
from routes.email import email  # Your email OTP router
from github_oauth import github  # GitHub OAuth router
from routes.auth import user
from routes.url_short import url_manage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

ENV = os.getenv("ENV", "development").lower()
IS_PRODUCTION = ENV == "production"
YOUR_DOMAIN = os.getenv("DOMAIN", "yourdomain.com")

# ============================================================================
# LIFESPAN EVENTS
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan event handler for startup and shutdown.
    """
    # Startup
    logger.info("🚀 Starting Authentication API...")
    logger.info("=" * 60)
    logger.info(f"📍 Environment: {ENV.upper()}")
    logger.info("📧 Email OTP Authentication: ENABLED")
    logger.info("🐙 GitHub OAuth2 Authentication: ENABLED")
    logger.info("🔵 Google OAuth2 Authentication: ENABLED")
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down Authentication API...")

# ============================================================================
# CREATE FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Authentication API",
    description="Multi-provider authentication with Email OTP and GitHub OAuth2",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# ============================================================================
# SIMPLE CORS CONFIGURATION
# ============================================================================

if IS_PRODUCTION:
    # Production: Only your domain
    allowed_origins = [
        f"https://{YOUR_DOMAIN}",
        f"https://www.{YOUR_DOMAIN}",
    ]
    logger.info(f"🔒 CORS: Production mode - {YOUR_DOMAIN}")
else:
    # Development: Localhost on various ports
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8000",
        "http://localhost:9000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:9000",
    ]
    logger.info("🔒 CORS: Development mode - localhost allowed")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info(f"✅ CORS configured with {len(allowed_origins)} origins")

# ============================================================================
# INCLUDE ROUTERS
# ============================================================================

app.include_router(user, tags=["google auth"])
app.include_router(url_manage, tags=["url"])
app.include_router(email, tags=["Email Authentication"])
app.include_router(github, tags=["GitHub OAuth"])

# ============================================================================
# ROOT ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Authentication API",
        "version": "1.0.0",
        "environment": ENV,
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "email_otp": {
                "send": "/api/otp/send",
                "verify": "/api/otp/verify",
                "status": "/api/otp/status/{email}"
            },
            "github_oauth": {
                "login": "/api/auth/github/login",
                "callback": "/api/auth/github/callback",
                "status": "/api/auth/github/status"
            },
            "google_auth": {
                "login": "/auth/login",
                "callback": "/auth/callback",
                "profile": "/auth/profile"
            }
        }
    }


@app.get("/health")
async def health_check():
    """
    Global health check endpoint.
    Combines health checks from all authentication methods.
    """
    return {
        "status": "healthy",
        "environment": ENV,
        "timestamp": "2024-01-01T00:00:00Z",
        "services": {
            "email_otp": {
                "enabled": True,
                "mailjet_configured": bool(os.getenv("MAILJET_API_KEY")),
                "storage": "redis" if os.getenv("USE_REDIS", "false").lower() == "true" else "memory"
            },
            "github_oauth": {
                "enabled": True,
                "configured": bool(os.getenv("GITHUB_CLIENT_ID") and os.getenv("GITHUB_CLIENT_SECRET"))
            },
            "google_oauth": {
                "enabled": True,
                "configured": bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
            }
        }
    }


@app.get("/api/auth/providers")
async def get_auth_providers():
    """
    Get list of available authentication providers.
    """
    providers = []
    
    # Check Email OTP
    if os.getenv("MAILJET_API_KEY"):
        providers.append({
            "name": "email",
            "display_name": "Email OTP",
            "type": "otp",
            "enabled": True,
            "endpoint": "/api/otp/send"
        })
    
    # Check GitHub OAuth
    if os.getenv("GITHUB_CLIENT_ID"):
        providers.append({
            "name": "github",
            "display_name": "GitHub",
            "type": "oauth2",
            "enabled": True,
            "endpoint": "/api/auth/github/login"
        })
    
    # Check Google OAuth
    if os.getenv("GOOGLE_CLIENT_ID"):
        providers.append({
            "name": "google",
            "display_name": "Google",
            "type": "oauth2",
            "enabled": True,
            "endpoint": "/auth/login"
        })
    
    return {
        "providers": providers,
        "total": len(providers)
    }

# ============================================================================
# LOGOUT ENDPOINT (Shared)
# ============================================================================

@app.post("/api/auth/logout")
async def logout():
    """
    Logout endpoint - clears authentication cookies.
    Works for both email and GitHub authentication.
    """
    response = JSONResponse(content={
        "success": True,
        "message": "Logged out successfully"
    })
    
    # Clear cookies
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
    
    logger.info("👋 User logged out")
    return response

# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 9000))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        "main:app",
        # host=host,
        port=port,
        reload=True,
        log_level="info"
    )