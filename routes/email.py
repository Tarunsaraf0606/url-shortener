"""
FastAPI OTP Application with JWT Token Generation
===================================================

Installation:
pip install fastapi uvicorn python-dotenv mailjet-rest redis pydantic[email] pyjwt

Run:
python main.py
"""

import os
from typing import Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, status, APIRouter, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr, validator
from dotenv import load_dotenv
from mailjet_rest import Client
import logging
import jwt

# Import the OTP helper
from otp_helper import OTPManager, OTPConfig, RedisStore, InMemoryStore

# Import your database
from database import get_db
from db_helper.db_helper_prod import DB

# Load environment variables
load_dotenv()

email = APIRouter()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

class Settings:
    """Application settings from environment variables."""
    MAILJET_API_KEY = os.getenv("MAILJET_API_KEY")
    MAILJET_API_SECRET = os.getenv("MAILJET_API_SECRET")
    MAILJET_FROM_EMAIL = os.getenv("MAILJET_FROM_EMAIL", "noreply@yourdomain.com")
    MAILJET_FROM_NAME = os.getenv("MAILJET_FROM_NAME", "OTP Service")
    
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
    
    OTP_LENGTH = int(os.getenv("OTP_LENGTH", 6))
    OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", 300))
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", 3))
    OTP_RESEND_COOLDOWN = int(os.getenv("OTP_RESEND_COOLDOWN", 60))
    
    USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
    
    # JWT Settings
    APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "your-secret-key-must-be-at-least-32-characters-long")
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS = 30  # 30 days

settings = Settings()

# ============================================================================
# JWT TOKEN UTILITIES
# ============================================================================

def create_access_token(email: str, user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": email,
        "user_id": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
        "provider": "email"
    }
    
    encoded_jwt = jwt.encode(to_encode, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(email: str, user_id: int) -> str:
    """Create JWT refresh token."""
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {
        "sub": email,
        "user_id": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "provider": "email"
    }
    
    encoded_jwt = jwt.encode(to_encode, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


# ============================================================================
# MAILJET EMAIL SENDER
# ============================================================================

class MailjetSender:
    """Mailjet email sender wrapper."""
    
    def __init__(self):
        if not settings.MAILJET_API_KEY or not settings.MAILJET_API_SECRET:
            logger.warning("⚠️ Mailjet credentials not found! Using mock sender.")
            self.client = None
        else:
            self.client = Client(
                auth=(settings.MAILJET_API_KEY, settings.MAILJET_API_SECRET),
                version='v3.1'
            )
    
    async def send_email(self, to: str, subject: str, body: str) -> bool:
        """
        Send email via Mailjet.
        
        Args:
            to: Recipient email
            subject: Email subject
            body: Email body (plain text)
        
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.client:
            # Mock mode for development
            logger.info(f"\n📧 [MOCK] Email to {to}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Body:\n{body}\n")
            return True
        
        try:
            data = {
                'Messages': [
                    {
                        "From": {
                            "Email": settings.MAILJET_FROM_EMAIL,
                            "Name": settings.MAILJET_FROM_NAME
                        },
                        "To": [
                            {
                                "Email": to
                            }
                        ],
                        "Subject": subject,
                        "TextPart": body,
                        "HTMLPart": f"<div style='font-family: Arial, sans-serif;'><p>{body.replace(chr(10), '<br>')}</p></div>"
                    }
                ]
            }
            
            result = self.client.send.create(data=data)
            
            if result.status_code == 200:
                logger.info(f"✅ Email sent successfully to {to}")
                return True
            else:
                logger.error(f"❌ Mailjet error: {result.status_code} - {result.json()}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to send email: {str(e)}")
            return False


# ============================================================================
# INITIALIZE SERVICES
# ============================================================================

# Email sender
mailjet_sender = MailjetSender()

# Storage (Redis or In-Memory)
if settings.USE_REDIS:
    logger.info("🔴 Using Redis storage")
    try:
        fallback = InMemoryStore()
        storage = RedisStore(
            redis_url=f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
            key_prefix="otp",
            fallback_store=fallback
        )
    except Exception as e:
        logger.error(f"❌ Redis initialization failed: {e}")
        logger.info("💾 Falling back to In-Memory storage")
        storage = InMemoryStore()
else:
    logger.info("💾 Using In-Memory storage (development mode)")
    storage = InMemoryStore()

# OTP Configuration
from otp_helper import Environment, RedisFallbackStrategy

otp_config = OTPConfig(
    length=settings.OTP_LENGTH,
    ttl_seconds=settings.OTP_TTL_SECONDS,
    max_attempts=settings.OTP_MAX_ATTEMPTS,
    resend_cooldown_seconds=settings.OTP_RESEND_COOLDOWN,
    environment=Environment.DEVELOPMENT,
    redis_fallback=RedisFallbackStrategy.MEMORY
)

# OTP Manager callbacks
def on_send_callback(email: str, otp: Optional[str] = None):
    """Callback when OTP is sent"""
    if otp:
        logger.info(f"📤 OTP sent to {email} - Code: {otp}")
    else:
        logger.info(f"📤 OTP sent to {email}")

def on_verify_callback(email: str, valid: bool):
    """Callback when OTP is verified"""
    logger.info(f"🔍 Verification for {email}: {'✅ Valid' if valid else '❌ Invalid'}")

# OTP Manager
otp_manager = OTPManager(
    storage=storage,
    send_fn=mailjet_sender.send_email,
    config=otp_config,
    on_send=on_send_callback,
    on_verify=on_verify_callback
)

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class SendOTPRequest(BaseModel):
    email: EmailStr
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str
    
    @validator('otp')
    def validate_otp(cls, v):
        if not v or not v.strip():
            raise ValueError("OTP cannot be empty")
        if not v.isdigit():
            raise ValueError("OTP must contain only digits")
        return v.strip()
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "otp": "123456"
            }
        }


class SendOTPResponse(BaseModel):
    success: bool
    message: str
    cooldown_seconds: Optional[int] = None
    expires_in: Optional[int] = None


class VerifyOTPResponse(BaseModel):
    success: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    expires_in: Optional[int] = None


class OTPStatusResponse(BaseModel):
    has_active_otp: bool
    time_left: int
    resend_available_in: int
    attempts_used: int


# ============================================================================
# API ENDPOINTS
# ============================================================================

@email.get("/auth/email", response_class=HTMLResponse)
async def root():
    """Serve the frontend HTML."""
    try:
        return FileResponse("./templates/index.html")
    except:
        return HTMLResponse(content="<h1>Email OTP Authentication</h1>")


@email.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "storage": "redis" if settings.USE_REDIS else "memory",
        "mailjet_configured": bool(settings.MAILJET_API_KEY)
    }


@email.post("/api/otp/send", response_model=SendOTPResponse, status_code=status.HTTP_200_OK)
async def send_otp(request: SendOTPRequest):
    """Send OTP to email address."""
    try:
        result = await otp_manager.send_otp(request.email)
        return SendOTPResponse(**result)
    except Exception as e:
        logger.error(f"Error sending OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP. Please try again later."
        )


@email.post("/api/otp/verify", response_model=VerifyOTPResponse, status_code=status.HTTP_200_OK)
async def verify_otp(request: VerifyOTPRequest, db: DB = Depends(get_db)):
    """Verify OTP and issue JWT tokens."""
    try:
        is_valid = await otp_manager.verify_otp(request.email, request.otp)
        
        if is_valid:
            # ============================================================================
            # OTP VERIFIED - Create/Update User and Generate Tokens
            # ============================================================================
            
            try:
                # Check if user exists
                existing_user = db.table("users").where(email=request.email).first()
                
                if existing_user:
                    logger.info(f"👤 User exists: {request.email}")
                    db.update("users", {
                        "last_login": "CURRENT_TIMESTAMP"
                    }, {"id": existing_user['id']})
                    user_id = existing_user['id']
                    username = existing_user['username']
                    
                else:
                    # Create new user
                    logger.info(f"➕ Creating new user: {request.email}")
                    username = request.email.split('@')[0]
                    user_id = db.insert("users", {
                        "email": request.email,
                        "username": username,
                        "hashed_password": None,  # Email OTP users don't have passwords
                        "profile": {
                            "provider": "email",
                            "verified_email": True
                        },
                        "last_login": "CURRENT_TIMESTAMP"
                    }, return_id=True)
                    logger.info(f"✅ User created: ID={user_id}")
                
                # Generate JWT tokens
                access_token = create_access_token(request.email, user_id)
                refresh_token = create_refresh_token(request.email, user_id)
                
                # Store session in database
                db.insert("sessions", {
                    "user_id": user_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": "CURRENT_TIMESTAMP"  # Adjust as needed
                })
                logger.info("✅ Session stored")
                
                # Create response with tokens
                response = JSONResponse(content={
                    "success": True,
                    "message": "Email verified successfully",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    "user": {
                        "id": user_id,
                        "email": request.email,
                        "username": username
                    }
                })
                
                # Set tokens in cookies (same as OAuth)
                cookie_settings = {
                    "httponly": True,
                    "samesite": "lax",
                    "path": "/",
                }
                
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    **cookie_settings
                )
                
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
                    **cookie_settings
                )
                
                logger.info(f"✅ Email authentication successful for {request.email}")
                return response
                
            except Exception as e:
                logger.error(f"❌ Database error during email verification: {e}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to complete authentication"
                )
        
        else:
            # OTP verification failed
            has_otp = await otp_manager.has_active_otp(request.email)
            attempts = await otp_manager.get_attempts(request.email)
            
            if not has_otp:
                message = "Invalid or expired OTP"
            elif attempts >= settings.OTP_MAX_ATTEMPTS:
                message = "Maximum verification attempts exceeded"
            else:
                remaining = settings.OTP_MAX_ATTEMPTS - attempts
                message = f"Invalid OTP. {remaining} attempt(s) remaining"
            
            return VerifyOTPResponse(
                success=False,
                message=message
            )
            
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify OTP. Please try again later."
        )


@email.get("/api/otp/status/{email}", response_model=OTPStatusResponse)
async def get_otp_status(email: EmailStr):
    """Get OTP status for an email address."""
    try:
        return OTPStatusResponse(
            has_active_otp=await otp_manager.has_active_otp(email),
            time_left=await otp_manager.time_left(email),
            resend_available_in=await otp_manager.resend_available_in(email),
            attempts_used=await otp_manager.get_attempts(email)
        )
    except Exception as e:
        logger.error(f"Error getting OTP status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get OTP status"
        )


@email.delete("/api/otp/{email}")
async def clear_otp(email: EmailStr):
    """Clear OTP for an email address (admin use)."""
    try:
        cleared = await otp_manager.clear_otp(email)
        return {
            "success": cleared,
            "message": "OTP cleared successfully" if cleared else "No OTP found"
        }
    except Exception as e:
        logger.error(f"Error clearing OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear OTP"
        )


# Mount static files directory (if it exists)
try:
    email.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    logger.info("Static directory not found, using embedded HTML")