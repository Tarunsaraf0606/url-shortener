from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from auth_instense import auth

from database import get_db
from db_helper.db_helper_prod import DB
from pydantic import BaseModel
import logging
import jwt
import os
import json
from typing import Optional, Union
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ============================================================================
# JWT CONFIGURATION
# ============================================================================

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "your2secr#t-5ey-must-b33at-lehst-02-characters-long")
JWT_ALGORITHM = "HS256"

# ============================================================================
# UNIFIED TOKEN DECODER
# ============================================================================

def decode_jwt_token(token: str) -> dict:
    """
    Decode JWT token (for email authentication).
    Raises HTTPException if invalid.
    """
    try:
        payload = jwt.decode(token, APP_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )



async def get_current_user(request: Request, db: DB = Depends(get_db)) -> dict:
    """
    Unified user authentication that handles both OAuth and Email tokens.
    
    Returns user dict with standardized fields:
    - id: user ID
    - email: user email
    - username/name: user name
    - provider: "google", "email", or "github"
    - authenticated: True
    """
    
    # Try to get token from cookies or Authorization header
    access_token = request.cookies.get("access_token")
    
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
    
    if not access_token:
        logger.error("❌ No access token found in cookies or headers")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Allowed.Login first"
        )
    
    logger.info(f"🔍 Access token found: {access_token[:30]}...")
    
    # ============================================================================
    # TRY JWT TOKEN FIRST (Email/GitHub)
    # ============================================================================
    try:
        # Attempt to decode as JWT without verification first to peek at claims
        unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
        
        logger.info(f"📋 Unverified payload: {unverified_payload}")
        
        # Check if it's a JWT token (has our custom claims)
        if unverified_payload.get("type") in ["access", "refresh"] and unverified_payload.get("provider") in ["email", "github"]:
            # Now verify the signature
            payload = decode_jwt_token(access_token)
            
            logger.info(f"✅ JWT token decoded for: {payload.get('sub')} (provider: {payload.get('provider')})")
            
            # Get user from database
            user_id = payload.get("user_id")
            logger.info(f"🔍 Looking up user ID: {user_id}")
            
            user = db.table("users").where(id=user_id).first()
            
            if not user:
                logger.error(f"❌ User not found: ID={user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )
            
            logger.info(f"✅ User found: {user.get('email')}")
            
            # Parse profile if it's a JSON string (for SQLite)
            profile = user.get("profile", {})
            if isinstance(profile, str):
                try:
                    profile = json.loads(profile)
                    logger.info(f"📦 Profile parsed from JSON string")
                except json.JSONDecodeError:
                    logger.warning(f"⚠️ Failed to parse profile JSON")
                    profile = {}
            
            return {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("username", user["email"].split("@")[0]),
                "username": user.get("username"),
                "provider": payload.get("provider"),
                "authenticated": True,
                "profile": profile
            }
    
    except jwt.DecodeError as e:
        # Not a JWT token, continue to OAuth check
        logger.debug(f"Not a JWT token: {e}")
        pass
    except jwt.InvalidTokenError as e:
        # JWT token but invalid/expired
        logger.error(f"❌ JWT token invalid: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Other JWT errors, try OAuth
        logger.debug(f"JWT decode failed, trying OAuth: {e}")
        pass
    
    # ============================================================================
    # TRY OAUTH TOKEN (Google) - Only if JWT failed
    # ============================================================================
    try:
        # Use the auth_instense library to verify OAuth token
        user_dependency = auth.user()
        oauth_user = await user_dependency.dependency(request)
        
        logger.info(f"✅ OAuth token verified for: {oauth_user.get('email')}")
        
        # Return in standardized format
        return {
            "id": oauth_user.get("id"),
            "email": oauth_user.get("email"),
            "name": oauth_user.get("name"),
            "username": oauth_user.get("name"),
            "provider": "google",
            "authenticated": True,
            "profile": oauth_user
        }
    
    except Exception as e:
        logger.error(f"❌ All token verification methods failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        ) 
    



async def get_optional_user(request: Request, db: DB = Depends(get_db)) -> Optional[dict]:
    """
    Optional authentication - returns user if authenticated, None otherwise.
    """
    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


# ============================================================================
# MODELS
# ============================================================================

class UserCreate(BaseModel):
    email: str
    username: str
    password: str


def get_database():
    return next(get_db())


user = APIRouter()



@user.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main frontend page."""
    try:
        with open("templates/auth_frontend_html.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html><body>
        <h1>Frontend not found</h1>
        <p>Place auth_frontend_html.html in the project root</p>
        <p><a href="/docs">API Documentation</a></p>
        </body></html>
        """


# ============================================================================
# AUTHENTICATION ROUTES (OAuth)
# ============================================================================

@user.get("/auth/login")
async def login(request: Request):
    """Initiate Google OAuth login."""
    return await auth.login_redirect(request)





@user.get("/auth/callback")
async def callback(request: Request, db: DB = Depends(get_db)):
    """Handle OAuth callback from Google."""
    
    logger.info("📄 OAuth Callback Received")
    logger.info(f"Query params: {dict(request.query_params)}")
    
    try:
        result = await auth.handle_callback(request)
        
        user_data = result.get('user', {})
        user_email = user_data.get('email')
        user_name = user_data.get('name', user_email.split('@')[0] if user_email else 'Unknown')
        
        logger.info(f"✅ Auth successful: {user_email}")
        
        try:
            existing_user = db.table("users").where(email=user_email).first()
            
            if existing_user:
                logger.info(f"👤 User exists: {user_email}")
                db.update("users", {
                    "last_login": "CURRENT_TIMESTAMP"
                }, {"id": existing_user['id']})
                user_id = existing_user['id']
                
            else:
                logger.info(f"➕ Creating new user: {user_email}")
                user_id = db.insert("users", {
                    "email": user_email,
                    "username": user_name,
                    "hashed_password": None,
                    "profile": {
                        "provider": "google",
                        "name": user_name,
                        "picture": user_data.get('picture', ''),
                        "verified_email": user_data.get('verified_email', False)
                    },
                    "last_login": "CURRENT_TIMESTAMP"
                }, return_id=True)
                logger.info(f"✅ User created: ID={user_id}")
            
            db.insert("sessions", {
                "user_id": user_id,
                "access_token": result["access_token"],
                "refresh_token": result["refresh_token"],
                "expires_at": result.get("expires_at", "CURRENT_TIMESTAMP")
            })
            logger.info("✅ Session stored")
            
        except Exception as e:
            logger.error(f"❌ Database error: {e}", exc_info=True)
            logger.warning("⚠️ Continuing without saving to database")
        
        response = RedirectResponse(url="/callback", status_code=303)
        
        cookie_settings = {
            "httponly": True,
            "samesite": "lax",
            "path": "/",
        }
        
        response.set_cookie(
            key="access_token",
            value=result["access_token"],
            max_age=result.get("expires_in", 3600),
            **cookie_settings
        )
        
        response.set_cookie(
            key="refresh_token",
            value=result["refresh_token"],
            max_age=30 * 86400,
            **cookie_settings
        )
        
        logger.info("✅ Login successful, redirecting...")
        return response
        
    except HTTPException as e:
        logger.error(f"❌ HTTPException: {e.detail}")
        from urllib.parse import urlencode
        error_params = {"success": "false", "error": e.detail}
        return RedirectResponse(
            url=f"/?{urlencode(error_params)}",
            status_code=303
        )
        
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        from urllib.parse import urlencode
        error_params = {"success": "false", "error": "Authentication failed"}
        return RedirectResponse(
            url=f"/?{urlencode(error_params)}",
            status_code=303
        )


@user.get("/users")
async def get_users(db: DB = Depends(get_db)):
    """Get all users (example endpoint)."""
    users = db.table("users").select("id", "email", "username", "created_at").all()
    return {"users": users, "count": len(users)}


@user.get("/users/{user_id}")
async def get_user(user_id: int, db: DB = Depends(get_db)):
    """Get user by ID."""
    user = db.table("users").where(id=user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.pop('hashed_password', None)
    return user


@user.post("/auth/logout")
async def logout_endpoint(
    request: Request, 
    current_user: Optional[dict] = Depends(get_optional_user),
    db: DB = Depends(get_db)
):
    """
    Logout user and revoke tokens.
    Handles Google OAuth, GitHub OAuth, and Email OTP authentication.
    """
    logger.info("🚪 Logout Request")
    logger.info(f"   User: {current_user.get('email') if current_user else 'Anonymous'}")
    logger.info(f"   Provider: {current_user.get('provider') if current_user else 'Unknown'}")
    
    try:
        refresh_token = request.cookies.get("refresh_token")
        access_token = request.cookies.get("access_token")
        
        # Handle different authentication providers
        if current_user:
            provider = current_user.get("provider")
            user_id = current_user.get("id")
            
            # 1. Google OAuth - Revoke tokens via OAuth provider
            if provider == "google" and refresh_token:
                try:
                    backend = auth.get_tenant_backend(None)
                    await backend.revoke_refresh_token(refresh_token)
                    logger.info("   ✅ Google OAuth refresh token revoked")
                except Exception as e:
                    logger.warning(f"   ⚠️ Failed to revoke Google token: {e}")
            
            # 2. GitHub OAuth - Delete session from database
            # (GitHub doesn't provide token revocation in the same way)
            # 2. GitHub OAuth - Delete session from database
            elif provider == "github":
                try:
                    deleted = db.delete("sessions", {"user_id": user_id})
                    logger.info(f"   ✅ GitHub sessions deleted from database (count: {deleted})")
                except Exception as e:
                    logger.warning(f"   ⚠️ Failed to delete GitHub sessions: {e}")

            # 3. Email OTP - Delete session from database
            elif provider == "email":
                try:
                    deleted = db.delete("sessions", {"user_id": user_id})
                    logger.info(f"   ✅ Email OTP sessions deleted from database (count: {deleted})")
                except Exception as e:
                    logger.warning(f"   ⚠️ Failed to delete email sessions: {e}")
           
            else:
                logger.warning(f"   ⚠️ Unknown provider: {provider}")
        
        else:
            logger.info("   ℹ️ No authenticated user found, just clearing cookies")
        
        # Create response
        response = JSONResponse(
            content={
                "success": True,
                "message": "Logged out successfully",
                "provider": current_user.get("provider") if current_user else None
            },
            status_code=200
        )
        
        # Clear cookies (works for all providers)
        response.delete_cookie(
            key="access_token",
            path="/",
            domain=None
        )
        response.delete_cookie(
            key="refresh_token",
            path="/",
            domain=None
        )
        
        logger.info("   ✅ Cookies cleared")
        logger.info("   ✅ Logout successful")
        
        return response
        
    except Exception as e:
        logger.error(f"   ❌ Logout error: {e}", exc_info=True)
        
        # Even on error, clear cookies to ensure user is logged out client-side
        response = JSONResponse(
            content={
                "success": False,
                "message": "Logout completed with errors",
                "error": str(e)
            },
            status_code=200  # Return 200 to allow frontend to proceed
        )
        
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        
        logger.info("   ⚠️ Cookies cleared despite error")
        
        return response

@user.post("/auth/refresh")
async def refresh_token_endpoint(request: Request):
    """Refresh access token using refresh token."""
    logger.info("🔄 Token Refresh Request")
    
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        try:
            body = await request.json()
            refresh_token = body.get("refresh_token")
        except:
            pass
    
    if not refresh_token:
        logger.error("   ❌ No refresh token provided")
        raise HTTPException(status_code=400, detail="Refresh token required")
    
    try:
        # Call backend directly (OAuth refresh)
        backend = auth.get_tenant_backend(None)
        result = await backend.refresh_access_token(refresh_token, 
                                                     request.client.host if request.client else None)
        
        logger.info("   ✅ Token refreshed successfully")
        
        response = JSONResponse(content=result)
        
        cookie_settings = {
            "httponly": True,
            "samesite": "lax",
            "path": "/",
        }
        
        response.set_cookie(
            key="access_token",
            value=result["access_token"],
            max_age=result["expires_in"],
            **cookie_settings
        )
        response.set_cookie(
            key="refresh_token",
            value=result["refresh_token"],
            max_age=30 * 86400,
            **cookie_settings
        )
        
        return response
    
    except Exception as e:
        logger.error(f"   ❌ Token refresh failed: {e}")
        raise HTTPException(status_code=401, detail=f"Token refresh failed: {str(e)}")


# ============================================================================
# UNIFIED PROTECTED ROUTES
# ============================================================================
@user.get("/callback" ,response_class=HTMLResponse)
async def serve_callback(current_user:dict = Depends(get_current_user)):
    """Serve the callback page."""
    try:

        with open("templates/callback.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<html><body><h1>Callback page not found</h1></body></html>"

@user.get("/auth/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    """
    Get current user profile - works with both OAuth and Email authentication.
    """
    logger.info(f"🔍 Profile request for: {current_user.get('email')} (provider: {current_user.get('provider')})")
    
    return JSONResponse(content={
        "user": current_user,
        "message": "Profile retrieved successfully",
        "authenticated": True
    })


@user.get("/api/admin")
async def admin_route(current_user: dict = Depends(get_current_user)):
    """Example admin route."""
    if current_user.get("email") == "guddusarafdev@gmail.com":
        return {
            "message": "Admin access granted",
            "user": current_user,
            "note": "Add role checking for production"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access denied"
        )


@user.get("/api/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    """Example protected route - works with both auth methods."""
    return {
        "message": f"Hello {current_user.get('name', 'User')}!",
        "user_id": current_user.get("id"),
        "email": current_user.get("email"),
        "provider": current_user.get("provider"),
        "authenticated": True
    }


@user.get("/api/public")
async def public_route(current_user: Optional[dict] = Depends(get_optional_user)):
    """Public route with optional authentication."""
    if current_user:
        return {
            "message": f"Welcome back, {current_user.get('name')}!",
            "user_id": current_user.get("id"),
            "provider": current_user.get("provider"),
            "authenticated": True
        }
    else:
        return {
            "message": "Welcome, guest!",
            "authenticated": False,
            "note": "Login to access personalized features"
        }


# ============================================================================
# PUBLIC ROUTES
# ============================================================================

@user.get("/api/info")
async def root():
    return {
        "message": "Production Auth API",
        "version": "2.0.0",
        "auth_methods": ["OAuth (Google)", "Email OTP"],
        "docs": "/docs",
        "endpoints": {
            "oauth_login": "/auth/login",
            "oauth_callback": "/auth/callback",
            "email_otp_send": "/api/otp/send",
            "email_otp_verify": "/api/otp/verify",
            "profile": "/auth/profile",
            "logout": "/auth/logout",
            "refresh": "/auth/refresh",
            "health": "/health"
        }
    }


@user.get("/health")
async def health():
    return await auth.health_check()


@user.get("/metrics")
async def metrics():
    return await auth.get_metrics()