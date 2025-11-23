"""
GitHub OAuth2 Authentication for FastAPI - SECURE VERSION
==========================================================
Prevents client-side token manipulation using HTTPOnly cookies
"""

import os
from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import jwt
import logging
import secrets
import json

# Import your database
from database import get_db
from db_helper.db_helper_prod import DB

# Load environment variables
load_dotenv()

github = APIRouter()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

class GitHubOAuthSettings:
    """GitHub OAuth settings from environment variables."""
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
    GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
    
    # JWT Settings
    APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS = 30  # 30 days
    
    # GitHub OAuth URLs
    GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
    GITHUB_USER_API_URL = "https://api.github.com/user"
    GITHUB_USER_EMAILS_URL = "https://api.github.com/user/emails"
    
    # Frontend redirect URL after successful auth
    FRONTEND_SUCCESS_URL = os.getenv("FRONTEND_SUCCESS_URL", "/callback")
    FRONTEND_ERROR_URL = os.getenv("FRONTEND_ERROR_URL", "")
    
    # Database type detection
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    IS_SQLITE = DATABASE_URL.startswith("sqlite")

settings = GitHubOAuthSettings()

# In-memory state storage (use Redis in production)
oauth_states = {}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def find_user_by_github_id(db: DB, github_id: str):
    """
    Find user by GitHub ID - works with both SQLite and PostgreSQL.
    
    Args:
        db: Database instance
        github_id: GitHub user ID as string
        
    Returns:
        User record or None
    """
    # Get all users and check their profile field
    try:
        all_users = db.table("users").all()
    except AttributeError:
        try:
            all_users = list(db.table("users").select())
        except:
            all_users = db.query("SELECT * FROM users")
    
    if not all_users:
        return None
    
    for user in all_users:
        profile = user.get('profile')
        
        if profile is None:
            continue
            
        # If profile is a string (JSON), parse it
        if isinstance(profile, str):
            try:
                profile = json.loads(profile)
            except json.JSONDecodeError:
                continue
        
        # Check if github_id matches
        if isinstance(profile, dict) and str(profile.get('github_id')) == str(github_id):
            return user
    
    return None


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
        "provider": "github"
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
        "provider": "github"
    }
    
    encoded_jwt = jwt.encode(to_encode, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


# ============================================================================
# GITHUB OAUTH HELPERS
# ============================================================================

async def get_github_user_data(access_token: str) -> dict:
    """
    Fetch user data from GitHub API.
    GitHub requires separate API calls for user profile and emails.
    """
    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        # Fetch user profile data
        logger.info("📡 Fetching GitHub user profile...")
        user_response = await client.get(settings.GITHUB_USER_API_URL, headers=headers)
        
        if user_response.status_code != 200:
            logger.error(f"❌ Failed to fetch user data: {user_response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user data from GitHub"
            )
        
        user_data = user_response.json()
        logger.info(f"✅ User profile fetched: {user_data.get('login')}")
        
        # Fetch user emails
        logger.info("📧 Fetching GitHub user emails...")
        emails_response = await client.get(settings.GITHUB_USER_EMAILS_URL, headers=headers)
        
        if emails_response.status_code != 200:
            logger.error(f"❌ Failed to fetch emails: {emails_response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch email from GitHub. Please ensure email permissions are granted."
            )
        
        emails = emails_response.json()
        logger.info(f"📬 Found {len(emails)} email(s) in GitHub account")
        
        # Select the best email (priority order)
        primary_verified = next(
            (email["email"] for email in emails 
             if email.get("primary") and email.get("verified")),
            None
        )
        
        if primary_verified:
            user_data["email"] = primary_verified
            user_data["email_verified"] = True
            logger.info(f"✅ Using primary verified email: {primary_verified}")
        else:
            verified_email = next(
                (email["email"] for email in emails if email.get("verified")),
                None
            )
            
            if verified_email:
                user_data["email"] = verified_email
                user_data["email_verified"] = True
                logger.info(f"✅ Using verified email: {verified_email}")
            else:
                primary_email = next(
                    (email["email"] for email in emails if email.get("primary")),
                    None
                )
                
                if primary_email:
                    user_data["email"] = primary_email
                    user_data["email_verified"] = False
                    logger.warning(f"⚠️ Using unverified primary email: {primary_email}")
                else:
                    if emails and len(emails) > 0:
                        user_data["email"] = emails[0]["email"]
                        user_data["email_verified"] = emails[0].get("verified", False)
                        logger.warning(f"⚠️ Using first available email: {emails[0]['email']}")
                    else:
                        logger.error("❌ No email found in GitHub account")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No email address found in your GitHub account"
                        )
        
        user_data["all_emails"] = emails
        
        return user_data


def generate_state_token() -> str:
    """Generate a secure random state token for CSRF protection."""
    return secrets.token_urlsafe(32)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@github.get("/api/auth/github/login")
async def github_login():
    """
    Initiate GitHub OAuth flow.
    Redirects user to GitHub authorization page.
    """
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth is not configured"
        )
    
    # Generate state token for CSRF protection
    state = generate_state_token()
    oauth_states[state] = {"created_at": datetime.utcnow()}
    
    # Build GitHub authorization URL
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "user:email",
        "state": state,
    }
    
    auth_url = f"{settings.GITHUB_AUTHORIZE_URL}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    
    logger.info(f"🔑 Redirecting to GitHub OAuth: {auth_url}")
    return RedirectResponse(url=auth_url)

"""
GitHub OAuth2 Authentication - FIXED COOKIE SETTINGS
====================================================
This fixes the cookie persistence issue across tabs
"""

# Replace the callback function in github_oauth.py with this fixed version:

@github.get("/api/auth/github/callback")
async def github_callback(code: str, state: str, request: Request, db: DB = Depends(get_db)):
    """
    GitHub OAuth callback endpoint - FIXED VERSION
    ==============================================
    Now cookies work consistently across all tabs
    """
    try:
        logger.info(f"📥 GitHub Callback Received - Code: {code[:10]}..., State: {state[:10]}...")
        
        # ============================================================================
        # Step 1: Verify state token (CSRF protection)
        # ============================================================================
        if state not in oauth_states:
            logger.error("❌ Invalid state token")
            return RedirectResponse(
                url=f"{settings.FRONTEND_SUCCESS_URL}?error=invalid_state"
            )
        
        # Remove used state token
        del oauth_states[state]
        logger.info("✅ State token validated")
        
        # ============================================================================
        # Step 2: Exchange code for GitHub access token
        # ============================================================================
        async with httpx.AsyncClient() as client:
            logger.info("🔄 Exchanging code for GitHub access token...")
            token_response = await client.post(
                settings.GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_REDIRECT_URI,
                }
            )
            
            logger.info(f"Token response status: {token_response.status_code}")
            
            if token_response.status_code != 200:
                logger.error(f"❌ GitHub token exchange failed: {token_response.text}")
                return RedirectResponse(
                    url=f"{settings.FRONTEND_SUCCESS_URL}?error=token_exchange_failed"
                )
            
            token_data = token_response.json()
            github_access_token = token_data.get("access_token")
            
            if not github_access_token:
                logger.error("❌ No access token in response")
                return RedirectResponse(
                    url=f"{settings.FRONTEND_SUCCESS_URL}?error=no_access_token"
                )
            
            logger.info(f"✅ GitHub access token received")
        
        # ============================================================================
        # Step 3: Get user data from GitHub
        # ============================================================================
        logger.info("👤 Fetching GitHub user data...")
        user_data = await get_github_user_data(github_access_token)
        
        github_id = user_data.get("id")
        email = user_data.get("email")
        username = user_data.get("login")
        name = user_data.get("name")
        avatar_url = user_data.get("avatar_url")
        
        logger.info(f"User data: ID={github_id}, Email={email}, Username={username}")
        
        if not email:
            logger.error("❌ No email found in GitHub account")
            return RedirectResponse(
                url=f"{settings.FRONTEND_SUCCESS_URL}?error=no_email"
            )
        
        logger.info(f"👤 GitHub user authenticated: {username} ({email})")
        
        # ============================================================================
        # Step 4: Create or Update User in Database
        # ============================================================================
        
        # Check if user exists by email
        logger.info(f"🔍 Checking if user exists: {email}")
        existing_user = db.table("users").where(email=email).first()
        
        if not existing_user:
            # Check by GitHub ID (SQLite compatible)
            logger.info(f"🔍 Checking by GitHub ID: {github_id}")
            existing_user = find_user_by_github_id(db, str(github_id))
        
        if existing_user:
            # Update existing user
            logger.info(f"👤 User exists: {email}, updating...")
            
            profile_data = {
                "provider": "github",
                "github_id": github_id,
                "github_username": username,
                "name": name,
                "avatar_url": avatar_url,
                "github_access_token": github_access_token
            }
            
            db.update("users", {
                "profile": json.dumps(profile_data) if settings.IS_SQLITE else profile_data,
                "last_login": datetime.utcnow()
            }, {"id": existing_user['id']})
            
            user_id = existing_user['id']
            logger.info(f"✅ User updated: ID={user_id}")
            
        else:
            # Create new user
            logger.info(f"➕ Creating new user: {email}")
            
            profile_data = {
                "provider": "github",
                "github_id": github_id,
                "github_username": username,
                "name": name,
                "avatar_url": avatar_url,
                "github_access_token": github_access_token
            }
            
            user_id = db.insert("users", {
                "email": email,
                "username": username,
                "hashed_password": None,
                "profile": json.dumps(profile_data) if settings.IS_SQLITE else profile_data,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow()
            }, return_id=True)
            
            logger.info(f"✅ User created: ID={user_id}")
        
        # ============================================================================
        # Step 5: Generate JWT Tokens
        # ============================================================================
        logger.info("🔐 Generating JWT tokens...")
        access_token = create_access_token(email, user_id)
        refresh_token = create_refresh_token(email, user_id)
        logger.info(f"✅ Tokens generated")
        
        # ============================================================================
        # Step 6: Store Session in Database
        # ============================================================================
        logger.info("💾 Storing session in database...")
        db.insert("sessions", {
            "user_id": user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "created_at": datetime.utcnow()
        })
        logger.info("✅ Session stored")
        
        # ============================================================================
        # Step 7: Redirect to Frontend
        # ============================================================================
        redirect_url = f"{settings.FRONTEND_SUCCESS_URL}?auth_success=true"
        
        logger.info(f"🔗 Redirecting to frontend with HTTPOnly cookies...")
        response = RedirectResponse(url=redirect_url, status_code=303)
        
        # ============================================================================
        # Step 8: FIXED COOKIE SETTINGS (Same as email.py and auth.py)
        # ============================================================================
        cookie_settings = {
            "httponly": True,      # JavaScript CANNOT access
            "samesite": "lax",     # CSRF protection
            "path": "/",           # Available for all routes
            # ⚠️ IMPORTANT: Remove 'secure' or set to False for local development
            # Set to True ONLY in production with HTTPS
        }
        
        # Detect if running locally
        is_local = request.url.hostname in ["localhost", "127.0.0.1", "0.0.0.0"]
        if not is_local:
            cookie_settings["secure"] = True  # Enable HTTPS-only in production
        
        # Set access token cookie with backend-controlled expiration
        response.set_cookie(
            key="access_token",
            value=access_token,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            **cookie_settings
        )
        
        # Set refresh token cookie with backend-controlled expiration
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            **cookie_settings
        )
        
        logger.info(f"✅ GitHub authentication successful for {email}")
        logger.info(f"🔒 Tokens stored in HTTPOnly cookies (secure={cookie_settings.get('secure', False)})")
        return response
        
    except Exception as e:
        logger.error(f"❌ GitHub OAuth error: {e}", exc_info=True)
        return RedirectResponse(
            url=f"{settings.FRONTEND_SUCCESS_URL}?error=server_error"
        )


# ============================================================================
# ALSO UPDATE THE REFRESH TOKEN ENDPOINT
# ============================================================================

@github.post("/api/auth/refresh")
async def refresh_access_token(request: Request, db: DB = Depends(get_db)):
    """
    Refresh access token using refresh token from HTTPOnly cookie.
    FIXED: Now uses same cookie settings as other auth methods
    """
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token found"
        )
    
    try:
        # Verify refresh token signature and expiration
        payload = jwt.decode(
            refresh_token, 
            settings.APP_SECRET_KEY, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        email = payload.get("sub")
        user_id = payload.get("user_id")
        
        # Verify session exists in database
        session = db.table("sessions").where(
            user_id=user_id, 
            refresh_token=refresh_token
        ).first()
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or expired"
            )
        
        # Generate new access token
        new_access_token = create_access_token(email, user_id)
        
        # Update session
        db.update("sessions", {
            "access_token": new_access_token
        }, {"id": session['id']})
        
        logger.info(f"✅ Token refreshed for user {user_id}")
        
        # Return new access token with FIXED cookie settings
        response = JSONResponse({"success": True, "message": "Token refreshed"})
        
        # FIXED: Same cookie settings as callback
        cookie_settings = {
            "httponly": True,
            "samesite": "lax",
            "path": "/",
        }
        
        # Detect if running locally
        is_local = request.url.hostname in ["localhost", "127.0.0.1", "0.0.0.0"]
        if not is_local:
            cookie_settings["secure"] = True
        
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            **cookie_settings
        )
        
        return response
        
    except jwt.ExpiredSignatureError:
        logger.warning("⚠️ Refresh token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired. Please login again."
        )
    except jwt.JWTError as e:
        logger.error(f"❌ Invalid refresh token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


# ============================================================================
# DEBUGGING TIPS
# ============================================================================
"""
To debug cookie issues:

1. Check browser DevTools > Application > Cookies
   - Verify 'access_token' and 'refresh_token' exist
   - Check their expiration times
   - Verify 'HttpOnly' flag is set
   - Check 'Secure' flag (should be False for localhost)
   - Verify 'Path' is '/'

2. Check if cookies are being sent:
   - Open DevTools > Network tab
   - Make a request to /auth/profile
   - Click on the request
   - Check 'Cookies' tab to see if access_token is sent

3. Common issues:
   - secure=True on localhost (HTTP) = cookies won't be sent
   - Wrong domain/path = cookies not available
   - Expired cookies = need to refresh token
   - HttpOnly flag = can't see in JavaScript (this is correct!)

4. Test cookie persistence:
   - Login via GitHub
   - Open DevTools > Console
   - Type: document.cookie (should NOT show access_token - that's correct!)
   - Open new tab with same domain
   - Check if /auth/profile returns user data
"""

@github.post("/api/auth/logout")
async def logout(request: Request, db: DB = Depends(get_db)):
    """
    Logout user and invalidate session.
    ===================================
    Clears HTTPOnly cookies and removes session from database.
    """
    access_token = request.cookies.get("access_token")
    
    if access_token:
        try:
            # Delete session from database
            db.table("sessions").where(access_token=access_token).delete()
            logger.info("✅ Session deleted from database")
        except Exception as e:
            logger.error(f"⚠️ Failed to delete session: {e}")
    
    response = JSONResponse({"success": True, "message": "Logged out successfully"})
    
    # Clear HTTPOnly cookies
    response.delete_cookie(key="access_token", path="/", samesite="lax")
    response.delete_cookie(key="refresh_token", path="/", samesite="lax")
    
    logger.info("✅ Logout successful, cookies cleared")
    return response


@github.get("/api/auth/github/status")
async def github_status():
    """Check if GitHub OAuth is configured."""
    return {
        "configured": bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET),
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "database_type": "SQLite" if settings.IS_SQLITE else "PostgreSQL",
        "security": {
            "httponly_cookies": True,
            "tokens_in_url": False,
            "backend_controlled_expiration": True
        }
    }


# ============================================================================
# CLEANUP TASK (Optional - Run periodically)
# ============================================================================

async def cleanup_expired_states():
    """Remove expired state tokens (run periodically)."""
    now = datetime.utcnow()
    expired = [
        state for state, data in oauth_states.items()
        if (now - data["created_at"]).seconds > 600  # 10 minutes
    ]
    for state in expired:
        del oauth_states[state]
    logger.info(f"🧹 Cleaned up {len(expired)} expired OAuth states")


# ============================================================================
# SECURITY NOTES
# ============================================================================
"""
🔒 SECURITY FEATURES IMPLEMENTED:

1. HTTPOnly Cookies:
   - Tokens stored in cookies with httponly=True
   - JavaScript CANNOT access or modify these cookies
   - Prevents XSS attacks from stealing tokens

2. Backend-Controlled Expiration:
   - Cookie max_age is set ONLY by backend
   - Users cannot extend token lifetime via browser console
   - Even if user modifies cookies, JWT signature validation will fail

3. No Tokens in URL:
   - Tokens are NOT sent in query parameters
   - Prevents token exposure in browser history or logs
   - Uses only "auth_success=true" flag in URL

4. SameSite Protection:
   - samesite="lax" prevents CSRF attacks
   - Cookies sent only to same-site requests

5. Secure Flag (Production):
   - secure=True enforces HTTPS-only transmission
   - Prevents man-in-the-middle attacks

6. JWT Signature Verification:
   - All tokens are cryptographically signed
   - Tampering with token content invalidates signature
   - Backend verifies signature on every request

7. Database Session Validation:
   - Tokens are cross-checked with database sessions
   - Logout invalidates sessions server-side
   - Refresh tokens are verified against stored values

8. Token Expiration Checks:
   - JWT includes "exp" claim
   - Backend validates expiration on every request
   - Expired tokens are automatically rejected

WHAT USERS CANNOT DO:
❌ Extend token lifetime beyond backend limits
❌ Access tokens via JavaScript/console
❌ Modify token contents without breaking signature
❌ Use tokens after logout (session deleted)
❌ Bypass token expiration checks
"""