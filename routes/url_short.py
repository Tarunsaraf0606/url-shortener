
from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import RedirectResponse
from auth_instense import auth

from database import get_db
from db_helper.db_helper_prod import DB
from pydantic import BaseModel
import logging
import jwt
import os
import json
import string
import random
import base64
from typing import Optional
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "your2secr#t-5ey-must-b33at-lehst-02-characters-long")
JWT_ALGORITHM = "HS256"

# Reserved routes that cannot be used as custom aliases
RESERVED_ROUTES = {
    'create', 'urls', 'auth', 'api', 'admin', 'static', 
    'login', 'logout', 'signup', 'dashboard', 'profile'
}

# ============================================================================
# JWT TOKEN DECODER
# ============================================================================

def decode_jwt_token(token: str) -> dict:
    """Decode JWT token (for email/github authentication)"""
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
    """Unified user authentication that handles both OAuth and Email tokens"""
    
    # Try to get token from cookies or Authorization header
    access_token = request.cookies.get("access_token")
    
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
    
    if not access_token:
        logger.error("❌ No access token found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Allowed. Login first"
        )
    
    logger.info(f"🔑 Access token found: {access_token[:30]}...")
    
    # Try JWT token first
    try:
        unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
        logger.info(f"📋 Unverified payload: {unverified_payload}")
        
        if unverified_payload.get("type") in ["access", "refresh"] and unverified_payload.get("provider") in ["email", "github"]:
            payload = decode_jwt_token(access_token)
            logger.info(f"✅ JWT token decoded for: {payload.get('sub')} (provider: {payload.get('provider')})")
            
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
            
            profile = user.get("profile", {})
            if isinstance(profile, str):
                try:
                    profile = json.loads(profile)
                except json.JSONDecodeError:
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
    
    except jwt.DecodeError:
        pass
    except jwt.InvalidTokenError as e:
        logger.error(f"❌ JWT token invalid: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.debug(f"JWT decode failed, trying OAuth: {e}")
    
    # Try OAuth token (Google)
    try:
        user_dependency = auth.user()
        oauth_user = await user_dependency.dependency(request)
        logger.info(f"✅ OAuth token verified for: {oauth_user.get('email')}")
        
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


url_manage = APIRouter()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_short_code(length: int = 6) -> str:
    """Generate a random short code for URL"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def generate_base64_short_code(url: str, length: int = 8) -> str:
    """Generate a short code using base64 encoding of URL hash"""
    import hashlib
    url_hash = hashlib.sha256(url.encode()).digest()
    base64_hash = base64.urlsafe_b64encode(url_hash).decode('utf-8')
    return base64_hash[:length].rstrip('=')


def is_valid_url(url: str) -> bool:
    """Basic URL validation"""
    return url.startswith(('http://', 'https://'))


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class UrlInput(BaseModel):
    long_url: str
    custom_alias: Optional[str] = None
    expiry_date: Optional[str] = None
    use_base64: Optional[bool] = False


# ============================================================================
# ENDPOINTS
# ============================================================================

@url_manage.post("/create", response_model=dict)
async def create_url(
    data: UrlInput, 
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: DB = Depends(get_db)
):
    """Create a shortened URL"""
    
    logger.info(f"🔗 Creating URL for user: {current_user.get('email')} (ID: {current_user.get('id')})")
    
    # Validate URL
    if not is_valid_url(data.long_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format. Must start with http:// or https://"
        )
    
    if len(data.long_url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL too long. Maximum 2048 characters allowed"
        )
    
    # Check if URL already exists for this user
    existing_url = db.table("urls").where(
        user_id=current_user["id"],
        long_url=data.long_url
    ).first()
    
    if existing_url:
        base_url = str(request.base_url).rstrip('/')
        short_url = f"{base_url}/{existing_url['short_code']}"
        
        logger.info(f"♻️ Returning existing URL: {existing_url['short_code']}")
        
        return {
            "success": True,
            "message": "URL already exists",
            "data": {
                "id": existing_url["id"],
                "short_code": existing_url["short_code"],
                "long_url": existing_url["long_url"],
                "short_url": short_url,
                "clicks": existing_url["clicks"],
                "created_at": existing_url["created_at"],
                "expiry_date": existing_url.get("expiry_date")
            }
        }
    
    # Generate short code
    if data.custom_alias:
        short_code = data.custom_alias
        
        if not short_code.replace('-', '').replace('_', '').isalnum():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom alias can only contain letters, numbers, hyphens, and underscores"
            )
        
        if len(short_code) < 3 or len(short_code) > 50:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom alias must be between 3 and 50 characters"
            )
        
        if short_code.lower() in RESERVED_ROUTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"'{short_code}' is a reserved route"
            )
        
        existing = db.table("urls").where(short_code=short_code).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom alias already taken"
            )
            
    elif data.use_base64:
        short_code = generate_base64_short_code(data.long_url, length=8)
        existing = db.table("urls").where(short_code=short_code).first()
        
        if existing and existing["long_url"] != data.long_url:
            counter = 1
            while True:
                new_code = f"{short_code}{counter}"
                if not db.table("urls").where(short_code=new_code).first():
                    short_code = new_code
                    break
                counter += 1
    else:
        max_attempts = 10
        for attempt in range(max_attempts):
            short_code = generate_short_code()
            if not db.table("urls").where(short_code=short_code).first():
                break
            if attempt == max_attempts - 1:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate unique short code"
                )
    
    # Create URL record
    url_data = {
        "user_id": current_user["id"],
        "long_url": data.long_url,
        "short_code": short_code,
        "clicks": 0,
        "created_at": datetime.utcnow().isoformat(),
        "expiry_date": data.expiry_date
    }
    
    try:
        # Use db.insert() like your auth code
        url_id = db.insert("urls", url_data, return_id=True)
        
        base_url = str(request.base_url).rstrip('/')
        short_url = f"{base_url}/{short_code}"
        
        logger.info(f"✅ URL created: {short_code} -> {data.long_url[:50]}... (ID: {url_id})")
        
        return {
            "success": True,
            "message": "URL shortened successfully",
            "data": {
                "id": url_id,
                "short_code": short_code,
                "long_url": data.long_url,
                "short_url": short_url,
                "clicks": 0,
                "created_at": url_data["created_at"],
                "expiry_date": data.expiry_date
            }
        }
    
    except Exception as e:
        logger.error(f"❌ Error creating URL: {e}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create short URL"
        )


@url_manage.get("/urls", response_model=dict)
async def get_user_urls(
    current_user: dict = Depends(get_current_user),
    db: DB = Depends(get_db)
):
    """Get all URLs created by the current user"""
    
    logger.info(f"📋 Fetching URLs for user: {current_user.get('email')}")
    
    try:
        urls = db.table("urls").where(user_id=current_user["id"]).order_by("created_at", "desc").get()
        
        logger.info(f"✅ Found {len(urls)} URLs for user: {current_user.get('email')}")
        
        return {
            "success": True,
            "count": len(urls),
            "data": urls
        }
    
    except Exception as e:
        logger.error(f"❌ Error fetching URLs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch URLs"
        )


@url_manage.get("/urls/{short_code}/stats", response_model=dict)
async def get_url_stats(
    short_code: str,
    current_user: dict = Depends(get_current_user),
    db: DB = Depends(get_db)
):
    """Get statistics for a specific URL"""
    
    url = db.table("urls").where(
        short_code=short_code,
        user_id=current_user["id"]
    ).first()
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="URL not found"
        )
    
    return {
        "success": True,
        "data": url
    }


@url_manage.delete("/urls/{short_code}", response_model=dict)
async def delete_url(
    short_code: str,
    current_user: dict = Depends(get_current_user),
    db: DB = Depends(get_db)
):
    """Delete a shortened URL"""
    
    url = db.table("urls").where(
        short_code=short_code,
        user_id=current_user["id"]
    ).first()
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="URL not found"
        )
    
    try:
        # Use db.delete() like your auth code
        db.delete("urls", {"short_code": short_code, "user_id": current_user["id"]})
        
        logger.info(f"✅ URL deleted: {short_code} (user: {current_user.get('email')})")
        
        return {
            "success": True,
            "message": "URL deleted successfully"
        }
    
    except Exception as e:
        logger.error(f"❌ Error deleting URL: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete URL"
        )


# ============================================================================
# PUBLIC REDIRECT ENDPOINT (No authentication required)
# ============================================================================

@url_manage.get("/{short_code}")
async def redirect_url(short_code: str, db: DB = Depends(get_db)):
    """Redirect to the original URL and track click"""
    
    if short_code.lower() in RESERVED_ROUTES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="URL not found"
        )
    
    url = db.table("urls").where(short_code=short_code).first()
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="URL not found"
        )
    
    # Check if URL has expired
    if url.get("expiry_date"):
        try:
            expiry = datetime.fromisoformat(url["expiry_date"])
            if datetime.utcnow() > expiry:
                logger.warning(f"⏰ Expired URL accessed: {short_code}")
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="This URL has expired"
                )
        except (ValueError, TypeError) as e:
            logger.error(f"❌ Invalid expiry date format: {e}")
    
    # Increment click count
    try:
        new_clicks = url["clicks"] + 1
        # Use db.update() like your auth code
        db.update("urls", {"clicks": new_clicks}, {"short_code": short_code})
        logger.info(f"🔗 Redirect: {short_code} -> {url['long_url'][:50]}... (clicks: {new_clicks})")
    except Exception as e:
        logger.error(f"⚠️ Failed to update click count: {e}")
    
    # Redirect to original URL
    return RedirectResponse(url=url["long_url"], status_code=status.HTTP_307_TEMPORARY_REDIRECT)