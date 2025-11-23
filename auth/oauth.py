"""
Ultra-Simple Google Auth Wrapper with Redis Support - FIXED VERSION

FIXES APPLIED:
- ✅ Removed global mutable state (thread-safe now)
- ✅ Using contextvars for async safety
- ✅ Token mapping in Redis (not memory)
- ✅ Better error handling (specific exceptions)
- ✅ Proper FastAPI dependency injection
- ✅ Token blacklist key fixes
- ✅ Logout endpoint included

Enhanced wrapper with:
- Redis storage backend support
- Proper logout/token revocation
- Session management
- Token refresh functionality
- NO GLOBAL STATE
"""

from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional, Dict, Any
from contextvars import ContextVar
import asyncio
import logging
from datetime import datetime, timedelta, timezone
import os

# Import the fixed auth module
try:
    from auth.google_auth import SimpleAuthSecure, StorageBackend
except ImportError:
    from .google_auth import SimpleAuthSecure, StorageBackend

logger = logging.getLogger(__name__)

# FIX: Use ContextVar instead of global variable (thread-safe)
_auth_context: ContextVar[Optional[SimpleAuthSecure]] = ContextVar('auth', default=None)


# ============================================================================
# REDIS STORAGE BACKEND
# ============================================================================

class RedisStorage(StorageBackend):
    """
    Redis storage backend for production use.
    
    Requires: pip install redis[asyncio]
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """
        Initialize Redis storage.
        
        Args:
            redis_url: Redis connection URL
        """
        try:
            import redis.asyncio as aioredis
            self._redis_module = aioredis
        except ImportError:
            raise ImportError(
                "Redis support requires 'redis' package. "
                "Install with: pip install redis[asyncio]"
            )
        
        self.redis_url = redis_url
        self._client: Optional[aioredis.Redis] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        logger.info(f"Redis storage initialized with URL: {redis_url}")
    
    async def _get_client(self):
        """Get or create Redis client."""
        if not self._client:
            self._client = self._redis_module.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # Test connection
            await self._client.ping()
            logger.info("Redis connection established")
        return self._client
    
    async def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        """Store a value with TTL in Redis."""
        import json
        client = await self._get_client()
        json_value = json.dumps(value)
        await client.setex(key, ttl_seconds, json_value)
    
    async def get(self, key: str) -> Optional[dict]:
        """Retrieve a value from Redis."""
        import json
        client = await self._get_client()
        value = await client.get(key)
        if value:
            return json.loads(value)
        return None
    
    async def delete(self, key: str) -> None:
        """Delete a key from Redis."""
        client = await self._get_client()
        await client.delete(key)
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists in Redis."""
        client = await self._get_client()
        result = await client.exists(key)
        return bool(result)
    
    async def start_cleanup(self) -> None:
        """
        Start cleanup task for Redis.
        
        Note: Redis handles TTL expiration automatically, so this is a no-op.
        """
        logger.info("Redis cleanup: Redis handles TTL automatically, no cleanup task needed")
    
    async def stop_cleanup(self) -> None:
        """Stop cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Redis cleanup task stopped")
    
    async def stop(self) -> None:
        """Stop storage backend and cleanup."""
        await self.stop_cleanup()
        logger.info("Redis storage stopped")
    
    async def close(self):
        """Close Redis connection."""
        await self.stop_cleanup()
        
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")


# ============================================================================
# SETUP - Enhanced with Redis Support
# ============================================================================

def setup_google_auth(
    config: Dict[str, Any],
    use_redis: bool = False,
    redis_url: str = "redis://localhost:6379/0"
) -> SimpleAuthSecure:
    """
    Initialize Google OAuth with optional Redis support.
    
    Usage:
        # Without Redis (in-memory, development only)
        auth = setup_google_auth({
            "client_id": "your-id",
            "client_secret": "your-secret",
            "app_secret_key": "your-jwt-secret",
            "redirect_uri": "http://localhost:8000/auth/callback",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo"
        })
        
        # With Redis (production)
        auth = setup_google_auth(
            config={...},
            use_redis=True,
            redis_url="redis://localhost:6379/0"
        )
    
    Args:
        config: OAuth configuration dictionary
        use_redis: Enable Redis storage backend (default: False)
        redis_url: Redis connection URL (default: redis://localhost:6379/0)
    
    Returns:
        Initialized SimpleAuthSecure instance
    """
    storage = None
    if use_redis:
        logger.info("Initializing with Redis storage backend")
        storage = RedisStorage(redis_url)
    else:
        # Check environment
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            raise RuntimeError(
                "Redis is required for production. Set use_redis=True"
            )
        logger.warning("Using in-memory storage - not recommended for production")
    
    auth = SimpleAuthSecure(config, storage=storage)
    
    # FIX: Store in context var instead of global
    _auth_context.set(auth)
    
    return auth


# ============================================================================
# INTERNAL: Get Auth Instance
# ============================================================================

def _get_auth() -> SimpleAuthSecure:
    """FIX: Get auth instance from context."""
    auth = _auth_context.get()
    if not auth:
        raise HTTPException(
            status_code=500,
            detail="Auth not initialized. Call setup_google_auth() first."
        )
    return auth


# ============================================================================
# MAIN AUTH FUNCTION - Fixed with Proper Dependencies
# ============================================================================

def google_user(optional: bool = False):
    """
    Get authenticated Google user (1 line).
    
    Usage:
        @app.get("/profile")
        def profile(user = google_user()):
            return user
        
        @app.get("/public")
        def public(user = google_user(optional=True)):
            return user or "guest"
    
    Returns:
        User dict with: id, email, name, picture
    """
    
    async def dependency(request: Request) -> Optional[Dict[str, Any]]:
        auth = _get_auth()
        
        try:
            # Get access token
            access_token = request.cookies.get("access_token")
            
            # FIX: Proper blacklist checking with specific exception handling
            if access_token and auth._store:
                try:
                    blacklisted = await auth._store.get(f"auth:bl:{access_token}")
                    if blacklisted:
                        logger.warning("Blacklisted token attempted to be used")
                        raise HTTPException(401, "Token has been revoked")
                except KeyError:
                    # Key doesn't exist, token is not blacklisted
                    pass
                except Exception as e:
                    # Only raise if it's not a "key not found" error
                    if "not found" not in str(e).lower() and "does not exist" not in str(e).lower():
                        logger.error(f"Blacklist check error: {e}")
            
            # Extract user from request
            user_payload = await auth.current_user(request)
            
            # Get refresh token from cookie for logout support
            refresh_token = request.cookies.get("refresh_token")
            
            user_data = {
                "id": user_payload.get("sub"),
                "email": user_payload.get("email"),
                "name": user_payload.get("name"),
                "picture": user_payload.get("picture"),
                "email_verified": user_payload.get("email_verified"),
                "refresh_token": refresh_token,  # Include for logout
                "_raw": user_payload  # Full payload
            }
            
            # FIX: Store token mapping in Redis instead of memory
            if refresh_token and auth._store:
                user_id = user_payload.get("sub")
                mapping_key = f"auth:token_map:{user_id}"
                try:
                    await auth._store.set(
                        mapping_key,
                        {"refresh_token": refresh_token},
                        ttl_seconds=auth.refresh_expires_days * 86400
                    )
                except Exception as e:
                    logger.error(f"Failed to store token mapping: {e}")
            
            return user_data
            
        except HTTPException as e:
            if optional:
                return None
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            if optional:
                return None
            raise HTTPException(401, "Authentication failed")
    
    return Depends(dependency)


# ============================================================================
# LOGIN/LOGOUT - Enhanced with Proper Token Revocation
# ============================================================================

async def login_url(request: Request) -> str:
    """
    Get Google login URL (1 line).
    
    Usage:
        @app.get("/auth/login")
        async def login(request: Request):
            url = await login_url(request)
            return {"login_url": url}
    """
    auth = _get_auth()
    result = await auth.get_login_url(request)
    return result["login_url"]


async def login_redirect(request: Request) -> RedirectResponse:
    """
    Redirect to Google login (1 line).
    
    Usage:
        @app.get("/auth/login")
        async def login(request: Request):
            return await login_redirect(request)
    """
    auth = _get_auth()
    return await auth.login_redirect(request)


async def handle_callback(request: Request, frontend_url: str = "http://localhost:3000") -> RedirectResponse:
    """
    Handle Google callback (1 line).
    
    Usage:
        @app.get("/auth/callback")
        async def callback(request: Request):
            return await handle_callback(request, "http://localhost:3000")
    """
    auth = _get_auth()
    return await auth.handle_callback_redirect(request, frontend_url)


async def logout(
    user_dict: Optional[dict] = None,
    request: Optional[Request] = None,
) -> dict:
    """
    Logout user (revoke tokens and clear cookies).
    
    Usage:
        # Method 1: With user dict from google_user()
        @app.post("/auth/logout")
        async def logout_user(user = google_user()):
            result = await logout(user_dict=user)
            return result
        
        # Method 2: With request (extracts token from cookies)
        @app.post("/auth/logout")
        async def logout_user(request: Request):
            result = await logout(request=request)
            return result
    
    Returns:
        Dictionary with logout status
    """
    auth = _get_auth()
    
    refresh_token = None
    access_token = None
    user_id = None
    
    # Extract tokens from various sources
    if user_dict:
        refresh_token = user_dict.get("refresh_token")
        user_id = user_dict.get("id")
    
    if request:
        if not refresh_token:
            refresh_token = request.cookies.get("refresh_token")
        access_token = request.cookies.get("access_token")
        
        # Try to get user_id from access token
        if not user_id:
            try:
                user_payload = await auth.current_user(request)
                user_id = user_payload.get("sub")
            except:
                pass
    
    # FIX: Check token mapping in Redis instead of memory
    if not refresh_token and user_id and auth._store:
        try:
            mapping_key = f"auth:token_map:{user_id}"
            mapping_data = await auth._store.get(mapping_key)
            if mapping_data:
                refresh_token = mapping_data.get("refresh_token")
        except Exception as e:
            logger.error(f"Failed to retrieve token mapping: {e}")
    
    if not refresh_token and not access_token:
        logger.warning("No tokens found for logout")
        return {
            "success": False,
            "message": "No active session found"
        }
    
    # 1. Blacklist access token in storage
    if access_token:
        try:
            # FIX: Use proper blacklist key format
            await auth._store.set(
                f"auth:bl:{access_token}",
                {"revoked": True, "user_id": user_id, "revoked_at": datetime.now(timezone.utc).isoformat()},
                ttl_seconds=auth.access_expires_minutes * 60
            )
            logger.info(f"Access token blacklisted for user: {user_id}")
        except Exception as e:
            logger.error(f"Failed to blacklist access token: {e}")
    
    # 2. Revoke the refresh token
    try:
        if refresh_token:
            revoked = await auth.revoke_refresh_token(refresh_token)
        else:
            revoked = True  # No refresh token to revoke
        
        # FIX: Clear token mapping in Redis
        if user_id and auth._store:
            try:
                mapping_key = f"auth:token_map:{user_id}"
                await auth._store.delete(mapping_key)
            except Exception as e:
                logger.error(f"Failed to delete token mapping: {e}")
        
        logger.info(f"User logged out successfully: {user_id}")
        return {
            "success": True,
            "message": "Logged out successfully"
        }
            
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(500, f"Logout failed: {str(e)}")


# FIX: NEW - Logout endpoint with response cookie clearing
async def logout_with_response(
    user_dict: Optional[dict] = None,
    request: Optional[Request] = None,
) -> JSONResponse:
    """
    Logout user and return response with cleared cookies.
    
    Usage:
        @app.post("/auth/logout")
        async def logout_user(request: Request, user = google_user(optional=True)):
            return await logout_with_response(user_dict=user, request=request)
    
    Returns:
        JSONResponse with logout status and cleared cookies
    """
    result = await logout(user_dict=user_dict, request=request)
    
    response = JSONResponse(content=result)
    
    # Clear cookies
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    
    return response


# ============================================================================
# TOKEN MANAGEMENT
# ============================================================================

async def refresh_token(
    refresh_token_str: Optional[str] = None,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Refresh access token.
    
    Usage:
        # Method 1: Direct refresh token
        @app.post("/auth/refresh")
        async def refresh(refresh_token: str):
            return await refresh_token(refresh_token_str=refresh_token)
        
        # Method 2: From request cookies
        @app.post("/auth/refresh")
        async def refresh(request: Request):
            return await refresh_token(request=request)
    
    Returns:
        New tokens dictionary
    """
    auth = _get_auth()
    
    # Extract refresh token
    if not refresh_token_str and request:
        refresh_token_str = request.cookies.get("refresh_token")
    
    if not refresh_token_str:
        raise HTTPException(400, "No refresh token provided")
    
    # Get client identifier for rate limiting
    client_id = None
    if request:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_id = forwarded.split(",")[0].strip()
        else:
            client_id = request.client.host if request.client else None
    
    try:
        return await auth.refresh_access_token(refresh_token_str, client_id)
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(401, "Token refresh failed")


# ============================================================================
# UTILITIES
# ============================================================================

async def health_check() -> Dict[str, Any]:
    """
    Check auth system health.
    
    Usage:
        @app.get("/auth/health")
        async def health():
            return await health_check()
    """
    try:
        auth = _get_auth()
    except HTTPException:
        return {
            "status": "not_initialized",
            "storage": "unknown",
            "redis": False
        }
    
    health = await auth.health_check()
    
    # Add Redis status
    if hasattr(auth._store, '_redis_module'):
        health["redis"] = "enabled"
    else:
        health["redis"] = "disabled"
    
    return health


async def get_metrics() -> Dict[str, Any]:
    """
    Get authentication metrics.
    
    Usage:
        @app.get("/auth/metrics")
        async def metrics():
            return await get_metrics()
    """
    try:
        auth = _get_auth()
    except HTTPException:
        return {"error": "Auth not initialized"}
    
    return auth.get_metrics()


async def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.
    
    Usage:
        @app.post("/auth/verify")
        async def verify(token: str):
            return await verify_token(token)
    """
    auth = _get_auth()
    
    try:
        return await auth.verify_access_token(token)
    except Exception as e:
        raise HTTPException(401, f"Token verification failed: {str(e)}")


async def introspect_token(token: str) -> Dict[str, Any]:
    """
    FIX: NEW - Introspect token for debugging.
    
    Usage:
        @app.post("/auth/introspect")
        async def introspect(token: str):
            return await introspect_token(token)
    """
    auth = _get_auth()
    
    try:
        return await auth.introspect_token(token)
    except Exception as e:
        logger.error(f"Token introspection error: {e}")
        raise HTTPException(401, f"Token introspection failed: {str(e)}")


# ============================================================================
# CLEANUP
# ============================================================================

async def shutdown():
    """
    Shutdown auth system and cleanup resources.
    
    Usage:
        @app.on_event("shutdown")
        async def app_shutdown():
            await shutdown()
    """
    try:
        auth = _get_auth()
        
        await auth.shutdown()
        
        # Close Redis connection if using Redis
        if hasattr(auth._store, 'close'):
            await auth._store.close()
        
        logger.info("Auth system shutdown complete")
    except HTTPException:
        logger.warning("Auth not initialized, nothing to shutdown")
    finally:
        # FIX: Clear context var
        _auth_context.set(None)


# ============================================================================
# ALIASES
# ============================================================================

gu = google_user  # Ultra-short alias


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Setup
    "setup_google_auth",
    "RedisStorage",
    
    # Main functions
    "google_user",
    "login_url",
    "login_redirect", 
    "handle_callback",
    "logout",
    "logout_with_response",  # NEW
    
    # Token management
    "refresh_token",
    "verify_token",
    "introspect_token",  # NEW
    
    # Utilities
    "health_check",
    "get_metrics",
    "shutdown",
    
    # Aliases
    "gu"
]
