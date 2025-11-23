"""
simple_secure.py - Dead Simple Security Wrapper for FastAPI

This is a simplified wrapper around secure_app.py that provides
the easiest possible API while maintaining full production quality.

Ultra Simple Usage:
    from simple_secure import protect
    from fastapi import FastAPI
    
    app = FastAPI()
    protect(app)  # That's it! Your app is now secure.

Intermediate Usage:
    protect(app, origins=["https://mysite.com"], rate_limit=100)

Advanced Usage:
    protect(
        app,
        origins=["https://mysite.com"],
        rate_limit=100,
        redis="redis://localhost:6379",
        https=True
    )
"""

from typing import List, Optional
from fastapi import FastAPI
from security.secure_app import secure_app


# ============================================================================
# Ultra Simple API
# ============================================================================

def protect(
    app: FastAPI,
    origins: Optional[List[str]] = None,
    rate_limit: int = 30,
    redis: Optional[str] = None,
    https: bool = False,
    debug: bool = False
) -> FastAPI:
    """
    Protect your FastAPI app with production-grade security.
    
    Just call protect(app) and you're done! 🛡️
    
    Args:
        app: Your FastAPI application
        origins: List of allowed frontend URLs (default: localhost)
                 Example: ["https://mysite.com", "https://app.mysite.com"]
        rate_limit: Max requests per minute per IP (default: 30)
        redis: Redis URL for distributed rate limiting (optional)
               Example: "redis://localhost:6379"
        https: Force HTTPS redirect (default: False, enable in production)
        debug: Show detailed security logs (default: False)
    
    Returns:
        Your protected FastAPI app
    
    What you get automatically:
        ✅ Rate limiting (stops API abuse)
        ✅ CORS protection (allows your frontend)
        ✅ Security headers (HSTS, CSP, etc.)
        ✅ Request tracing (debug with correlation IDs)
        ✅ Health checks (/health endpoint)
        ✅ IP extraction (works behind proxies)
    
    Examples:
        # Simplest - just protect it!
        protect(app)
        
        # With your frontend URL
        protect(app, origins=["https://mysite.com"])
        
        # Higher rate limit for production
        protect(app, origins=["https://mysite.com"], rate_limit=100)
        
        # Full production setup with Redis
        protect(
            app,
            origins=["https://mysite.com"],
            rate_limit=100,
            redis="redis://localhost:6379",
            https=True
        )
    """
    
    # Apply full security with sensible defaults
    return secure_app(
        app,
        # CORS - allow your frontend
        allowed_origins=origins or [
            "http://localhost:3000",   # React
            "http://localhost:5173",   # Vite
            "http://localhost:8080",   # Vue
        ],
        
        # Rate limiting - prevent abuse
        enable_rate_limit=True,
        rate_limit_calls=rate_limit,
        rate_limit_period=60,  # per minute
        redis_url=redis,
        
        # Security headers - protect against common attacks
        enable_secure_headers=True,
        
        # HTTPS - enable in production
        enable_https_redirect=https,
        
        # Health checks - monitor your app
        enable_health_endpoints=True,
        
        # Logging - see what's happening
        enable_monitoring=True,
        log_level="DEBUG" if debug else "INFO",
    )


# ============================================================================
# Even Simpler Presets
# ============================================================================

def protect_development(app: FastAPI) -> FastAPI:
    """
    Development mode - relaxed settings for local development.
    
    Usage:
        from simple_secure import protect_development
        protect_development(app)
    
    Features:
        - Rate limit: 100 requests/minute (high for testing)
        - No HTTPS redirect (works on localhost)
        - Debug logging enabled
        - Allows localhost origins
    """
    return protect(
        app,
        rate_limit=100,
        https=False,
        debug=True
    )


def protect_production(
    app: FastAPI,
    origins: List[str],
    redis_url: str
) -> FastAPI:
    """
    Production mode - strict security settings.
    
    Usage:
        from simple_secure import protect_production
        protect_production(
            app,
            origins=["https://mysite.com"],
            redis_url="redis://localhost:6379"
        )
    
    Features:
        - Rate limit: 30 requests/minute
        - HTTPS redirect enabled
        - Redis for distributed rate limiting
        - Info logging (not debug)
        - Only specified origins allowed
    """
    return protect(
        app,
        origins=origins,
        rate_limit=30,
        redis=redis_url,
        https=True,
        debug=False
    )


# ============================================================================
# Quick Testing Helper
# ============================================================================

def test_security(base_url: str = "http://localhost:8000") -> None:
    """
    Quick test to verify security is working.
    
    Usage:
        from simple_secure import test_security
        test_security()  # Test localhost
        test_security("https://api.mysite.com")  # Test production
    """
    try:
        import requests
    except ImportError:
        print("❌ Need requests library: pip install requests")
        return
    
    print(f"\n🔒 Testing security at {base_url}...")
    print("=" * 60)
    
    # Test 1: Health check
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        if r.status_code == 200:
            print("✅ Health check: OK")
        else:
            print(f"⚠️  Health check: {r.status_code}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
    
    # Test 2: Rate limiter
    try:
        r = requests.get(f"{base_url}/health/rate-limiter", timeout=5)
        if r.status_code == 200:
            data = r.json()
            backend = data.get("stats", {}).get("backend", "unknown")
            print(f"✅ Rate limiter: {backend} backend")
        else:
            print(f"⚠️  Rate limiter: {r.status_code}")
    except Exception as e:
        print(f"❌ Rate limiter check failed: {e}")
    
    # Test 3: Security headers
    try:
        r = requests.get(f"{base_url}/", timeout=5)
        headers = r.headers
        
        checks = {
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Frame Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
        }
        
        for header, name in checks.items():
            if header in headers:
                print(f"✅ {name}: Enabled")
            else:
                print(f"⚠️  {name}: Missing")
                
    except Exception as e:
        print(f"❌ Security headers check failed: {e}")
    
    print("=" * 60)
    print("✅ Security test complete!\n")


# ============================================================================
# Module Info
# ============================================================================

__all__ = [
    "protect",                    # Main function - use this!
    "protect_development",        # Dev preset
    "protect_production",         # Production preset
    "test_security",              # Quick test helper
]

__version__ = "1.0.0"
__doc__ = """
Simple Security for FastAPI - Production grade, zero configuration.

Quickstart:
    from simple_secure import protect
    from fastapi import FastAPI
    
    app = FastAPI()
    protect(app)
    
That's literally it. Your app now has:
    ✅ Rate limiting
    ✅ CORS protection
    ✅ Security headers
    ✅ Health checks
    ✅ Request tracing

For more control:
    protect(app, origins=["https://mysite.com"], rate_limit=100)
"""


# ============================================================================
# Usage Examples (for documentation)
# ============================================================================

if __name__ == "__main__":
    print(__doc__)
    print("\n" + "=" * 60)
    print("USAGE EXAMPLES")
    print("=" * 60)
    
    examples = """
    
1. ULTRA SIMPLE (just works!)
   ────────────────────────────────────────────────────────────
   from simple_secure import protect
   from fastapi import FastAPI
   
   app = FastAPI()
   protect(app)  # Done! 🎉


2. WITH YOUR FRONTEND URL
   ────────────────────────────────────────────────────────────
   protect(app, origins=["https://mysite.com"])


3. HIGHER RATE LIMIT
   ────────────────────────────────────────────────────────────
   protect(app, rate_limit=100)  # 100 requests per minute


4. FULL PRODUCTION SETUP
   ────────────────────────────────────────────────────────────
   protect(
       app,
       origins=["https://mysite.com", "https://app.mysite.com"],
       rate_limit=100,
       redis="redis://localhost:6379",
       https=True
   )


5. DEVELOPMENT PRESET
   ────────────────────────────────────────────────────────────
   from simple_secure import protect_development
   protect_development(app)


6. PRODUCTION PRESET
   ────────────────────────────────────────────────────────────
   from simple_secure import protect_production
   protect_production(
       app,
       origins=["https://mysite.com"],
       redis_url="redis://localhost:6379"
   )


7. TEST YOUR SECURITY
   ────────────────────────────────────────────────────────────
   from simple_secure import test_security
   test_security()  # Runs security checks


8. MULTIPLE FRONTENDS
   ────────────────────────────────────────────────────────────
   protect(app, origins=[
       "https://mysite.com",
       "https://www.mysite.com",
       "https://app.mysite.com",
       "https://admin.mysite.com"
   ])

"""
    
    print(examples)
    print("=" * 60)
    print("\nReady to use! Import from simple_secure.py")
    print("Full power of secure_app.py, dead simple API! 🚀\n")
