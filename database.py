"""
database.py - Database connection and schema management
"""
from db_helper.db_engine_prod import create_engine_safe, shutdown_engine, get_health_report
from db_helper.db_helper_prod import DB
import os
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine_safe(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    echo=False
)

db = DB(engine=engine)

logger.info(f"✅ Database connected: {DATABASE_URL}")


# ============================================================================
# SCHEMA DEFINITION (Now Async!)
# ============================================================================

async def init_schema():
    """
    Initialize database schema (async version).
    Called on app startup.
    """
    logger.info("🔨 Initializing database schema...")
    
    # Run synchronous DB operations in thread pool
    import asyncio
    await asyncio.to_thread(_create_tables)
    
    logger.info("✅ Database schema initialized!")
    
    # Show summary
    tables = db.list_tables()
    logger.info(f"📊 Tables: {tables}")
    for table in tables:
        count = db.table(table).count()
        logger.info(f"   - {table}: {count} rows")


def _create_tables():
    """Internal function to create tables (synchronous)."""
    
    # ========================================================================
    # USERS TABLE
    # ========================================================================
    db.create_table("users", {
        "id": "serial primary",
        "email": "str unique not null",
        "username": "str not null",
        "hashed_password": "str",
        "profile": "jsonb",
        "created_at": "datetime default CURRENT_TIMESTAMP",
        "last_login": "datetime"
    }, if_not_exists=True)
    
    # Indexes for users
    db.create_index("idx_users_email", "users", "email", unique=True)
    db.create_index("idx_users_username", "users", "username")
    
    logger.info("✅ Users table created/verified")
    
    # ========================================================================
    # SESSIONS TABLE
    # ========================================================================
    db.create_table("sessions", {
        "id": "serial primary",
        "user_id": "str not null",
        "access_token": "str unique not null",
        "refresh_token": "str unique not null",
        "expires_at": "datetime not null",
        "created_at": "datetime default CURRENT_TIMESTAMP"
    }, if_not_exists=True)
    
    # Indexes for sessions
    db.create_index("idx_sessions_user", "sessions", "user_id")
    db.create_index("idx_sessions_access", "sessions", "access_token", unique=True)
    
    logger.info("✅ Sessions table created/verified")
    
    # ========================================================================
    # URLS TABLE - URL Shortener
    # ========================================================================
    db.create_table("urls", {
        "id": "serial primary",
        "user_id": "str not null",
        "long_url": "text not null",
        "short_code": "str unique not null",
        "clicks": "int default 0",
        "created_at": "datetime default CURRENT_TIMESTAMP",
        "updated_at": "datetime default CURRENT_TIMESTAMP",
        "expiry_date": "datetime",
        "is_active": "bool default true"
    }, if_not_exists=True)
    
    # Indexes for URLs
    db.create_index("idx_urls_short_code", "urls", "short_code", unique=True)
    db.create_index("idx_urls_user_id", "urls", "user_id")
    db.create_index("idx_urls_created_at", "urls", "created_at")
    db.create_index("idx_urls_is_active", "urls", "is_active")
    
    logger.info("✅ URLs table created/verified")
    
    # ========================================================================
    # URL CLICKS TABLE - Analytics (Optional)
    # ========================================================================
    db.create_table("url_clicks", {
        "id": "serial primary",
        "url_id": "str not null",
        "clicked_at": "datetime default CURRENT_TIMESTAMP",
        "ip_address": "str",
        "user_agent": "text",
        "referrer": "text",
        "country": "str",
        "city": "str",
        "device_type": "str",
        "browser": "str",
        "os": "str"
    }, if_not_exists=True)
    
    # Indexes for analytics
    db.create_index("idx_url_clicks_url_id", "url_clicks", "url_id")
    db.create_index("idx_url_clicks_clicked_at", "url_clicks", "clicked_at")
    
    logger.info("✅ URL clicks analytics table created/verified")
    
    # ========================================================================
    # FOREIGN KEY CONSTRAINTS (if supported by database)
    # ========================================================================
    try:
        # Note: These might not work with all databases
        # SQLite requires PRAGMA foreign_keys = ON
        if "sqlite" in DATABASE_URL.lower():
            db.execute_sql("PRAGMA foreign_keys = ON")
            logger.info("✅ SQLite foreign keys enabled")
    except Exception as e:
        logger.warning(f"⚠️ Could not set foreign key constraints: {e}")


# ============================================================================
# FASTAPI DEPENDENCY
# ============================================================================

def get_db() -> DB:
    """FastAPI dependency to get database instance."""
    return db


# ============================================================================
# LIFECYCLE MANAGEMENT (Now Async!)
# ============================================================================

async def close_db():
    """Close database connections (async version)."""
    logger.info("Closing database connections...")
    import asyncio
    await asyncio.to_thread(shutdown_engine, engine)
    logger.info("✅ Database closed")


def get_db_health():
    """Get database health status."""
    return get_health_report(engine)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def reset_database():
    """
    ⚠️ DANGER: Drop all tables and recreate schema.
    Only use in development!
    """
    logger.warning("⚠️ Resetting database - dropping all tables!")
    
    tables = db.list_tables()
    for table in tables:
        try:
            db.execute_sql(f"DROP TABLE IF EXISTS {table} CASCADE")
            logger.info(f"🗑️ Dropped table: {table}")
        except Exception as e:
            logger.error(f"❌ Failed to drop {table}: {e}")
    
    _create_tables()
    logger.info("✅ Database reset complete!")


def seed_test_data():
    """
    Add sample test data for development.
    """
    logger.info("🌱 Seeding test data...")
    
    try:
        # Check if test user exists
        test_user = db.table("users").where(email="test@example.com").first()
        
        if not test_user:
            # Create test user
            user_id = db.table("users").insert({
                "email": "test@example.com",
                "username": "testuser",
                "hashed_password": "hashed_password_here",
                "profile": {"role": "user"}
            })
            logger.info(f"✅ Created test user (ID: {user_id})")
            
            # Create sample URLs
            sample_urls = [
                {
                    "user_id": user_id,
                    "long_url": "https://www.google.com/search?q=python+fastapi",
                    "short_code": "pyfast",
                    "clicks": 0
                },
                {
                    "user_id": user_id,
                    "long_url": "https://github.com/tiangolo/fastapi",
                    "short_code": "github1",
                    "clicks": 5
                },
                {
                    "user_id": user_id,
                    "long_url": "https://docs.python.org/3/library/index.html",
                    "short_code": "pydocs",
                    "clicks": 12
                }
            ]
            
            for url_data in sample_urls:
                db.table("urls").insert(url_data)
            
            logger.info(f"✅ Created {len(sample_urls)} sample URLs")
        else:
            logger.info("ℹ️ Test data already exists, skipping...")
            
    except Exception as e:
        logger.error(f"❌ Failed to seed test data: {e}")


def get_database_stats():
    """
    Get statistics about database tables.
    """
    stats = {}
    tables = db.list_tables()
    
    for table in tables:
        try:
            count = db.table(table).count()
            stats[table] = count
        except Exception as e:
            stats[table] = f"Error: {e}"
    
    return stats


# ============================================================================
# OPTIONAL: Auto-initialize on import (sync version)
# ============================================================================

try:
    _create_tables()
    logger.info("✅ Schema auto-initialized on import")
except Exception as e:
    logger.warning(f"⚠️ Schema auto-init failed (will retry on startup): {e}")


# ============================================================================
# EXPORT FOR CONVENIENCE
# ============================================================================

__all__ = [
    'db',
    'engine',
    'get_db',
    'init_schema',
    'close_db',
    'get_db_health',
    'get_database_stats',
    'reset_database',
    'seed_test_data'
]
