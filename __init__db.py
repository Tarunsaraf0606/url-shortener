# from database import db_helper
# import logging

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)


# def init_db():
#     """Initialize database schema."""
    
#     logger.info("🔨 Initializing database schema...")
    
#     # Users table
#     db_helper.create_table("users", {
#         "id": "serial primary",
#         "email": "str unique not null",
#         "username": "str not null",  # ✅ FIXED: Added not null
#         "hashed_password": "str",     # ✅ FIXED: Removed space
#         "profile": "jsonb",
#         "created_at": "datetime default CURRENT_TIMESTAMP"
#     })
    
#     # Indexes
#     db_helper.create_index("idx_users_email", "users", "email", unique=True)
#     db_helper.create_index("idx_users_username", "users", "username")
    
#     logger.info("✅ Database initialized!")
    
#     # Show tables
#     tables = db_helper.list_tables()
#     logger.info(f"📊 Tables: {tables}")


# if __name__ == "__main__":
#     init_db()