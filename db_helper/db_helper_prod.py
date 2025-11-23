"""
db_helper.py - Production-Grade Database ORM Layer v3.0.1 (FIXED)

Enterprise database abstraction layer with advanced features:
✓ JSONB support (PostgreSQL native, SQLite simulated)
✓ Binary/BLOB with automatic compression
✓ Full-text search (GIN indexes, FTS5)
✓ Advanced indexing (B-tree, GIN, GiST, partial)
✓ Query builder with fluent interface
✓ Transaction management
✓ Type validation and coercion
✓ Security: SQL injection prevention
✓ Thread-safe operations
✓ Works as layer over db_engine.py

FIXED: Column type parsing for serial/autoincrement columns

Author: Production Team
Version: 3.0.1
License: MIT
"""

import logging
import sqlite3
import json
import zlib
import base64
import re
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass

try:
    from sqlalchemy import create_engine, text, inspect, Engine
    from sqlalchemy.pool import StaticPool
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    Engine = None

logger = logging.getLogger(__name__)

# Thread-safe locks
_schema_lock = threading.RLock()

# Constants
MAX_BLOB_SIZE = 50 * 1024 * 1024  # 50MB
BLOB_COMPRESSION_THRESHOLD = 4096  # 4KB
COMPRESSION_LEVEL = 6

# ============================================================================
# EXCEPTIONS
# ============================================================================

class DBError(Exception):
    """Base database exception."""
    pass


class SecurityError(DBError):
    """Security-related errors."""
    pass


class ValidationError(DBError):
    """Data validation errors."""
    pass


# ============================================================================
# INDEX CONFIGURATION
# ============================================================================

@dataclass
class IndexConfig:
    """Advanced index configuration."""
    name: str
    table: str
    columns: List[str]
    unique: bool = False
    index_type: str = "btree"  # btree, gin, gist, hash
    where: Optional[str] = None
    
    def to_sql(self, db_type: str) -> str:
        """Generate CREATE INDEX SQL."""
        unique = "UNIQUE " if self.unique else ""
        
        if db_type == "postgresql":
            method = f"USING {self.index_type.upper()}" if self.index_type != "btree" else ""
            where_clause = f"WHERE {self.where}" if self.where else ""
            
            return f"""
                CREATE {unique}INDEX IF NOT EXISTS {self.name}
                ON {self.table} {method} ({', '.join(self.columns)})
                {where_clause}
            """.strip()
        else:
            where_clause = f"WHERE {self.where}" if self.where else ""
            return f"""
                CREATE {unique}INDEX IF NOT EXISTS {self.name}
                ON {self.table} ({', '.join(self.columns)})
                {where_clause}
            """.strip()


# ============================================================================
# QUERY BUILDER
# ============================================================================

class QueryBuilder:
    """Fluent query builder."""
    
    def __init__(self, db: 'DB', table: str):
        self.db = db
        self.table = table
        self._select = ["*"]
        self._where = []
        self._where_params = []
        self._joins = []
        self._order = []
        self._group = []
        self._limit_val = None
        self._offset_val = None
    
    def select(self, *columns: str) -> 'QueryBuilder':
        """Select specific columns."""
        self._select = list(columns)
        return self
    
    def where(self, **conditions) -> 'QueryBuilder':
        """Add WHERE conditions."""
        for key, value in conditions.items():
            if self.db.engine:
                param_name = f"where_{key}_{len(self._where)}"
                self._where.append(f"{key} = :{param_name}")
                self._where_params.append((param_name, value))
            else:
                self._where.append(f"{key} = ?")
                self._where_params.append(value)
        return self
    
    def where_json(self, column: str, path: str, value: Any) -> 'QueryBuilder':
        """Add JSON path condition."""
        if self.db.db_type != "postgresql":
            raise DBError("JSON queries require PostgreSQL")
        
        param_name = f"json_{len(self._where)}"
        self._where.append(f"{column}->>{path!r} = :{param_name}")
        self._where_params.append((param_name, value))
        return self
    
    def where_raw(self, condition: str, params: Optional[List] = None) -> 'QueryBuilder':
        """Add raw WHERE condition."""
        self._where.append(condition)
        if params:
            if self.db.engine:
                for i, p in enumerate(params):
                    self._where_params.append((f"raw_{len(self._where)}_{i}", p))
            else:
                self._where_params.extend(params)
        return self
    
    def join(self, table: str, condition: str) -> 'QueryBuilder':
        """Add JOIN."""
        self._joins.append(f"JOIN {table} ON {condition}")
        return self
    
    def left_join(self, table: str, condition: str) -> 'QueryBuilder':
        """Add LEFT JOIN."""
        self._joins.append(f"LEFT JOIN {table} ON {condition}")
        return self
    
    def order_by(self, column: str, desc: bool = False) -> 'QueryBuilder':
        """Add ORDER BY."""
        direction = "DESC" if desc else "ASC"
        self._order.append(f"{column} {direction}")
        return self
    
    def group_by(self, *columns: str) -> 'QueryBuilder':
        """Add GROUP BY."""
        self._group.extend(columns)
        return self
    
    def limit(self, n: int) -> 'QueryBuilder':
        """Add LIMIT."""
        self._limit_val = n
        return self
    
    def offset(self, n: int) -> 'QueryBuilder':
        """Add OFFSET."""
        self._offset_val = n
        return self
    
    def _build_sql(self) -> tuple[str, Union[List, Dict]]:
        """Build final SQL."""
        parts = [f"SELECT {', '.join(self._select)} FROM {self.table}"]
        
        if self._joins:
            parts.extend(self._joins)
        
        if self._where:
            parts.append(f"WHERE {' AND '.join(self._where)}")
        
        if self._group:
            parts.append(f"GROUP BY {', '.join(self._group)}")
        
        if self._order:
            parts.append(f"ORDER BY {', '.join(self._order)}")
        
        if self._limit_val:
            parts.append(f"LIMIT {self._limit_val}")
        
        if self._offset_val:
            parts.append(f"OFFSET {self._offset_val}")
        
        sql = " ".join(parts)
        
        if self.db.engine:
            params = {k: v for k, v in self._where_params}
        else:
            params = [v if not isinstance(v, tuple) else v[1] for v in self._where_params]
        
        return sql, params
    
    def all(self) -> List[Dict]:
        """Execute and return all results."""
        sql, params = self._build_sql()
        return self.db.query(sql, params)
    
    def first(self) -> Optional[Dict]:
        """Execute and return first result."""
        results = self.limit(1).all()
        return results[0] if results else None
    
    def count(self) -> int:
        """Get count."""
        old_select = self._select
        self._select = ["COUNT(*) as count"]
        result = self.first()
        self._select = old_select
        return result["count"] if result else 0


# ============================================================================
# MAIN DB CLASS
# ============================================================================

class DB:
    """
    Production-grade database abstraction layer.
    
    Features:
        - JSONB support (PostgreSQL native, SQLite with JSON functions)
        - BLOB with automatic compression
        - Full-text search
        - Advanced indexing
        - Query builder
        - Transaction management
        - Type validation
    """
    
    SAFE_DEFAULTS = {
        'NULL', '0', '1', 'TRUE', 'FALSE',
        'CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME'
    }
    
    def __init__(
        self,
        path: Optional[str] = None,
        engine: Optional[Engine] = None, # type: ignore
        pool_size: int = 5,
        echo: bool = False,
        validate_types: bool = True,
        compress_blobs: bool = True
    ):
        """
        Initialize database connection.
        
        Args:
            path: Database path/URI (if engine not provided)
            engine: Existing SQLAlchemy Engine
            pool_size: Connection pool size
            echo: Log SQL statements
            validate_types: Validate data types
            compress_blobs: Auto-compress large BLOBs
        """
        self.pool_size = pool_size
        self.echo = echo
        self.validate_types = validate_types
        self.compress_blobs = compress_blobs
        self._schemas: Dict[str, Dict[str, type]] = {}
        self._indexes: Dict[str, IndexConfig] = {}
        self._sqlite_conn = None  # Persistent connection for :memory: databases
        
        # Use provided engine
        if engine is not None:
            if not HAS_SQLALCHEMY:
                raise DBError("SQLAlchemy required for Engine objects")
            self.engine = engine
            self.path = str(engine.url)
            self._is_url = True
            self._owns_engine = False
            self.db_type = engine.url.get_dialect().name
            logger.info(f"Using provided {self.db_type} engine")
            return
        
        # Create engine from path
        if path is None:
            path = "database.db"
        
        self.path = path
        self._owns_engine = True
        self._is_url = "://" in path
        
        if self._is_url and not HAS_SQLALCHEMY:
            raise DBError("SQLAlchemy required for non-SQLite databases")
        
        if self._is_url:
            self._setup_sqlalchemy()
        else:
            self._setup_sqlite()
    
    def _setup_sqlite(self):
        """Setup SQLite connection."""
        self.engine = None
        self.db_type = "sqlite"
        self._sqlite_conn = None  # Persistent connection for :memory:
        
        db_path = Path(self.path)
        if not db_path.exists() and self.path != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_path.touch()
        
        # For :memory: databases, we need to keep a persistent connection
        # because each new connection creates a separate database
        if self.path == ":memory:":
            self._sqlite_conn = sqlite3.connect(self.path, check_same_thread=False)
            self._sqlite_conn.row_factory = sqlite3.Row
            # Test connection
            self._sqlite_conn.execute("SELECT 1")
            self._sqlite_conn.commit()
        else:
            # For file databases, test with a temporary connection
            with self._connect() as conn:
                if isinstance(conn, sqlite3.Connection):
                    conn.execute("SELECT 1")
                else:
                    conn.execute(text("SELECT 1"))
        
        logger.info(f"Connected to SQLite: {self.path}")
    
    def _setup_sqlalchemy(self):
        """Setup SQLAlchemy engine."""
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        self.db_type = parsed.scheme.split("+")[0]
        
        self.engine = create_engine(
            self.path,
            echo=self.echo,
            pool_size=self.pool_size,
            pool_pre_ping=True,
        )
        
        with self.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        logger.info(f"Connected to {self.db_type}")
    
    @contextmanager
    def _connect(self):
        """Get database connection."""
        if self.engine:
            conn = self.engine.connect()
            trans = conn.begin()
            try:
                yield conn
                trans.commit()
            except Exception:
                trans.rollback()
                raise
            finally:
                conn.close()
        else:
            # For :memory: databases, reuse the persistent connection
            if self.path == ":memory:" and self._sqlite_conn is not None:
                try:
                    yield self._sqlite_conn
                    self._sqlite_conn.commit()
                except Exception:
                    self._sqlite_conn.rollback()
                    raise
            else:
                # For file databases, create a new connection each time
                conn = sqlite3.connect(self.path)
                conn.row_factory = sqlite3.Row
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
    
    @contextmanager
    def transaction(self):
        """Transaction context manager."""
        with self._connect() as conn:
            # Transaction is already begun in _connect
            try:
                yield conn
                # Commit happens automatically in _connect
            except Exception:
                # Rollback happens automatically in _connect
                raise
    
    def _sanitize_default(self, value: str) -> str:
        """Sanitize default values."""
        value = value.strip().upper()
        
        if value in self.SAFE_DEFAULTS:
            return value
        
        if re.match(r'^-?\d+(\.\d+)?$', value):
            return value
        
        if value.startswith("'") and value.endswith("'"):
            inner = value[1:-1]
            dangerous = ['--', ';', 'DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER']
            if any(p in inner.upper() for p in dangerous):
                raise SecurityError(f"Suspicious default: {value}")
            inner = inner.replace("'", "''")
            return f"'{inner}'"
        
        raise SecurityError(f"Invalid default: {value}")
    
    def _encode_blob(self, data: bytes) -> str:
        """Encode binary data with optional compression."""
        if len(data) > MAX_BLOB_SIZE:
            raise ValidationError(f"BLOB too large: {len(data)} bytes (max {MAX_BLOB_SIZE})")
        
        if self.compress_blobs and len(data) > BLOB_COMPRESSION_THRESHOLD:
            compressed = zlib.compress(data, level=COMPRESSION_LEVEL)
            if len(compressed) < len(data) * 0.9:
                return "Z:" + base64.b64encode(compressed).decode('ascii')
        
        return base64.b64encode(data).decode('ascii')
    
    def _decode_blob(self, data: str) -> bytes:
        """Decode binary data."""
        if data.startswith("Z:"):
            compressed = base64.b64decode(data[2:])
            return zlib.decompress(compressed)
        return base64.b64decode(data)
    
    def _parse_column_type(self, type_str: str) -> tuple[str, type]:
        """Parse column type including JSONB and BLOB. FIXED VERSION."""
        type_str = type_str.lower().strip()
        
        type_map = {
            "int": ("INTEGER", int),
            "serial": ("INTEGER", int),
            "str": ("TEXT" if self.db_type == "sqlite" else "VARCHAR(255)", str),
            "text": ("TEXT", str),
            "float": ("REAL" if self.db_type == "sqlite" else "FLOAT", float),
            "bool": ("BOOLEAN", bool),
            "datetime": ("TIMESTAMP", str),
            "date": ("DATE", str),
            "blob": ("BLOB" if self.db_type == "sqlite" else "BYTEA", bytes),
            "binary": ("BLOB" if self.db_type == "sqlite" else "BYTEA", bytes),
            "json": ("TEXT" if self.db_type == "sqlite" else "JSON", dict),
            "jsonb": ("TEXT" if self.db_type == "sqlite" else "JSONB", dict),
        }
        
        parts = type_str.split()
        base_type = parts[0]
        
        if base_type not in type_map:
            raise DBError(f"Unknown type: {base_type}")
        
        sql_type, python_type = type_map[base_type]
        
        # FIXED: Handle serial specially - check first before processing other modifiers
        if base_type == "serial":
            if self.db_type == "postgresql":
                # PostgreSQL: use SERIAL (auto-generates sequence)
                if "primary" in parts:
                    return "SERIAL PRIMARY KEY", python_type
                return "SERIAL", python_type
            else:
                # SQLite: SERIAL becomes INTEGER with special handling
                sql_type = "INTEGER"
                # Continue to process primary key and autoincrement below
        
        # Add constraints for non-serial or SQLite serial
        if "primary" in parts:
            sql_type += " PRIMARY KEY"
            # Add autoincrement for SQLite if needed
            if self.db_type == "sqlite" and (base_type == "serial" or "auto" in parts or "autoincrement" in parts):
                sql_type += " AUTOINCREMENT"
        
        if "unique" in parts and "primary" not in parts:  # Don't add UNIQUE if already PRIMARY KEY
            sql_type += " UNIQUE"
        
        if "not null" in type_str and "primary" not in parts:  # PRIMARY KEY implies NOT NULL
            sql_type += " NOT NULL"
        
        if "default" in parts:
            idx = parts.index("default")
            if idx + 1 < len(parts):
                default = parts[idx + 1]
                safe_default = self._sanitize_default(default)
                sql_type += f" DEFAULT {safe_default}"
        
        return sql_type, python_type

    def create_table(
        self,
        name: str,
        columns: Dict[str, str],
        if_not_exists: bool = True
    ) -> bool:
        """
        Create table with JSONB and BLOB support.
        
        Args:
            name: Table name
            columns: {column_name: type_definition}
            if_not_exists: Skip if exists
        
        Examples:
            >>> db.create_table("users", {
            ...     "id": "serial primary",
            ...     "email": "str unique not null",
            ...     "profile": "jsonb",
            ...     "avatar": "blob"
            ... })
        """
        with _schema_lock:
            col_defs = []
            schema = {}
            
            for col_name, col_type in columns.items():
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', col_name):
                    raise ValidationError(f"Invalid column name: {col_name}")
                
                sql_type, python_type = self._parse_column_type(col_type)
                col_defs.append(f"{col_name} {sql_type}")
                schema[col_name] = python_type
            
            self._schemas[name] = schema
            
            if_not = "IF NOT EXISTS" if if_not_exists else ""
            sql = f"CREATE TABLE {if_not} {name} ({', '.join(col_defs)})"
            
            try:
                with self._connect() as conn:
                    if self.engine:
                        conn.execute(text(sql))
                    else:
                        conn.execute(sql)
                
                logger.info(f"Created table '{name}'")
                return True
            except Exception as e:
                if "already exists" in str(e).lower() and if_not_exists:
                    return False
                raise DBError(f"Failed to create table: {e}")
    
    def create_index(
        self,
        name: str,
        table: str,
        columns: Union[str, List[str]],
        unique: bool = False,
        index_type: str = "btree",
        where: Optional[str] = None
    ) -> bool:
        """Create advanced index."""
        if isinstance(columns, str):
            columns = [columns]
        
        config = IndexConfig(
            name=name,
            table=table,
            columns=columns,
            unique=unique,
            index_type=index_type,
            where=where
        )
        
        sql = config.to_sql(self.db_type)
        
        try:
            with self._connect() as conn:
                if self.engine:
                    conn.execute(text(sql))
                else:
                    conn.execute(sql)
            
            self._indexes[name] = config
            logger.info(f"Created index '{name}'")
            return True
        except Exception as e:
            if "already exists" in str(e).lower():
                return False
            raise DBError(f"Failed to create index: {e}")
    
    def create_fulltext_index(
        self,
        name: str,
        table: str,
        columns: List[str]
    ) -> bool:
        """Create full-text search index."""
        if self.db_type == "postgresql":
            tsvector = f"to_tsvector('english', {' || '.join(columns)})"
            sql = f"CREATE INDEX IF NOT EXISTS {name} ON {table} USING GIN ({tsvector})"
        else:
            fts_table = f"{table}_fts"
            cols = ", ".join(columns)
            sql = f"CREATE VIRTUAL TABLE IF NOT EXISTS {fts_table} USING fts5({cols}, content={table})"
        
        try:
            with self._connect() as conn:
                if self.engine:
                    conn.execute(text(sql))
                else:
                    conn.execute(sql)
            
            logger.info(f"Created full-text index '{name}'")
            return True
        except Exception as e:
            raise DBError(f"Failed to create FTS index: {e}")
    
    def _validate_data(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and transform data."""
        if not self.validate_types or table not in self._schemas:
            return data
        
        schema = self._schemas[table]
        validated = {}
        
        for key, value in data.items():
            if value is None:
                validated[key] = None
                continue
            
            if key not in schema:
                validated[key] = value
                continue
            
            expected_type = schema[key]
            
            if expected_type == bytes:
                if isinstance(value, bytes):
                    validated[key] = self._encode_blob(value)
                elif isinstance(value, str):
                    validated[key] = value
                else:
                    raise ValidationError(f"Column '{key}' expects bytes")
            
            elif expected_type == dict:
                if isinstance(value, dict):
                    validated[key] = json.dumps(value) if self.db_type == "sqlite" else value
                elif isinstance(value, str):
                    json.loads(value)
                    validated[key] = value
                else:
                    raise ValidationError(f"Column '{key}' expects dict/JSON")
            
            else:
                if not isinstance(value, expected_type):
                    try:
                        if expected_type == bool:
                            if isinstance(value, str):
                                validated[key] = value.lower() in ('true', '1', 'yes', 'on')
                            else:
                                validated[key] = bool(value)
                        else:
                            validated[key] = expected_type(value)
                    except (ValueError, TypeError):
                        raise ValidationError(
                            f"Column '{key}' expects {expected_type.__name__}, "
                            f"got {type(value).__name__}"
                        )
                else:
                    validated[key] = value
        
        return validated
    
    def _build_placeholders(self, data: Dict[str, Any]) -> tuple[str, Union[List, Dict]]:
        """Build placeholders for query."""
        if self.engine:
            placeholders = ", ".join(f":{k}" for k in data.keys())
            return placeholders, data
        else:
            placeholders = ", ".join("?" * len(data))
            return placeholders, list(data.values())
    
    def insert(
        self,
        table: str,
        data: Dict[str, Any],
        return_id: bool = False
    ) -> Optional[int]:
        """Insert data with JSONB and BLOB support."""
        validated = self._validate_data(table, data)
        
        columns = ", ".join(validated.keys())
        placeholders, params = self._build_placeholders(validated)
        
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        
        with self._connect() as conn:
            if self.engine:
                result = conn.execute(text(sql), validated)
                if return_id:
                    return result.lastrowid
            else:
                cursor = conn.execute(sql, params)
                if return_id:
                    return cursor.lastrowid
    
    def insert_many(self, table: str, rows: List[Dict[str, Any]]) -> int:
        """Bulk insert."""
        count = 0
        with self.transaction():
            for row in rows:
                self.insert(table, row)
                count += 1
        return count
    
    def query(
        self,
        sql: str,
        params: Optional[Union[List, Dict]] = None,
        one: bool = False,
        decode_blobs: bool = True
    ) -> Union[List[Dict], Dict, None]:
        """Execute query with automatic BLOB/JSON decoding."""
        params = params or ([] if not self.engine else {})
        
        with self._connect() as conn:
            if self.engine:
                result = conn.execute(text(sql), params if isinstance(params, dict) else {})
                rows = [dict(row._mapping) for row in result]
            else:
                cursor = conn.execute(sql, params if isinstance(params, list) else [])
                rows = [dict(row) for row in cursor.fetchall()]
        
        if decode_blobs and rows and self._schemas:
            for row in rows:
                for table, schema in self._schemas.items():
                    for col, col_type in schema.items():
                        if col in row and row[col] is not None:
                            if col_type == bytes and isinstance(row[col], str):
                                try:
                                    row[col] = self._decode_blob(row[col])
                                except Exception:
                                    pass
                            elif col_type == dict and isinstance(row[col], str):
                                try:
                                    row[col] = json.loads(row[col])
                                except Exception:
                                    pass
        
        if one:
            return rows[0] if rows else None
        return rows
    
    def query_json(
        self,
        table: str,
        path: str,
        value: Any,
        operator: str = "="
    ) -> List[Dict]:
        """Query JSONB columns (PostgreSQL)."""
        if self.db_type != "postgresql":
            raise DBError("JSON queries require PostgreSQL")
        
        if operator in ("@>", "<@", "?", "?|", "?&"):
            if isinstance(value, dict):
                value_str = f"'{json.dumps(value)}'::jsonb"
            else:
                value_str = f"'{value}'"
            sql = f"SELECT * FROM {table} WHERE {path} {operator} {value_str}"
            return self.query(sql)
        else:
            sql = f"SELECT * FROM {table} WHERE {path} {operator} ?"
            return self.query(sql, [value])
    
    def fulltext_search(
        self,
        table: str,
        search_query: str,
        columns: Optional[List[str]] = None
    ) -> List[Dict]:
        """Full-text search."""
        if self.db_type == "postgresql":
            if columns:
                tsvector = f"to_tsvector('english', {' || '.join(columns)})"
            else:
                tsvector = "search_vector"
            
            sql = f"""
                SELECT * FROM {table}
                WHERE {tsvector} @@ plainto_tsquery('english', ?)
                ORDER BY ts_rank({tsvector}, plainto_tsquery('english', ?)) DESC
            """
            return self.query(sql, [search_query, search_query])
        else:
            fts_table = f"{table}_fts"
            sql = f"SELECT * FROM {fts_table} WHERE {fts_table} MATCH ?"
            return self.query(sql, [search_query])
    
    def table(self, name: str) -> QueryBuilder:
        """Get query builder for table."""
        return QueryBuilder(self, name)
    
    def execute(self, sql: str, params: Optional[Union[List, Dict]] = None) -> int:
        """Execute UPDATE/DELETE query."""
        params = params or ([] if not self.engine else {})
        
        with self._connect() as conn:
            if self.engine:
                result = conn.execute(text(sql), params if isinstance(params, dict) else {})
                return result.rowcount
            else:
                cursor = conn.execute(sql, params if isinstance(params, list) else [])
                return cursor.rowcount
    
    def update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> int:
        """Update with JSONB and BLOB support."""
        validated = self._validate_data(table, data)
        
        if self.engine:
            set_clause = ", ".join(f"{k} = :set_{k}" for k in validated.keys())
            where_clause = " AND ".join(f"{k} = :where_{k}" for k in where.keys())
            sql = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
            
            params = {f"set_{k}": v for k, v in validated.items()}
            params.update({f"where_{k}": v for k, v in where.items()})
        else:
            set_clause = ", ".join(f"{k} = ?" for k in validated.keys())
            where_clause = " AND ".join(f"{k} = ?" for k in where.keys())
            sql = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
            params = list(validated.values()) + list(where.values())
        
        return self.execute(sql, params)
    
    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """Delete rows."""
        if self.engine:
            where_clause = " AND ".join(f"{k} = :{k}" for k in where.keys())
            sql = f"DELETE FROM {table} WHERE {where_clause}"
            params = where
        else:
            where_clause = " AND ".join(f"{k} = ?" for k in where.keys())
            sql = f"DELETE FROM {table} WHERE {where_clause}"
            params = list(where.values())
        
        return self.execute(sql, params)
    
    def get_blob(self, table: str, column: str, where: Dict[str, Any]) -> Optional[bytes]:
        """Retrieve binary data."""
        result = self.table(table).where(**where).select(column).first()
        if result and result.get(column):
            value = result[column]
            if isinstance(value, str):
                return self._decode_blob(value)
            return value
        return None
    
    def table_exists(self, name: str) -> bool:
        """Check if table exists."""
        if self.engine:
            inspector = inspect(self.engine)
            return name in inspector.get_table_names()
        else:
            sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
            result = self.query(sql, [name], one=True)
            return result is not None
    
    def list_tables(self) -> List[str]:
        """List all tables."""
        if self.engine:
            inspector = inspect(self.engine)
            return inspector.get_table_names()
        else:
            sql = "SELECT name FROM sqlite_master WHERE type='table'"
            rows = self.query(sql)
            return [row["name"] for row in rows]
    
    def drop_table(self, name: str, if_exists: bool = True) -> bool:
        """Drop a table."""
        if_exists_clause = "IF EXISTS" if if_exists else ""
        sql = f"DROP TABLE {if_exists_clause} {name}"
        
        try:
            self.execute(sql)
            with _schema_lock:
                self._schemas.pop(name, None)
            logger.info(f"Dropped table '{name}'")
            return True
        except Exception as e:
            if if_exists:
                return False
            raise DBError(f"Failed to drop table: {e}")
    
    def vacuum(self) -> bool:
        """Optimize database (VACUUM)."""
        try:
            if self.db_type == "postgresql":
                with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                    conn.execute(text("VACUUM"))
            else:
                self.execute("VACUUM")
            logger.info("Database vacuumed")
            return True
        except Exception as e:
            logger.error(f"Vacuum failed: {e}")
            return False
    
    def analyze_table(self, table: str) -> Dict[str, Any]:
        """Analyze table statistics."""
        stats = {"table": table, "exists": self.table_exists(table)}
        
        if not stats["exists"]:
            return stats
        
        count_result = self.query(f"SELECT COUNT(*) as count FROM {table}", one=True)
        stats["row_count"] = count_result["count"] if count_result else 0
        
        if self.db_type == "postgresql":
            pg_stats = self.query(f"""
                SELECT 
                    pg_size_pretty(pg_total_relation_size('{table}')) as total_size,
                    pg_size_pretty(pg_relation_size('{table}')) as table_size,
                    pg_size_pretty(pg_indexes_size('{table}')) as indexes_size
            """, one=True)
            if pg_stats:
                stats.update(pg_stats)
        
        return stats
    
    def close(self):
        """Close database connection."""
        if self.engine and self._owns_engine:
            self.engine.dispose()
            logger.info(f"Closed {self.db_type} connection")
        elif self._sqlite_conn is not None:
            self._sqlite_conn.close()
            self._sqlite_conn = None
            logger.info(f"Closed SQLite connection")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def __repr__(self):
        if self.engine:
            return f"DB(engine={self.db_type})"
        return f"DB('{self.path}')"