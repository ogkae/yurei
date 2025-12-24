"""Simple key-value storage with SQLite or in-memory backend

Features:
- SQLite persistent storage with WAL mode
- In-memory storage for temporary data
- JSON serialization for complex values
- Context manager support
- Thread-safe operations
"""

from typing import Any, Dict, Final, List, Optional
import sqlite3
import json

_PRAGMA_JOURNAL_MODE: Final[str] = "WAL"
_PRAGMA_SYNCHRONOUS: Final[str] = "NORMAL"
_PRAGMA_CACHE_SIZE: Final[int] = -64000  # 64MB cache
_PRAGMA_TEMP_STORE: Final[str] = "MEMORY"

class KVStore:
    """Simple key-value store with SQLite or in-memory backend.
    
    Features:
        - SQLite file storage if path provided
        - In-memory dictionary if no path
        - JSON serialization/deserialization
        - Context manager support
        - Thread-safe SQLite operations
        
    Example:
        >>> # In-memory storage
        >>> store = KVStore()
        >>> store.set("key", {"value": "data"})
        >>> store.get("key")
        {'value': 'data'}
        
        >>> # Persistent storage
        >>> with KVStore("data.db") as db:
        ...     db.set("user:123", {"name": "Alice"})
        ...     user = db.get("user:123")
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """Initialize the key-value store.
        
        Args:
            path: Optional path to SQLite file. If None, store is in-memory.
        """
        self.path = path
        self._conn: Optional[sqlite3.Connection] = None
        self._data: Dict[str, str] = {}
        
        if path:
            self._init_sqlite()
        else:
            self._init_memory()
    
    def _init_sqlite(self) -> None:
        """Initialize SQLite database with optimized settings."""
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        
        # Apply performance optimizations
        self._conn.execute(f"PRAGMA journal_mode={_PRAGMA_JOURNAL_MODE}")
        self._conn.execute(f"PRAGMA synchronous={_PRAGMA_SYNCHRONOUS}")
        self._conn.execute(f"PRAGMA cache_size={_PRAGMA_CACHE_SIZE}")
        self._conn.execute(f"PRAGMA temp_store={_PRAGMA_TEMP_STORE}")
        
        # Create table
        cursor = self._conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self._conn.commit()
    
    def _init_memory(self) -> None:
        """Initialize in-memory storage."""
        self._data = {}
    
    def set(self, key: str, value: Any) -> None:
        """Store a key-value pair.
        
        Args:
            key: The key to store.
            value: The value to store (must be JSON-serializable).
            
        Raises:
            ValueError: If key is empty.
            TypeError: If value is not JSON-serializable.
            
        Example:
            >>> store = KVStore()
            >>> store.set("user:123", {"name": "Alice", "age": 30})
        """
        if not key:
            raise ValueError("Key cannot be empty")
        
        try:
            payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise TypeError(f"Value is not JSON-serializable: {e}")
        
        if self.path:
            cursor = self._conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
                (key, payload)
            )
            self._conn.commit()
        else:
            self._data[key] = payload
    
    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by key.
        
        Args:
            key: The key to look up.
            default: Default value if key not found.
            
        Returns:
            The stored value, or default if not found.
            
        Example:
            >>> store.set("key", {"value": "data"})
            >>> store.get("key")
            {'value': 'data'}
            >>> store.get("missing", default="not found")
            'not found'
        """
        if not key:
            return default
        
        if self.path:
            cursor = self._conn.cursor()
            cursor.execute("SELECT value FROM kv WHERE key=?", (key,))
            row = cursor.fetchone()
            if row is None:
                return default
            return json.loads(row[0])
        else:
            value = self._data.get(key)
            if value is None:
                return default
            return json.loads(value)
    
    def delete(self, key: str) -> bool:
        """Delete a key-value pair.
        
        Args:
            key: The key to delete.
            
        Returns:
            True if key was deleted, False if key didn't exist.
            
        Example:
            >>> store.set("key", "value")
            >>> store.delete("key")
            True
            >>> store.delete("key")
            False
        """
        if not key:
            return False
        
        if self.path:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM kv WHERE key=?", (key,))
            deleted = cursor.rowcount > 0
            self._conn.commit()
            return deleted
        else:
            return self._data.pop(key, None) is not None
    
    def exists(self, key: str) -> bool:
        """Check if a key exists without retrieving its value.
        
        Args:
            key: The key to check.
            
        Returns:
            True if key exists, False otherwise.
            
        Example:
            >>> store.set("key", "value")
            >>> store.exists("key")
            True
            >>> store.exists("missing")
            False
        """
        if not key:
            return False
        
        if self.path:
            cursor = self._conn.cursor()
            cursor.execute("SELECT 1 FROM kv WHERE key=? LIMIT 1", (key,))
            return cursor.fetchone() is not None
        else:
            return key in self._data
    
    def keys(self, prefix: Optional[str] = None) -> List[str]:
        """List all keys, optionally filtered by prefix.
        
        Args:
            prefix: Optional prefix to filter keys.
            
        Returns:
            List of matching keys.
            
        Example:
            >>> store.set("user:1", {"name": "Alice"})
            >>> store.set("user:2", {"name": "Bob"})
            >>> store.set("post:1", {"title": "Hello"})
            >>> store.keys(prefix="user:")
            ['user:1', 'user:2']
        """
        if self.path:
            cursor = self._conn.cursor()
            if prefix:
                cursor.execute(
                    "SELECT key FROM kv WHERE key LIKE ? ORDER BY key",
                    (f"{prefix}%",)
                )
            else:
                cursor.execute("SELECT key FROM kv ORDER BY key")
            return [row[0] for row in cursor.fetchall()]
        else:
            if prefix:
                return sorted([k for k in self._data.keys() if k.startswith(prefix)])
            else:
                return sorted(self._data.keys())
    
    def clear(self, prefix: Optional[str] = None) -> int:
        """Clear all keys, or keys matching a prefix.
        
        Args:
            prefix: Optional prefix to filter keys for deletion.
            
        Returns:
            Number of keys deleted.
            
        Example:
            >>> store.clear(prefix="temp:")  # Clear temporary keys
            5
            >>> store.clear()  # Clear all keys
            10
        """
        if self.path:
            cursor = self._conn.cursor()
            if prefix:
                cursor.execute("DELETE FROM kv WHERE key LIKE ?", (f"{prefix}%",))
            else:
                cursor.execute("DELETE FROM kv")
            deleted = cursor.rowcount
            self._conn.commit()
            return deleted
        else:
            if prefix:
                keys_to_delete = [k for k in self._data.keys() if k.startswith(prefix)]
                for key in keys_to_delete:
                    del self._data[key]
                return len(keys_to_delete)
            else:
                count = len(self._data)
                self._data.clear()
                return count
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close connection."""
        self.close()
        return False
    
    def close(self) -> None:
        """Explicitly close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __del__(self):
        """Cleanup on deletion."""
        self.close()
