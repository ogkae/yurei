from typing import Optional, Dict
import sqlite3
import json

class KVStore:
    """
    Simple key-value store.

    Features:
        - If `path` is provided, uses a SQLite file.
        - If no `path`, uses an in-memory dictionary.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """
        Initialize the key-value store.

        Args:
            path (Optional[str]): Optional path to SQLite file. If None, store is in-memory.
        """
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._init_table()
        else:
            self._data: Dict[str, str] = {}

    def _init_table(self) -> None:
        """Create the SQLite table if it doesn't exist."""
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def set(self, key: str, value: Dict) -> None:
        """
        Store a key-value pair.

        Args:
            key (str): The key to store.
            value (Dict): The value to store, JSON-serializable.
        """
        payload = json.dumps(value, separators=(",", ":"))
        if self.path:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, payload)
            )
            self._conn.commit()
        else:
            self._data[key] = payload

    def get(self, key: str) -> Optional[Dict]:
        """
        Retrieve a value by key.

        Args:
            key (str): The key to look up.

        Returns:
            Optional[Dict]: The stored value, or None if not found.
        """
        if self.path:
            cur = self._conn.cursor()
            cur.execute("SELECT value FROM kv WHERE key=?", (key,))
            row = cur.fetchone()
            if row is None:
                return None
            return json.loads(row[0])
        else:
            v = self._data.get(key)
            return json.loads(v) if v is not None else None

    def delete(self, key: str) -> None:
        """
        Delete a key-value pair.

        Args:
            key (str): The key to delete.
        """
        if self.path:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM kv WHERE key=?", (key,))
            self._conn.commit()
        else:
            self._data.pop(key, None)
