from typing import Optional, Dict
import sqlite3
import json

class KVStore:
    """
    simple key-value store:
    - if path provided -> sqlite file
    - else -> in-memory dict
    """
    def __init__(self, path: Optional[str] = None):
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._init_table()
        else:
            self._data = {}

    def _init_table(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        self._conn.commit()

    def set(self, key: str, value: Dict) -> None:
        payload = json.dumps(value, separators=(',',':'))
        if self.path:
            cur = self._conn.cursor()
            cur.execute("INSERT OR REPLACE INTO kv (key,value) VALUES (?,?)", (key, payload))
            self._conn.commit()
        else:
            self._data[key] = payload

    def get(self, key: str) -> Optional[Dict]:
        if self.path:
            cur = self._conn.cursor()
            cur.execute("SELECT value FROM kv WHERE key=?", (key,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
        else:
            v = self._data.get(key)
            return json.loads(v) if v is not None else None

    def delete(self, key: str) -> None:
        if self.path:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM kv WHERE key=?", (key,))
            self._conn.commit()
        else:
            self._data.pop(key, None)