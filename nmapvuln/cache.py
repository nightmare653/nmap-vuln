"""On-disk response cache.

CVE lookups are slow and rate limited, and the same service banner turns up on
host after host, so every API response is cached by query key. Re-running the
tool against the same scans is then effectively free.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Optional

DEFAULT_TTL = 7 * 24 * 3600  # a week — long enough to be useful, short enough to stay current


class Cache:
    def __init__(self, path: str, ttl: int = DEFAULT_TTL, enabled: bool = True):
        self.path = path
        self.ttl = ttl
        self.enabled = enabled
        self._conn: Optional[sqlite3.Connection] = None
        if enabled:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            self._conn = sqlite3.connect(path)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS responses ("
                " key TEXT PRIMARY KEY,"
                " fetched_at INTEGER NOT NULL,"
                " payload TEXT NOT NULL)"
            )
            self._conn.commit()

    def get(self, key: str) -> Optional[Any]:
        if not self.enabled or self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT fetched_at, payload FROM responses WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        fetched_at, payload = row
        if self.ttl > 0 and time.time() - fetched_at > self.ttl:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def put(self, key: str, value: Any) -> None:
        if not self.enabled or self._conn is None:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO responses (key, fetched_at, payload) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(value)),
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
