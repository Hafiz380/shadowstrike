"""
Memory Persistence System
==========================
Inspired by ECC's memory-persistence hooks. Provides session-based
context management for security scans.

Features:
- Session start: load bounded prior context
- Session end: persist session summaries
- Pre-compact: save state before context compaction
- Cross-session knowledge accumulation
- Bounded context loading (prevent memory explosion)
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class SessionContext:
    """Represents a scan session's persistent context."""
    session_id: str
    target: str
    started_at: str
    ended_at: Optional[str] = None
    findings_summary: str = ""
    vuln_classes_tested: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)
    key_discoveries: list[str] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class MemoryEntry:
    """A single memory entry — something worth remembering."""
    id: str
    category: str  # finding, technique, pattern, lesson, tool
    content: str
    context: str
    relevance_score: float = 0.5
    times_recalled: int = 0
    created_at: Optional[str] = None
    tags: list[str] = field(default_factory=list)


class MemoryPersistence:
    """
    Manages persistent memory across scan sessions.

    Inspired by ECC's session-start/session-end hooks:
    - SessionStart: Load bounded prior context and project metadata
    - SessionEnd: Persist session-end summaries
    - PreCompact: Save state before compaction

    Memory is bounded to prevent explosion:
    - Max context chars on session start (configurable)
    - Older memories decay in relevance
    - Frequently recalled memories stay relevant
    """

    MAX_SESSION_CONTEXT_CHARS = 8000
    MAX_MEMORY_ENTRIES = 10000
    DECAY_FACTOR = 0.95

    def __init__(self, base_dir: str = None):
        if base_dir is None:
            base_dir = os.environ.get(
                "SHADOWSTRIKE_MEMORY",
                os.path.join(os.path.expanduser("~"), ".shadowstrike", "memory"),
            )
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "memory.db"
        self._init_db()

    def session_start(self, session_id: str, target: str) -> str:
        """
        Called at the start of a scan session.
        Loads bounded prior context for the target.
        Returns the context string to inject into the session.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            # Create new session
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO sessions (session_id, target, started_at)
                VALUES (?, ?, ?)""",
                (session_id, target, now),
            )
            conn.commit()

            # Load prior context for this target
            context = self._load_prior_context(conn, target)
            return context
        finally:
            conn.close()

    def session_end(
        self,
        session_id: str,
        findings_summary: str = "",
        vuln_classes: list[str] = None,
        tools_used: list[str] = None,
        files_analyzed: list[str] = None,
        key_discoveries: list[str] = None,
        total_findings: int = 0,
        critical_findings: int = 0,
        metadata: dict = None,
    ):
        """
        Called at the end of a scan session.
        Persists session summary and extracts memories.
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """UPDATE sessions SET ended_at=?, findings_summary=?,
                vuln_classes_tested=?, tools_used=?, files_analyzed=?,
                key_discoveries=?, total_findings=?, critical_findings=?, metadata=?
                WHERE session_id=?""",
                (
                    now,
                    findings_summary,
                    json.dumps(vuln_classes or []),
                    json.dumps(tools_used or []),
                    json.dumps(files_analyzed or []),
                    json.dumps(key_discoveries or []),
                    total_findings,
                    critical_findings,
                    json.dumps(metadata or {}),
                    session_id,
                ),
            )

            # Extract memories from session
            self._extract_memories(conn, session_id, findings_summary, key_discoveries or [])

            # Decay old memories
            self._decay_memories(conn)

            conn.commit()
        finally:
            conn.close()

    def save_memory(
        self,
        category: str,
        content: str,
        context: str = "",
        relevance_score: float = 0.5,
        tags: list[str] = None,
    ) -> str:
        """Save a memory entry."""
        import uuid

        memory_id = str(uuid.uuid4())[:8]
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """INSERT INTO memories (id, category, content, context,
                relevance_score, tags, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    memory_id,
                    category,
                    content,
                    context,
                    relevance_score,
                    json.dumps(tags or []),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
            return memory_id
        finally:
            conn.close()

    def recall(
        self,
        query: str,
        category: str = None,
        limit: int = 10,
        min_relevance: float = 0.3,
    ) -> list[MemoryEntry]:
        """
        Recall memories relevant to a query.
        Uses keyword matching and relevance scoring.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            # Simple keyword-based recall
            query_words = query.lower().split()
            conditions = ["relevance_score >= ?"]
            params: list[Any] = [min_relevance]

            if category:
                conditions.append("category = ?")
                params.append(category)

            # Build keyword search
            keyword_conditions = []
            for word in query_words[:5]:  # Limit to 5 keywords
                keyword_conditions.append(
                    "(LOWER(content) LIKE ? OR LOWER(context) LIKE ?)"
                )
                params.extend([f"%{word}%", f"%{word}%"])

            if keyword_conditions:
                conditions.append(f"({' OR '})".join(keyword_conditions))

            where_clause = " AND ".join(conditions)
            sql = f"""SELECT * FROM memories
                WHERE {where_clause}
                ORDER BY relevance_score DESC, times_recalled DESC
                LIMIT ?"""
            params.append(limit)

            memories = []
            for row in conn.execute(sql, params).fetchall():
                # Update recall count
                conn.execute(
                    "UPDATE memories SET times_recalled = times_recalled + 1 WHERE id = ?",
                    (row["id"],),
                )
                memories.append(
                    MemoryEntry(
                        id=row["id"],
                        category=row["category"],
                        content=row["content"],
                        context=row["context"],
                        relevance_score=row["relevance_score"],
                        times_recalled=row["times_recalled"],
                        created_at=row["created_at"],
                        tags=json.loads(row["tags"] or "[]"),
                    )
                )

            conn.commit()
            return memories
        finally:
            conn.close()

    def get_recent_sessions(self, limit: int = 10) -> list[SessionContext]:
        """Get recent scan sessions."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            sessions = []
            for row in conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall():
                sessions.append(
                    SessionContext(
                        session_id=row["session_id"],
                        target=row["target"],
                        started_at=row["started_at"],
                        ended_at=row["ended_at"],
                        findings_summary=row["findings_summary"] or "",
                        vuln_classes_tested=json.loads(row["vuln_classes_tested"] or "[]"),
                        tools_used=json.loads(row["tools_used"] or "[]"),
                        files_analyzed=json.loads(row["files_analyzed"] or "[]"),
                        key_discoveries=json.loads(row["key_discoveries"] or "[]"),
                        total_findings=row["total_findings"] or 0,
                        critical_findings=row["critical_findings"] or 0,
                        metadata=json.loads(row["metadata"] or "{}"),
                    )
                )
            return sessions
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Get memory statistics."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            memories = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            by_category = {}
            for row in conn.execute(
                "SELECT category, COUNT(*) FROM memories GROUP BY category"
            ).fetchall():
                by_category[row[0]] = row[1]

            return {
                "total_sessions": sessions,
                "total_memories": memories,
                "by_category": by_category,
            }
        finally:
            conn.close()

    def _load_prior_context(self, conn, target: str) -> str:
        """Load bounded prior context for a target."""
        context_parts = []

        # Load recent sessions for this target
        for row in conn.execute(
            """SELECT * FROM sessions WHERE target = ? AND ended_at IS NOT NULL
            ORDER BY ended_at DESC LIMIT 3""",
            (target,),
        ).fetchall():
            summary = row["findings_summary"] or ""
            if summary:
                context_parts.append(
                    f"[Previous scan {row['ended_at'][:10]}]: {summary[:500]}"
                )

        # Load relevant memories
        target_words = target.replace("/", " ").replace(".", " ").split()
        for word in target_words[:3]:
            for row in conn.execute(
                """SELECT * FROM memories
                WHERE LOWER(content) LIKE ? OR LOWER(context) LIKE ?
                ORDER BY relevance_score DESC LIMIT 5""",
                (f"%{word.lower()}%", f"%{word.lower()}%"),
            ).fetchall():
                context_parts.append(f"[Memory {row['category']}]: {row['content'][:300]}")

        # Bound the context
        full_context = "\n".join(context_parts)
        if len(full_context) > self.MAX_SESSION_CONTEXT_CHARS:
            full_context = full_context[: self.MAX_SESSION_CONTEXT_CHARS] + "\n... [truncated]"

        return full_context

    def _extract_memories(self, conn, session_id: str, summary: str, discoveries: list[str]):
        """Extract memories from a completed session."""
        if summary:
            conn.execute(
                """INSERT INTO memories (id, category, content, context, relevance_score, tags, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"sum-{session_id[:8]}",
                    "finding",
                    summary[:1000],
                    f"Session {session_id}",
                    0.6,
                    json.dumps(["session-summary"]),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        for i, discovery in enumerate(discoveries[:10]):
            conn.execute(
                """INSERT INTO memories (id, category, content, context, relevance_score, tags, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"disc-{session_id[:8]}-{i}",
                    "technique",
                    discovery[:500],
                    f"Session {session_id}",
                    0.7,
                    json.dumps(["discovery"]),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _decay_memories(self, conn):
        """Decay old memories to prevent unbounded growth."""
        conn.execute(
            """UPDATE memories SET relevance_score = relevance_score * ?
            WHERE times_recalled = 0 AND created_at < datetime('now', '-30 days')""",
            (self.DECAY_FACTOR,),
        )

        # Remove very low relevance memories
        total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        if total > self.MAX_MEMORY_ENTRIES:
            conn.execute(
                """DELETE FROM memories WHERE id IN (
                SELECT id FROM memories ORDER BY relevance_score ASC
                LIMIT ?
                )""",
                (total - self.MAX_MEMORY_ENTRIES,),
            )

    def _init_db(self):
        """Initialize the memory database."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT,
                ended_at TEXT,
                findings_summary TEXT,
                vuln_classes_tested TEXT,
                tools_used TEXT,
                files_analyzed TEXT,
                key_discoveries TEXT,
                total_findings INTEGER DEFAULT 0,
                critical_findings INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            )"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                content TEXT NOT NULL,
                context TEXT,
                relevance_score REAL DEFAULT 0.5,
                times_recalled INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                created_at TEXT
            )"""
            )

            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target)"""
            )
            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category)"""
            )
            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_memories_relevance ON memories(relevance_score)"""
            )

            conn.commit()
        finally:
            conn.close()
