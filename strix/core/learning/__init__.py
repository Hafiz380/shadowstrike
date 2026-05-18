"""
Instinct-Based Learning System
================================
Inspired by ECC's Continuous Learning v2. Learns from scan sessions
by creating atomic "instincts" — small learned behaviors with confidence
scoring that evolve into reusable skills.

Each instinct is:
- Atomic: one trigger, one action
- Confidence-weighted: 0.3 (tentative) to 0.9 (near certain)
- Domain-tagged: code-style, testing, security, debugging, etc.
- Evidence-backed: tracks what observations created it
- Scope-aware: project-specific or global
"""

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class InstinctDomain(str, Enum):
    SECURITY = "security"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    RECON = "recon"
    CODE_ANALYSIS = "code-analysis"
    FALSE_POSITIVE = "false-positive"
    WORKFLOW = "workflow"
    DEBUGGING = "debugging"


class InstinctScope(str, Enum):
    PROJECT = "project"
    GLOBAL = "global"


@dataclass
class Instinct:
    id: str
    trigger: str
    action: str
    confidence: float
    domain: str
    evidence: list[str] = field(default_factory=list)
    scope: str = "global"
    project_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    times_applied: int = 0
    times_correct: int = 0
    evolved_to_skill: bool = False


@dataclass
class LearningObservation:
    """A single observation from a scan session that may become an instinct."""
    observation_type: str  # error_resolution, false_positive, user_correction, pattern
    context: str
    detail: str
    vuln_class: Optional[str] = None
    file_path: Optional[str] = None
    confidence_delta: float = 0.1


class InstinctEngine:
    """
    Learns from scan sessions by observing patterns and creating instincts.

    Inspired by ECC's continuous-learning-v2:
    - Observes scan sessions for patterns
    - Creates atomic instincts with confidence scoring
    - Evolves instincts into skills when confidence is high enough
    - Supports project-scoped and global instincts
    """

    def __init__(self, base_dir: str = None):
        if base_dir is None:
            base_dir = os.environ.get(
                "SHADOWSTRIKE_INSTINCTS",
                os.path.join(os.path.expanduser("~"), ".shadowstrike", "instincts"),
            )
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "instincts.db"
        self._init_db()

    def observe(self, observation: LearningObservation, project_id: str = None):
        """
        Record an observation from a scan session.
        Observations are accumulated and may trigger instinct creation.
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """INSERT INTO observations (id, type, context, detail, vuln_class, file_path,
                confidence_delta, project_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4())[:8],
                    observation.observation_type,
                    observation.context,
                    observation.detail,
                    observation.vuln_class,
                    observation.file_path,
                    observation.confidence_delta,
                    project_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

            # Check if we should create or update an instinct
            self._process_observation(conn, observation, project_id)
        finally:
            conn.close()

    def record_scan_result(
        self,
        scan_id: str,
        vuln_class: str,
        was_true_positive: bool,
        was_exploited: bool,
        context: str = "",
    ):
        """Record the outcome of a scan finding for learning."""
        obs_type = "true_positive" if was_true_positive else "false_positive"
        confidence_delta = 0.15 if was_exploited else 0.1 if was_true_positive else -0.2

        self.observe(
            LearningObservation(
                observation_type=obs_type,
                context=f"Scan {scan_id}: {vuln_class}",
                detail=context,
                vuln_class=vuln_class,
                confidence_delta=confidence_delta,
            )
        )

    def record_user_correction(self, original: str, corrected: str, vuln_class: str = None):
        """Record when a user corrects the tool's finding."""
        self.observe(
            LearningObservation(
                observation_type="user_correction",
                context=f"User corrected: {original}",
                detail=f"Corrected to: {corrected}",
                vuln_class=vuln_class,
                confidence_delta=0.2,
            )
        )

    def get_instincts(
        self,
        domain: str = None,
        scope: str = None,
        project_id: str = None,
        min_confidence: float = 0.0,
    ) -> list[Instinct]:
        """Get instincts matching the given filters."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            query = "SELECT * FROM instincts WHERE confidence >= ?"
            params: list[Any] = [min_confidence]

            if domain:
                query += " AND domain = ?"
                params.append(domain)
            if scope:
                query += " AND scope = ?"
                params.append(scope)
            if project_id:
                query += " AND (project_id = ? OR project_id IS NULL)"
                params.append(project_id)

            query += " ORDER BY confidence DESC"

            instincts = []
            for row in conn.execute(query, params).fetchall():
                instincts.append(
                    Instinct(
                        id=row["id"],
                        trigger=row["trigger"],
                        action=row["action"],
                        confidence=row["confidence"],
                        domain=row["domain"],
                        evidence=json.loads(row["evidence"] or "[]"),
                        scope=row["scope"],
                        project_id=row["project_id"],
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        times_applied=row["times_applied"],
                        times_correct=row["times_correct"],
                        evolved_to_skill=bool(row["evolved_to_skill"]),
                    )
                )
            return instincts
        finally:
            conn.close()

    def apply_instinct(self, instinct_id: str, was_correct: bool):
        """Record that an instinct was applied and whether it was correct."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            instinct = conn.execute(
                "SELECT * FROM instincts WHERE id = ?", (instinct_id,)
            ).fetchone()
            if not instinct:
                return

            times_applied = instinct["times_applied"] + 1
            times_correct = instinct["times_correct"] + (1 if was_correct else 0)

            # Adjust confidence based on application results
            accuracy = times_correct / times_applied if times_applied > 0 else 0.5
            base_confidence = instinct["confidence"]
            new_confidence = max(0.1, min(0.95, base_confidence + (0.05 if was_correct else -0.1)))

            conn.execute(
                """UPDATE instincts SET times_applied=?, times_correct=?,
                confidence=?, updated_at=? WHERE id=?""",
                (
                    times_applied,
                    times_correct,
                    new_confidence,
                    datetime.now(timezone.utc).isoformat(),
                    instinct_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def evolve_instincts(self, min_confidence: float = 0.8, min_applications: int = 5):
        """
        Evolve high-confidence instincts into reusable skills.
        Instincts with high confidence and enough applications become skills.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            candidates = conn.execute(
                """SELECT * FROM instincts
                WHERE confidence >= ? AND times_applied >= ?
                AND evolved_to_skill = 0""",
                (min_confidence, min_applications),
            ).fetchall()

            evolved = []
            for inst in candidates:
                accuracy = inst["times_correct"] / inst["times_applied"]
                if accuracy >= 0.8:
                    # Create skill from instinct
                    skill_content = self._instinct_to_skill(inst)
                    skill_path = self.base_dir / "evolved_skills" / f"{inst['id']}.md"
                    skill_path.parent.mkdir(parents=True, exist_ok=True)
                    skill_path.write_text(skill_content, encoding="utf-8")

                    conn.execute(
                        "UPDATE instincts SET evolved_to_skill = 1 WHERE id = ?",
                        (inst["id"],),
                    )
                    evolved.append(inst["id"])

            conn.commit()
            return evolved
        finally:
            conn.close()

    def export_instincts(self, output_path: str, scope: str = None):
        """Export instincts to a JSON file."""
        instincts = self.get_instincts(scope=scope)
        data = []
        for inst in instincts:
            data.append({
                "id": inst.id,
                "trigger": inst.trigger,
                "action": inst.action,
                "confidence": inst.confidence,
                "domain": inst.domain,
                "evidence": inst.evidence,
                "scope": inst.scope,
                "times_applied": inst.times_applied,
                "times_correct": inst.times_correct,
            })

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

    def import_instincts(self, input_path: str):
        """Import instincts from a JSON file."""
        with open(input_path) as f:
            data = json.load(f)

        conn = sqlite3.connect(str(self.db_path))
        try:
            for inst in data:
                conn.execute(
                    """INSERT OR REPLACE INTO instincts
                    (id, trigger, action, confidence, domain, evidence, scope,
                    project_id, created_at, updated_at, times_applied, times_correct, evolved_to_skill)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        inst["id"],
                        inst["trigger"],
                        inst["action"],
                        inst["confidence"],
                        inst["domain"],
                        json.dumps(inst.get("evidence", [])),
                        inst.get("scope", "global"),
                        inst.get("project_id"),
                        inst.get("created_at", datetime.now(timezone.utc).isoformat()),
                        inst.get("updated_at", datetime.now(timezone.utc).isoformat()),
                        inst.get("times_applied", 0),
                        inst.get("times_correct", 0),
                        inst.get("evolved_to_skill", False),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Get learning statistics."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            total = conn.execute("SELECT COUNT(*) FROM instincts").fetchone()[0]
            by_domain = {}
            for row in conn.execute(
                "SELECT domain, COUNT(*) as cnt FROM instincts GROUP BY domain"
            ).fetchall():
                by_domain[row[0]] = row[1]

            avg_confidence = conn.execute(
                "SELECT AVG(confidence) FROM instincts"
            ).fetchone()[0] or 0

            evolved = conn.execute(
                "SELECT COUNT(*) FROM instincts WHERE evolved_to_skill = 1"
            ).fetchone()[0]

            observations = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

            return {
                "total_instincts": total,
                "by_domain": by_domain,
                "avg_confidence": round(avg_confidence, 3),
                "evolved_to_skill": evolved,
                "total_observations": observations,
            }
        finally:
            conn.close()

    def _process_observation(self, conn, observation: LearningObservation, project_id: str):
        """Process an observation and potentially create/update an instinct."""
        # Look for existing instinct matching this pattern
        existing = conn.execute(
            """SELECT * FROM instincts
            WHERE domain = ? AND (project_id = ? OR project_id IS NULL)
            ORDER BY confidence DESC LIMIT 1""",
            (observation.observation_type, project_id),
        ).fetchone()

        if existing:
            # Update existing instinct
            new_confidence = max(
                0.1, min(0.95, existing["confidence"] + observation.confidence_delta)
            )
            evidence = json.loads(existing["evidence"] or "[]")
            evidence.append(observation.detail[:200])
            evidence = evidence[-10:]  # Keep last 10 evidence items

            conn.execute(
                """UPDATE instincts SET confidence=?, evidence=?, updated_at=? WHERE id=?""",
                (
                    new_confidence,
                    json.dumps(evidence),
                    datetime.now(timezone.utc).isoformat(),
                    existing["id"],
                ),
            )
        elif observation.confidence_delta > 0:
            # Create new instinct
            instinct_id = str(uuid.uuid4())[:8]
            conn.execute(
                """INSERT INTO instincts
                (id, trigger, action, confidence, domain, evidence, scope, project_id,
                created_at, updated_at, times_applied, times_correct, evolved_to_skill)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)""",
                (
                    instinct_id,
                    observation.context[:200],
                    observation.detail[:200],
                    max(0.3, min(0.7, 0.5 + observation.confidence_delta)),
                    observation.observation_type,
                    json.dumps([observation.detail[:200]]),
                    "project" if project_id else "global",
                    project_id,
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _instinct_to_skill(self, instinct) -> str:
        """Convert an instinct to a reusable skill markdown."""
        return f"""---
name: evolved-{instinct['id']}
description: "Auto-evolved from instinct: {instinct['trigger']}"
origin: shadowstrike-learned
confidence: {instinct['confidence']}
---

# Evolved Skill: {instinct['trigger']}

## Trigger
{instinct['trigger']}

## Action
{instinct['action']}

## Confidence
{instinct['confidence']} (applied {instinct['times_applied']} times, correct {instinct['times_correct']})

## Evidence
{chr(10).join(f'- {e}' for e in json.loads(instinct['evidence'] or '[]'))}

## Domain
{instinct['domain']}
"""

    def _init_db(self):
        """Initialize the instincts database."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS instincts (
                id TEXT PRIMARY KEY,
                trigger TEXT NOT NULL,
                action TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                domain TEXT,
                evidence TEXT DEFAULT '[]',
                scope TEXT DEFAULT 'global',
                project_id TEXT,
                created_at TEXT,
                updated_at TEXT,
                times_applied INTEGER DEFAULT 0,
                times_correct INTEGER DEFAULT 0,
                evolved_to_skill INTEGER DEFAULT 0
            )"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                context TEXT,
                detail TEXT,
                vuln_class TEXT,
                file_path TEXT,
                confidence_delta REAL DEFAULT 0.1,
                project_id TEXT,
                created_at TEXT
            )"""
            )

            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_instincts_domain ON instincts(domain)"""
            )
            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_instincts_confidence ON instincts(confidence)"""
            )
            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_observations_type ON observations(type)"""
            )

            conn.commit()
        finally:
            conn.close()
