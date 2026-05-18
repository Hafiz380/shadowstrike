"""
Workspace Manager — Resumable Scan State
=========================================
Inspired by Shannon's workspace system. Provides checkpointing
and resume capability for long-running security scans.

Each scan creates a workspace with SQLite-backed state tracking.
If a scan is interrupted, it can be resumed from the last checkpoint.
"""

import json
import os
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class AgentStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class VulnClass(str, Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "auth"
    AUTHZ = "authz"
    SSRF = "ssrf"


@dataclass
class AgentCheckpoint:
    agent_name: str
    status: AgentStatus
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings_count: int = 0
    exploits_count: int = 0
    error: Optional[str] = None
    deliverable_path: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class WorkspaceInfo:
    workspace_id: str
    name: str
    target: str
    created_at: str
    updated_at: str
    status: str
    vuln_classes: list
    exploit_mode: bool
    checkpoints: list
    config: dict = field(default_factory=dict)


class WorkspaceManager:
    """
    Manages scan workspaces with SQLite-backed checkpointing.

    Each workspace tracks:
    - Scan configuration
    - Agent execution state
    - Findings and deliverables
    - Resume points

    Inspired by Shannon's workspace system but implemented in Python
    with SQLite for portability.
    """

    def __init__(self, base_dir: str = None):
        if base_dir is None:
            base_dir = os.environ.get(
                "SHADOWSTRIKE_WORKSPACES",
                os.path.join(os.getcwd(), "shadowstrike_workspaces"),
            )
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create_workspace(
        self,
        target: str,
        name: str = None,
        vuln_classes: list[str] = None,
        exploit_mode: bool = True,
        config: dict = None,
    ) -> WorkspaceInfo:
        """Create a new scan workspace."""
        workspace_id = str(uuid.uuid4())[:8]
        if name is None:
            safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")[:30]
            name = f"{safe_target}_{workspace_id}"

        if vuln_classes is None:
            vuln_classes = [vc.value for vc in VulnClass]

        now = datetime.now(timezone.utc).isoformat()
        workspace_dir = self.base_dir / name
        workspace_dir.mkdir(parents=True, exist_ok=True)

        deliverables_dir = workspace_dir / "deliverables"
        deliverables_dir.mkdir(exist_ok=True)

        db_path = workspace_dir / "workspace.db"
        self._init_db(
            db_path, workspace_id, name, target, now, vuln_classes, exploit_mode, config or {}
        )

        return WorkspaceInfo(
            workspace_id=workspace_id,
            name=name,
            target=target,
            created_at=now,
            updated_at=now,
            status="active",
            vuln_classes=vuln_classes,
            exploit_mode=exploit_mode,
            checkpoints=[],
            config=config or {},
        )

    def get_workspace(self, name: str) -> Optional[WorkspaceInfo]:
        """Get workspace info by name."""
        workspace_dir = self.base_dir / name
        db_path = workspace_dir / "workspace.db"
        if not db_path.exists():
            return None

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT * FROM workspace LIMIT 1").fetchone()
            if not row:
                return None

            checkpoints = []
            for cp in conn.execute("SELECT * FROM agents ORDER BY rowid").fetchall():
                checkpoints.append(
                    AgentCheckpoint(
                        agent_name=cp["agent_name"],
                        status=AgentStatus(cp["status"]),
                        started_at=cp["started_at"],
                        completed_at=cp["completed_at"],
                        findings_count=cp["findings_count"],
                        exploits_count=cp["exploits_count"],
                        error=cp["error"],
                        deliverable_path=cp["deliverable_path"],
                        metadata=json.loads(cp["metadata"] or "{}"),
                    )
                )

            return WorkspaceInfo(
                workspace_id=row["workspace_id"],
                name=row["name"],
                target=row["target"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                status=row["status"],
                vuln_classes=json.loads(row["vuln_classes"]),
                exploit_mode=bool(row["exploit_mode"]),
                checkpoints=checkpoints,
                config=json.loads(row["config"] or "{}"),
            )
        finally:
            conn.close()

    def list_workspaces(self) -> list[WorkspaceInfo]:
        """List all workspaces."""
        workspaces = []
        for d in sorted(self.base_dir.iterdir()):
            if d.is_dir() and (d / "workspace.db").exists():
                ws = self.get_workspace(d.name)
                if ws:
                    workspaces.append(ws)
        return workspaces

    def update_agent_status(
        self,
        workspace_name: str,
        agent_name: str,
        status: AgentStatus,
        findings_count: int = 0,
        exploits_count: int = 0,
        error: str = None,
        deliverable_path: str = None,
        metadata: dict = None,
    ):
        """Update the status of an agent in the workspace."""
        workspace_dir = self.base_dir / workspace_name
        db_path = workspace_dir / "workspace.db"
        if not db_path.exists():
            raise ValueError(f"Workspace '{workspace_name}' not found")

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(db_path))
        try:
            if status == AgentStatus.IN_PROGRESS:
                conn.execute(
                    """UPDATE agents SET status=?, started_at=?, findings_count=?, exploits_count=?,
                      error=?, deliverable_path=?, metadata=? WHERE agent_name=?""",
                    (
                        status.value,
                        now,
                        findings_count,
                        exploits_count,
                        error,
                        deliverable_path,
                        json.dumps(metadata or {}),
                        agent_name,
                    ),
                )
            elif status in (AgentStatus.COMPLETED, AgentStatus.FAILED):
                conn.execute(
                    """UPDATE agents SET status=?, completed_at=?, findings_count=?, exploits_count=?,
                      error=?, deliverable_path=?, metadata=? WHERE agent_name=?""",
                    (
                        status.value,
                        now,
                        findings_count,
                        exploits_count,
                        error,
                        deliverable_path,
                        json.dumps(metadata or {}),
                        agent_name,
                    ),
                )
            else:
                conn.execute(
                    """UPDATE agents SET status=?, findings_count=?, exploits_count=?,
                      error=?, deliverable_path=?, metadata=? WHERE agent_name=?""",
                    (
                        status.value,
                        findings_count,
                        exploits_count,
                        error,
                        deliverable_path,
                        json.dumps(metadata or {}),
                        agent_name,
                    ),
                )

            conn.execute("UPDATE workspace SET updated_at=? WHERE name=?", (now, workspace_name))
            conn.commit()
        finally:
            conn.close()

    def get_pending_agents(self, workspace_name: str) -> list[str]:
        """Get list of agents that haven't completed yet (for resume)."""
        workspace_dir = self.base_dir / workspace_name
        db_path = workspace_dir / "workspace.db"
        if not db_path.exists():
            return []

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT agent_name FROM agents WHERE status IN ('pending', 'failed') ORDER BY rowid"
            ).fetchall()
            return [r["agent_name"] for r in rows]
        finally:
            conn.close()

    def get_completed_agents(self, workspace_name: str) -> list[str]:
        """Get list of completed agents."""
        workspace_dir = self.base_dir / workspace_name
        db_path = workspace_dir / "workspace.db"
        if not db_path.exists():
            return []

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT agent_name FROM agents WHERE status='completed' ORDER BY rowid"
            ).fetchall()
            return [r["agent_name"] for r in rows]
        finally:
            conn.close()

    def save_deliverable(self, workspace_name: str, filename: str, content: str):
        """Save a deliverable file to the workspace."""
        workspace_dir = self.base_dir / workspace_name
        deliverables_dir = workspace_dir / "deliverables"
        deliverables_dir.mkdir(exist_ok=True)
        (deliverables_dir / filename).write_text(content, encoding="utf-8")

    def load_deliverable(self, workspace_name: str, filename: str) -> Optional[str]:
        """Load a deliverable file from the workspace."""
        workspace_dir = self.base_dir / workspace_name
        path = workspace_dir / "deliverables" / filename
        if path.exists():
            return path.read_text(encoding="utf-8")
        return None

    def delete_workspace(self, name: str):
        """Delete a workspace and all its data."""
        import shutil

        workspace_dir = self.base_dir / name
        if workspace_dir.exists():
            shutil.rmtree(workspace_dir)

    def _init_db(
        self,
        db_path: Path,
        workspace_id: str,
        name: str,
        target: str,
        now: str,
        vuln_classes: list,
        exploit_mode: bool,
        config: dict,
    ):
        """Initialize the workspace database."""
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS workspace (
                workspace_id TEXT,
                name TEXT PRIMARY KEY,
                target TEXT,
                created_at TEXT,
                updated_at TEXT,
                status TEXT DEFAULT 'active',
                vuln_classes TEXT,
                exploit_mode INTEGER,
                config TEXT
            )"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS agents (
                agent_name TEXT PRIMARY KEY,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0,
                exploits_count INTEGER DEFAULT 0,
                error TEXT,
                deliverable_path TEXT,
                metadata TEXT DEFAULT '{}'
            )"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                agent_name TEXT,
                vuln_class TEXT,
                title TEXT,
                severity TEXT,
                confidence TEXT,
                description TEXT,
                file_path TEXT,
                line_number INTEGER,
                cwe_id TEXT,
                evidence TEXT,
                exploit_payload TEXT,
                exploited INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            )"""
            )

            conn.execute(
                """INSERT OR REPLACE INTO workspace
                (workspace_id, name, target, created_at, updated_at, status, vuln_classes, exploit_mode, config)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                (
                    workspace_id,
                    name,
                    target,
                    now,
                    now,
                    json.dumps(vuln_classes),
                    int(exploit_mode),
                    json.dumps(config),
                ),
            )

            # Create agent checkpoints based on Shannon's pipeline
            agents = ["pre-recon", "recon"]
            for vc in vuln_classes:
                agents.append(f"{vc}-vuln")
                if exploit_mode:
                    agents.append(f"{vc}-exploit")
            agents.append("report")

            for agent in agents:
                conn.execute(
                    """INSERT OR IGNORE INTO agents (agent_name, status) VALUES (?, 'pending')""",
                    (agent,),
                )

            conn.commit()
        finally:
            conn.close()
