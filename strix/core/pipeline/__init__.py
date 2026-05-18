"""
Parallel Vulnerability Pipeline
================================
Inspired by Shannon's architecture that runs 5 vulnerability classes
in parallel: Injection, XSS, Auth, Authz, SSRF.

Each class has a vulnerability analysis phase followed by an exploitation phase.
The pipeline supports:
- Parallel execution of independent vuln classes
- Sequential vuln→exploit within each class
- Checkpointing and resume via WorkspaceManager
- Static-dynamic correlation (feed static findings to exploitation)
"""

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from .workspace import AgentStatus, VulnClass, WorkspaceManager


class PipelinePhase(str, Enum):
    PRE_RECON = "pre-recon"
    RECON = "recon"
    VULN_ANALYSIS = "vuln"
    EXPLOITATION = "exploit"
    REPORT = "report"


@dataclass
class VulnFinding:
    id: str
    vuln_class: str
    title: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    evidence: Optional[str] = None
    exploit_payload: Optional[str] = None
    exploited: bool = False
    static_finding: bool = False
    metadata: dict = field(default_factory=dict)


@dataclass
class PipelineProgress:
    phase: str
    agent: str
    status: str
    message: str
    findings_count: int = 0
    exploits_count: int = 0
    elapsed_seconds: float = 0


@dataclass
class PipelineResult:
    workspace_name: str
    target: str
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    exploited_count: int = 0
    findings: list = field(default_factory=list)
    report: str = ""
    elapsed_seconds: float = 0
    vuln_class_results: dict = field(default_factory=dict)


ProgressCallback = Callable[[PipelineProgress], None]


class VulnerabilityPipeline:
    """
    Parallel vulnerability analysis and exploitation pipeline.

    Architecture (from Shannon):
    1. Pre-Reconnaissance — gather initial target info
    2. Reconnaissance — map attack surface
    3. Vulnerability Analysis — 5 classes in PARALLEL:
       - Injection (SQLi, Command, SSTI, Path Traversal, Deserialization)
       - XSS (Reflected, Stored, DOM, Blind)
       - Authentication (Bypass, JWT, Session, 2FA)
       - Authorization (IDOR, Privilege Escalation, Access Control)
       - SSRF (Blind, Full, Partial)
    4. Exploitation — exploit confirmed vulns (parallel per class)
    5. Reporting — generate consolidated report

    Each vuln→exploit pair runs independently, enabling maximum parallelism.
    """

    def __init__(
        self,
        workspace_manager: WorkspaceManager = None,
        llm_provider: str = None,
        http_client=None,
    ):
        self.workspace_manager = workspace_manager or WorkspaceManager()
        self.llm_provider = llm_provider
        self.http_client = http_client
        self._progress_callbacks: list[ProgressCallback] = []
        self._cancel_flag = False

    def on_progress(self, callback: ProgressCallback):
        """Register a progress callback."""
        self._progress_callbacks.append(callback)

    def cancel(self):
        """Request cancellation of the pipeline."""
        self._cancel_flag = True

    async def run(
        self,
        target: str,
        workspace_name: str = None,
        vuln_classes: list[str] = None,
        exploit_mode: bool = True,
        code_path: str = None,
        config: dict = None,
        resume: bool = True,
    ) -> PipelineResult:
        """
        Run the full vulnerability pipeline.

        Args:
            target: Target URL or domain
            workspace_name: Existing workspace name to resume, or None for new
            vuln_classes: List of vuln classes to test (default: all 5)
            exploit_mode: Whether to run exploitation phase
            code_path: Local source code path for white-box testing
            config: Additional configuration
            resume: Whether to resume from checkpoint if workspace exists
        """
        start_time = time.time()

        if vuln_classes is None:
            vuln_classes = [vc.value for vc in VulnClass]

        # Create or resume workspace
        if workspace_name and resume:
            ws = self.workspace_manager.get_workspace(workspace_name)
            if ws:
                self._report_progress(
                    PipelineProgress(
                        phase="init",
                        agent="workspace",
                        status="resuming",
                        message=f"Resuming workspace: {workspace_name}",
                    )
                )
            else:
                ws = self.workspace_manager.create_workspace(
                    target=target,
                    name=workspace_name,
                    vuln_classes=vuln_classes,
                    exploit_mode=exploit_mode,
                    config=config,
                )
        else:
            ws = self.workspace_manager.create_workspace(
                target=target,
                name=workspace_name,
                vuln_classes=vuln_classes,
                exploit_mode=exploit_mode,
                config=config,
            )

        workspace_name = ws.name

        # Get pending agents for resume
        pending = self.workspace_manager.get_pending_agents(workspace_name)
        completed = self.workspace_manager.get_completed_agents(workspace_name)

        result = PipelineResult(workspace_name=workspace_name, target=target)

        self._report_progress(
            PipelineProgress(
                phase="init",
                agent="pipeline",
                status="started",
                message=f"Pipeline started. {len(completed)} agents already completed, {len(pending)} pending.",
            )
        )

        # Phase 1 & 2: Recon (sequential)
        recon_result = None
        if "pre-recon" in pending or "recon" in pending:
            recon_result = await self._run_recon(target, workspace_name, code_path, pending)

        # Phase 3: Parallel vulnerability analysis
        vuln_tasks = []
        for vc in vuln_classes:
            agent_name = f"{vc}-vuln"
            if agent_name in pending:
                vuln_tasks.append(
                    self._run_vuln_analysis(vc, target, workspace_name, code_path, recon_result)
                )

        if vuln_tasks:
            vuln_results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
            for vc, vr in zip(vuln_classes, vuln_results):
                if isinstance(vr, Exception):
                    self._report_progress(
                        PipelineProgress(
                            phase="vuln",
                            agent=f"{vc}-vuln",
                            status="failed",
                            message=f"Error: {vr}",
                        )
                    )
                elif vr:
                    result.vuln_class_results[vc] = vr
                    result.findings.extend(vr if isinstance(vr, list) else [vr])

        # Phase 4: Parallel exploitation (if enabled)
        if exploit_mode:
            exploit_tasks = []
            for vc in vuln_classes:
                agent_name = f"{vc}-exploit"
                if agent_name in pending:
                    vc_findings = result.vuln_class_results.get(vc, [])
                    if vc_findings:
                        exploit_tasks.append(
                            self._run_exploitation(vc, target, workspace_name, vc_findings)
                        )

            if exploit_tasks:
                exploit_results = await asyncio.gather(*exploit_tasks, return_exceptions=True)
                for er in exploit_results:
                    if isinstance(er, list):
                        for f in er:
                            if isinstance(f, VulnFinding) and f.exploited:
                                result.exploited_count += 1

        # Phase 5: Report
        if "report" in pending:
            result.report = await self._generate_report(workspace_name, result)

        # Calculate stats
        result.total_findings = len(result.findings)
        result.critical_findings = sum(1 for f in result.findings if f.severity == "critical")
        result.high_findings = sum(1 for f in result.findings if f.severity == "high")
        result.elapsed_seconds = time.time() - start_time

        self._report_progress(
            PipelineProgress(
                phase="complete",
                agent="pipeline",
                status="completed",
                message=f"Pipeline complete. {result.total_findings} findings, {result.exploited_count} exploited.",
                findings_count=result.total_findings,
                exploits_count=result.exploited_count,
                elapsed_seconds=result.elapsed_seconds,
            )
        )

        return result

    async def _run_recon(
        self, target: str, workspace_name: str, code_path: str, pending: list
    ) -> dict:
        """Run reconnaissance phase."""
        self.workspace_manager.update_agent_status(
            workspace_name, "pre-recon", AgentStatus.IN_PROGRESS
        )
        self._report_progress(
            PipelineProgress(
                phase="recon",
                agent="pre-recon",
                status="running",
                message=f"Starting reconnaissance on {target}",
            )
        )

        recon_data = {
            "target": target,
            "code_path": code_path,
            "endpoints": [],
            "technologies": [],
            "input_vectors": [],
            "auth_mechanisms": [],
            "api_endpoints": [],
        }

        try:
            # Use existing recon capabilities
            from strix.agents.advanced.recon_agent import ReconAgent

            async with self._get_http_client() as client:
                agent = ReconAgent(http_client=client)
                result = await agent.recon(target, "standard")

                recon_data["subdomains"] = result.subdomains
                recon_data["technologies"] = result.technologies
                recon_data["endpoints"] = result.endpoints
                recon_data["js_files"] = result.js_files
                recon_data["api_endpoints"] = result.api_endpoints

            self.workspace_manager.update_agent_status(
                workspace_name,
                "pre-recon",
                AgentStatus.COMPLETED,
                metadata=recon_data,
            )

            if "recon" in pending:
                self.workspace_manager.update_agent_status(
                    workspace_name, "recon", AgentStatus.COMPLETED, metadata=recon_data
                )

            self.workspace_manager.save_deliverable(
                workspace_name,
                "recon_deliverable.md",
                self._format_recon_deliverable(recon_data),
            )

            self._report_progress(
                PipelineProgress(
                    phase="recon",
                    agent="recon",
                    status="completed",
                    message=f"Recon complete. {len(recon_data.get('endpoints', []))} endpoints found.",
                )
            )

        except Exception as e:
            self.workspace_manager.update_agent_status(
                workspace_name, "pre-recon", AgentStatus.FAILED, error=str(e)
            )
            self._report_progress(
                PipelineProgress(
                    phase="recon",
                    agent="pre-recon",
                    status="failed",
                    message=f"Recon failed: {e}",
                )
            )

        return recon_data

    async def _run_vuln_analysis(
        self,
        vuln_class: str,
        target: str,
        workspace_name: str,
        code_path: str,
        recon_data: dict,
    ) -> list[VulnFinding]:
        """Run vulnerability analysis for a specific class."""
        agent_name = f"{vuln_class}-vuln"
        self.workspace_manager.update_agent_status(
            workspace_name, agent_name, AgentStatus.IN_PROGRESS
        )
        self._report_progress(
            PipelineProgress(
                phase="vuln",
                agent=agent_name,
                status="running",
                message=f"Analyzing {vuln_class} vulnerabilities...",
            )
        )

        findings = []
        try:
            # Load recon deliverable for context
            recon_context = self.workspace_manager.load_deliverable(
                workspace_name, "recon_deliverable.md"
            )

            # Run class-specific analysis
            if code_path:
                findings = await self._static_vuln_analysis(
                    vuln_class, code_path, recon_context
                )

            # Dynamic analysis
            dynamic_findings = await self._dynamic_vuln_analysis(
                vuln_class, target, recon_context
            )
            findings.extend(dynamic_findings)

            # Save deliverable
            deliverable = self._format_vuln_deliverable(vuln_class, findings)
            self.workspace_manager.save_deliverable(
                workspace_name, f"{vuln_class}_analysis_deliverable.md", deliverable
            )

            self.workspace_manager.update_agent_status(
                workspace_name,
                agent_name,
                AgentStatus.COMPLETED,
                findings_count=len(findings),
            )

            self._report_progress(
                PipelineProgress(
                    phase="vuln",
                    agent=agent_name,
                    status="completed",
                    message=f"Found {len(findings)} {vuln_class} vulnerabilities.",
                    findings_count=len(findings),
                )
            )

        except Exception as e:
            self.workspace_manager.update_agent_status(
                workspace_name, agent_name, AgentStatus.FAILED, error=str(e)
            )
            self._report_progress(
                PipelineProgress(
                    phase="vuln",
                    agent=agent_name,
                    status="failed",
                    message=f"Error: {e}",
                )
            )

        return findings

    async def _run_exploitation(
        self,
        vuln_class: str,
        target: str,
        workspace_name: str,
        findings: list[VulnFinding],
    ) -> list[VulnFinding]:
        """Run exploitation for confirmed vulnerabilities."""
        agent_name = f"{vuln_class}-exploit"
        self.workspace_manager.update_agent_status(
            workspace_name, agent_name, AgentStatus.IN_PROGRESS
        )
        self._report_progress(
            PipelineProgress(
                phase="exploit",
                agent=agent_name,
                status="running",
                message=f"Exploiting {len(findings)} {vuln_class} vulnerabilities...",
            )
        )

        exploited = []
        try:
            for finding in findings:
                if self._cancel_flag:
                    break

                result = await self._exploit_single(vuln_class, target, finding)
                if result and result.exploited:
                    exploited.append(result)

            self.workspace_manager.update_agent_status(
                workspace_name,
                agent_name,
                AgentStatus.COMPLETED,
                exploits_count=len(exploited),
            )

            self._report_progress(
                PipelineProgress(
                    phase="exploit",
                    agent=agent_name,
                    status="completed",
                    message=f"Exploited {len(exploited)}/{len(findings)} {vuln_class} vulnerabilities.",
                    exploits_count=len(exploited),
                )
            )

        except Exception as e:
            self.workspace_manager.update_agent_status(
                workspace_name, agent_name, AgentStatus.FAILED, error=str(e)
            )

        return exploited

    async def _static_vuln_analysis(
        self, vuln_class: str, code_path: str, recon_context: str
    ) -> list[VulnFinding]:
        """Run static analysis for a vulnerability class."""
        try:
            from strix.core.static_analyzer import StaticAnalysisEngine

            engine = StaticAnalysisEngine()
            if not engine.is_available():
                return []

            raw_findings = engine.analyze_project(code_path)
            findings = []
            for f in raw_findings:
                if self._matches_vuln_class(f, vuln_class):
                    findings.append(
                        VulnFinding(
                            id=f.id,
                            vuln_class=vuln_class,
                            title=f.title,
                            severity=f.severity.value,
                            confidence=f.confidence.value,
                            description=f.description,
                            file_path=f.location.file_path if f.location else None,
                            line_number=f.location.line_start if f.location else None,
                            cwe_id=f.cwe_id,
                            static_finding=True,
                        )
                    )
            return findings
        except Exception:
            return []

    async def _dynamic_vuln_analysis(
        self, vuln_class: str, target: str, recon_context: str
    ) -> list[VulnFinding]:
        """Run dynamic vulnerability analysis using LLM-guided testing."""
        # Placeholder for LLM-guided dynamic analysis
        # In full implementation, this would use Shannon-style prompts
        return []

    async def _exploit_single(
        self, vuln_class: str, target: str, finding: VulnFinding
    ) -> Optional[VulnFinding]:
        """Attempt to exploit a single vulnerability."""
        try:
            from strix.agents.advanced.exploit_agent import ExploitAgent

            async with self._get_http_client() as client:
                agent = ExploitAgent(http_client=client)
                result = await agent.exploit(target, finding)
                if result and result.get("exploited"):
                    finding.exploited = True
                    finding.exploit_payload = result.get("payload")
                    finding.evidence = result.get("evidence")
                    return finding
        except Exception:
            pass
        return None

    async def _generate_report(self, workspace_name: str, result: PipelineResult) -> str:
        """Generate a consolidated security report."""
        self.workspace_manager.update_agent_status(
            workspace_name, "report", AgentStatus.IN_PROGRESS
        )

        report_lines = [
            "# ShadowStrike Security Report",
            "",
            f"**Target:** {result.target}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Duration:** {result.elapsed_seconds:.1f}s",
            "",
            "## Executive Summary",
            "",
            f"- **Total Findings:** {result.total_findings}",
            f"- **Critical:** {result.critical_findings}",
            f"- **High:** {result.high_findings}",
            f"- **Exploited:** {result.exploited_count}",
            "",
            "## Findings by Category",
            "",
        ]

        for vc, findings in result.vuln_class_results.items():
            report_lines.append(f"### {vc.upper()}")
            report_lines.append("")
            if isinstance(findings, list):
                for f in findings:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                        f.severity, "⚪"
                    )
                    report_lines.append(f"- {emoji} **{f.title}** ({f.severity})")
                    if f.file_path:
                        report_lines.append(f"  - Location: `{f.file_path}:{f.line_number}`")
                    if f.cwe_id:
                        report_lines.append(f"  - CWE: {f.cwe_id}")
                    if f.exploited:
                        report_lines.append(f"  - ✅ **EXPLOITED** — PoC available")
                    report_lines.append("")

        report = "\n".join(report_lines)

        self.workspace_manager.save_deliverable(workspace_name, "final_report.md", report)
        self.workspace_manager.update_agent_status(
            workspace_name, "report", AgentStatus.COMPLETED
        )

        return report

    def _matches_vuln_class(self, finding, vuln_class: str) -> bool:
        """Check if a static finding matches a vulnerability class."""
        class_cwe_map = {
            "injection": ["CWE-89", "CWE-78", "CWE-1336", "CWE-22", "CWE-502"],
            "xss": ["CWE-79"],
            "auth": ["CWE-287", "CWE-601"],
            "authz": ["CWE-639", "CWE-352"],
            "ssrf": ["CWE-918"],
        }
        cwes = class_cwe_map.get(vuln_class, [])
        return finding.cwe_id in cwes if finding.cwe_id else False

    def _format_recon_deliverable(self, recon_data: dict) -> str:
        """Format reconnaissance data as markdown deliverable."""
        lines = [
            "# Reconnaissance Report",
            "",
            f"**Target:** {recon_data.get('target', 'Unknown')}",
            "",
            "## Endpoints",
            "",
        ]
        for ep in recon_data.get("endpoints", []):
            lines.append(f"- {ep}")

        lines.extend(["", "## Technologies", ""])
        for tech in recon_data.get("technologies", []):
            lines.append(f"- {tech}")

        lines.extend(["", "## API Endpoints", ""])
        for api in recon_data.get("api_endpoints", []):
            lines.append(f"- {api}")

        return "\n".join(lines)

    def _format_vuln_deliverable(self, vuln_class: str, findings: list) -> str:
        """Format vulnerability findings as markdown deliverable."""
        lines = [
            f"# {vuln_class.upper()} Vulnerability Analysis",
            "",
            f"**Total Findings:** {len(findings)}",
            "",
        ]

        for f in findings:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                f.severity, "⚪"
            )
            lines.append(f"## {emoji} {f.title}")
            lines.append("")
            lines.append(f"- **Severity:** {f.severity}")
            lines.append(f"- **Confidence:** {f.confidence}")
            if f.cwe_id:
                lines.append(f"- **CWE:** {f.cwe_id}")
            if f.file_path:
                lines.append(f"- **Location:** `{f.file_path}:{f.line_number}`")
            lines.append(f"- **Description:** {f.description}")
            lines.append("")

        return "\n".join(lines)

    def _report_progress(self, progress: PipelineProgress):
        """Report progress to all registered callbacks."""
        for cb in self._progress_callbacks:
            try:
                cb(progress)
            except Exception:
                pass

    def _get_http_client(self):
        """Get or create an HTTP client context manager."""
        if self.http_client:
            return self.http_client

        class _NullCtx:
            async def __aenter__(self):
                import httpx

                return httpx.AsyncClient(verify=False, timeout=30)

            async def __aexit__(self, *args):
                pass

        return _NullCtx()
