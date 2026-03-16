from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from pathlib import Path

from watt.models.entities import Finding, FindingSeverity, NodeKind, Evidence, EvidenceKind, EvidencePointer
from watt.modules.base import SimpleModule


class RetireJSIntegrationModule(SimpleModule):
    """
    Integrates RetireJS to scan for vulnerable JavaScript libraries.
    Requires 'retire' (Node.js) to be installed and available in the system PATH.
    """

    name = "analysis.retirejs"
    phase = "analysis"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.retire_path = shutil.which("retire")

    async def run(self) -> None:
        if not self.retire_path:
            self.log.warning("RetireJS binary not found in PATH. Skipping RetireJS scan.")
            return

        # RetireJS primarily scans files on disk or a live URL.
        # Since we have crawled pages cached in the workspace, we can scan that directory.
        pages_dir = self.ctx.workspace.cache_dir / "pages"
        if not pages_dir.exists() or not any(pages_dir.iterdir()):
            self.log.info("No cached pages found to scan with RetireJS.")
            return

        self.log.info("Starting RetireJS scan on cached pages...")
        output_file = self.ctx.workspace.cache_dir / "retirejs_results.json"

        # Command: retire --path <dir> --outputformat json --outputpath <file>
        cmd = [
            self.retire_path,
            "--path", str(pages_dir),
            "--outputformat", "json",
            "--outputpath", str(output_file),
            "--exitwith", "0" # Don't exit with error code on vulnerabilities
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _stdout, stderr = await process.communicate()

        if process.returncode != 0 and not output_file.exists():
            self.log.error("RetireJS failed: %s", stderr.decode())
            return

        self._parse_results(output_file)

    def _parse_results(self, result_file: Path) -> None:
        if not result_file.exists():
            return

        try:
            content = result_file.read_text(encoding="utf-8")
            if not content:
                return
            
            # RetireJS output is a JSON list of file objects
            results = json.loads(content)
            for file_entry in results:
                file_path = file_entry.get("file", "unknown")
                for result in file_entry.get("results", []):
                     self._create_finding(file_path, result)

        except Exception as e:
            self.log.error("Failed to parse RetireJS results: %s", e)

    def _create_finding(self, file_path: str, item: dict) -> None:
        component = item.get("component", "unknown")
        version = item.get("version", "unknown")
        vulnerabilities = item.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
             info = ", ".join(vuln.get("info", []))
             self.ctx.map.add_finding(Finding(
                id=str(uuid.uuid4()),
                title=f"Vulnerable JS Library: {component} {version}",
                summary=f"RetireJS detected {component} version {version} with issues: {info}",
                severity=FindingSeverity.medium, # JS lib vulns vary, default to medium
                score=50.0,
                tags=["retirejs", "vulnerable_dependency", component],
                evidence=[Evidence(pointer=EvidencePointer(kind=EvidenceKind.manual, url=file_path), excerpt=json.dumps(vuln), parser=self.name)],
                attrs={"retirejs_data": item}
            ))