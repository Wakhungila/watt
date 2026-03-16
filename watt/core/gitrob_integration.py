from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from pathlib import Path

from watt.models.entities import Finding, FindingSeverity, Evidence, EvidenceKind, EvidencePointer
from watt.modules.base import SimpleModule


class GitRobIntegrationModule(SimpleModule):
    """
    Integrates GitRob for finding sensitive files in public GitHub repositories.
    Requires 'gitrob' to be installed and available in the system PATH.
    """

    name = "analysis.gitrob"
    phase = "analysis"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.gitrob_path = shutil.which("gitrob")
        self.github_key = self.ctx.config.api_keys.github

    async def run(self) -> None:
        if not self.gitrob_path:
            self.log.warning("GitRob binary not found in PATH. Skipping gitrob scan.")
            return

        if not self.github_key:
            self.log.warning("GitHub API key not configured. Skipping gitrob scan.")
            return

        # Find targets of kind 'org'
        org_targets = [t.raw for t in self.ctx.config.targets if t.kind == "org"]
        if not org_targets:
            self.log.info("No organization targets found for GitRob scan.")
            return

        self.log.info("Starting GitRob scan for organizations: %s", ", ".join(org_targets))

        tasks = [self._scan_org(org) for org in org_targets]
        await asyncio.gather(*tasks)

    async def _scan_org(self, org_name: str) -> None:
        output_file = self.ctx.workspace.cache_dir / f"gitrob_{org_name}.json"

        cmd = [
            self.gitrob_path,
            "-github-access-token", self.github_key,
            "-save", str(output_file),
            "-no-banner",
            "-no-color",
            org_name,
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.log.error("GitRob failed for org %s: %s", org_name, stderr.decode())
            return

        self._parse_results(output_file)

    def _parse_results(self, result_file: Path) -> None:
        if not result_file.exists():
            return

        try:
            # GitRob's -save output is a line-delimited JSON file
            with result_file.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        finding_data = json.loads(line)
                        self._create_finding(finding_data)
        except Exception as e:
            self.log.error("Failed to parse GitRob results from %s: %s", result_file, e)

    def _create_finding(self, item: dict) -> None:
        caption = item.get("Caption", "Unknown GitRob Finding")
        description = item.get("Description", "No description")
        file_path = item.get("FilePath", "N/A")
        repo_name = item.get("RepositoryName", "N/A")
        commit_url = item.get("CommitUrl", "")

        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"GitRob: {caption}",
            summary=f"Found '{description}' in {repo_name} at path '{file_path}'.",
            severity=FindingSeverity.high, # GitRob findings are usually high-impact
            score=75.0,
            tags=["gitrob", "osint", "source_leak", "secret"],
            evidence=[Evidence(pointer=EvidencePointer(kind=EvidenceKind.url_list, url=commit_url), excerpt=file_path, parser=self.name)],
            attrs={"gitrob_data": item},
        ))