from __future__ import annotations

import asyncio
import json
import shutil
import hashlib
import uuid
from pathlib import Path

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.models.evidence import Evidence, EvidenceKind, EvidencePointer


class NucleiIntegrationModule(SimpleModule):
    """
    Integrates Nuclei for vulnerability scanning against discovered hosts.
    Requires 'nuclei' to be installed and available in the system PATH.
    """

    name = "analysis.nuclei"
    phase = "analysis"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.nuclei_path = shutil.which("nuclei")

    async def run(self) -> None:
        if not self.nuclei_path:
            self.log.warning("Nuclei binary not found in PATH. Skipping nuclei scan.")
            return

        # Update Nuclei templates before scanning
        await self._update_templates()

        self.log.info("Starting Nuclei scan...")
        
        # Gather targets: Hosts and Live URLs
        targets = set()
        for node in self.ctx.map.nodes_by_kind(NodeKind.host):
            targets.add(node.label)
        for node in self.ctx.map.nodes_by_kind(NodeKind.url):
            if "service_root" in node.tags:
                targets.add(node.label)

        if not targets:
            self.log.info("No targets found for Nuclei scan.")
            return

        # Calculate hash of targets + templates to enable caching
        sorted_targets = sorted(list(targets))
        custom_templates = self.ctx.config.analysis.nuclei_templates
        config_str = json.dumps({"targets": sorted_targets, "templates": custom_templates})
        run_hash = hashlib.sha256(config_str.encode()).hexdigest()

        output_file = self.ctx.workspace.cache_dir / f"nuclei_results_{run_hash}.json"

        if output_file.exists():
            self.log.info("Found cached Nuclei results. Skipping execution.")
            self._parse_results(output_file)
            return

        # Write targets to a file
        target_file = self.ctx.workspace.cache_dir / "nuclei_targets.txt"
        target_file.write_text("\n".join(targets), encoding="utf-8")

        # Construct command
        # Running with -json-export to parse results easily
        # Using default templates for now, can be configured later
        cmd = [
            self.nuclei_path,
            "-l", str(target_file),
            "-json-export", str(output_file),
            "-silent",
            "-nc", # No color
        ]

        # Add custom templates if specified
        if custom_templates:
            cmd.extend(["-t", ",".join(custom_templates)])

        self.log.info("Running Nuclei with command: %s", " ".join(cmd))
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.log.error("Nuclei failed with code %d: %s", process.returncode, stderr.decode())
            return

        self._parse_results(output_file)

    async def _update_templates(self) -> None:
        """
        Runs 'nuclei -update-templates' to ensure templates are fresh.
        """
        self.log.info("Updating Nuclei templates...")
        cmd = [self.nuclei_path, "-update-templates", "-silent"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.log.error("Nuclei template update failed: %s", stderr.decode())
        else:
            self.log.info("Nuclei templates updated successfully.")

    def _parse_results(self, result_file: Path) -> None:
        if not result_file.exists():
            return

        try:
            # Nuclei JSON export is a list of JSON objects (or stream?)
            # Usually it's one JSON object per line or a JSON array. 
            # Let's assume JSON array for -json-export, or line-delimited.
            # Recent nuclei uses JSON array for -json-export.
            content = result_file.read_text(encoding="utf-8")
            results = json.loads(content)

            for item in results:
                self._create_finding(item)
                
        except json.JSONDecodeError:
            # Fallback for line-delimited JSON
             content = result_file.read_text(encoding="utf-8")
             for line in content.splitlines():
                 if line.strip():
                     try:
                         self._create_finding(json.loads(line))
                     except Exception:
                         pass
        except Exception as e:
            self.log.error("Failed to parse Nuclei results: %s", e)

    def _create_finding(self, item: dict) -> None:
        template_id = item.get("template-id", "nuclei-finding")
        name = item.get("info", {}).get("name", template_id)
        severity_str = item.get("info", {}).get("severity", "info").lower()
        host = item.get("host", "")
        matched = item.get("matched-at", "")

        severity_map = {
            "critical": FindingSeverity.critical,
            "high": FindingSeverity.high,
            "medium": FindingSeverity.medium,
            "low": FindingSeverity.low,
            "info": FindingSeverity.info,
            "unknown": FindingSeverity.info
        }
        
        sev = severity_map.get(severity_str, FindingSeverity.info)
        score_map = {
            FindingSeverity.critical: 95.0,
            FindingSeverity.high: 80.0,
            FindingSeverity.medium: 50.0,
            FindingSeverity.low: 20.0,
            FindingSeverity.info: 5.0
        }

        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Nuclei: {name}",
            summary=f"Nuclei detected '{name}' at {matched}",
            severity=sev,
            score=score_map[sev],
            tags=["nuclei", template_id, severity_str],
            related_nodes=[], # Linking is hard without node ID lookup by label, skip for now or implement lookup
            evidence=[Evidence(
                pointer=EvidencePointer(kind=EvidenceKind.manual, url=matched),
                excerpt=json.dumps(item.get("extracted-results", [])),
                parser=self.name
            )],
            attrs={"nuclei_data": item}
        ))