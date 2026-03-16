from __future__ import annotations

import asyncio
import re
import uuid
from typing import List, NamedTuple, Pattern

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.models.evidence import Evidence, EvidenceKind, EvidencePointer
from watt.modules.base import ModuleContext, SimpleModule
from watt.utils.network import SmartClient


class RegexPattern(NamedTuple):
    name: str
    pattern: Pattern
    score: float


class SecretsModule(SimpleModule):
    """
    Scans JavaScript assets for hardcoded secrets and keys.
    """

    name = "intel.secrets"
    phase = "intel"

    PATTERNS = [
        RegexPattern("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), 0.9),
        RegexPattern("Google API Key", re.compile(r"AIza[0-9A-Za-z\\-_]{35}"), 0.9),
        RegexPattern("Generic API Key", re.compile(r"(?i)(?:api_key|apikey|secret|token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"), 0.6),
        RegexPattern("Slack Token", re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"), 0.95),
        RegexPattern("Private Key Block", re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"), 1.0),
    ]

    def __init__(self, ctx: ModuleContext) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        js_nodes = [
            n for n in self.ctx.map.nodes_by_kind(NodeKind.url)
            if n.label.endswith(".js") or "script" in n.tags
        ]

        if not js_nodes:
            self.log.info("No JavaScript assets found to scan for secrets.")
            return

        self.log.info("Scanning %d JS assets for secrets...", len(js_nodes))
        tasks = [self._scan_asset(node.id, node.label) for node in js_nodes]
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _scan_asset(self, node_id: str, url: str) -> None:
        try:
            resp = await self.client.get(url)
            if not resp.text:
                return
            
            content = resp.text
            for pattern in self.PATTERNS:
                matches = pattern.pattern.findall(content)
                for match in matches:
                    val = match if isinstance(match, str) else match[0]
                    # Basic false positive reduction
                    if self._is_false_positive(val):
                        continue
                        
                    self._report_secret(node_id, url, pattern.name, val, pattern.score)

        except Exception as exc:
            self.log.debug("Failed to scan %s for secrets: %s", url, exc)

    def _is_false_positive(self, val: str) -> bool:
        # Heuristic: Ignore common CSS/JS keywords that look like keys
        if len(val) < 8: return True
        if " " in val: return True
        return False

    def _report_secret(self, node_id: str, url: str, kind: str, value: str, confidence: float) -> None:
        masked = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
        self.log.warning("Potential %s found in %s: %s", kind, url, masked)
        
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Potential Secret: {kind}",
            summary=f"A pattern matching {kind} was found in {url}",
            severity=FindingSeverity.high if confidence > 0.8 else FindingSeverity.medium,
            score=confidence * 100,
            tags=["secret", "exposure"],
            related_nodes=[node_id],
            evidence=[Evidence(pointer=EvidencePointer(kind=EvidenceKind.url_list, url=url), excerpt=masked, parser=self.name)],
        ))