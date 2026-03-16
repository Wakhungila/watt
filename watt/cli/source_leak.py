from __future__ import annotations

import asyncio
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class SourceLeakModule(SimpleModule):
    """
    Checks for exposed source code repositories or sensitive files.
    """

    name = "analysis.source_leak"
    phase = "analysis"

    # Paths to check for source code leaks.
    # The tuple contains (path, expected_text_if_found)
    LEAK_PATHS = [
        (".git/config", "[core]"),
        (".svn/entries", "dir"),
        (".DS_Store", ""), # Check for existence and non-empty
        ("WEB-INF/web.xml", "<web-app"),
    ]

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Checking for source code leaks...")
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        live_urls = [node for node in url_nodes if "service_root" in node.tags]

        tasks = []
        for url_node in live_urls:
            for path, fingerprint in self.LEAK_PATHS:
                tasks.append(self._check_leak(url_node, path, fingerprint))
        
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _check_leak(self, url_node, path: str, fingerprint: str) -> None:
        # Construct the full URL, ensuring no double slashes
        leak_url = f"{url_node.label.rstrip('/')}/{path}"
        try:
            resp = await self.client.get(leak_url)
            if resp.status_code == 200 and (not fingerprint or fingerprint in resp.text):
                self._report_leak(url_node, leak_url, path)
        except Exception:
            # Ignore network errors, 404s, etc.
            pass

    def _report_leak(self, url_node, leak_url: str, leak_type: str) -> None:
        self.log.critical("Potential source code leak found: %s", leak_url)
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Source Code Leak Detected: {leak_type}",
            summary=f"A sensitive path '{leak_url}' was found and is publicly accessible.",
            severity=FindingSeverity.critical,
            score=95.0,
            tags=["source_leak", "exposure", "vulnerability"],
            related_nodes=[url_node.id],
        ))