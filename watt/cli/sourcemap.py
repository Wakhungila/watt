from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List
from urllib.parse import urljoin

from watt.models.entities import Confidence, EdgeKind, NodeKind
from watt.models.evidence import Evidence, EvidenceKind, EvidencePointer
from watt.modules.base import ModuleContext, SimpleModule
from watt.utils.network import SmartClient


class SourceMapModule(SimpleModule):
    """
    Source Map Intelligence Module.

    Responsibilities:
    - Detect source map references in JS files.
    - Fetch and parse .map files.
    - Extract original source file paths (restoring the developer's file structure).
    - Identify sensitive internal paths (node_modules, src/api, etc.).
    """

    name = "intel.sourcemap"
    phase = "intel"

    # Matches //# sourceMappingURL=app.js.map or //@ sourceMappingURL=...
    SOURCEMAP_REGEX = re.compile(r"[#@]\s+sourceMappingURL=([^\s'\"`]+)\s*$", re.MULTILINE)

    def __init__(self, ctx: ModuleContext) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        # Find all JS nodes to analyze
        js_nodes = [
            n for n in self.ctx.map.nodes_by_kind(NodeKind.url)
            if n.label.endswith(".js") or "script" in n.tags
        ]

        if not js_nodes:
            self.log.info("No JavaScript assets found to analyze for source maps.")
            return

        self.log.info("Checking %d JS assets for source maps...", len(js_nodes))
        tasks = [self._process_asset(node.id, node.label) for node in js_nodes]
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _process_asset(self, node_id: str, url: str) -> None:
        try:
            # 1. Fetch JS to find the map directive
            resp = await self.client.get(url)
            if not resp.text:
                return

            map_url = self._find_map_url(url, resp.text)
            if not map_url:
                # Fallback: try appending .map
                map_url = url + ".map"

            # 2. Fetch the Source Map
            map_resp = await self.client.get(map_url)
            if map_resp.status_code != 200:
                return
            
            try:
                data = map_resp.json()
            except json.JSONDecodeError:
                return

            self.log.info("Found source map: %s", map_url)
            self._ingest_map(node_id, map_url, data)

        except Exception as exc:
            self.log.debug("Failed to process source map for %s: %s", url, exc)

    def _find_map_url(self, base_url: str, content: str) -> str | None:
        match = self.SOURCEMAP_REGEX.search(content)
        if match:
            return urljoin(base_url, match.group(1))
        return None

    def _ingest_map(self, origin_node_id: str, map_url: str, data: Dict[str, Any]) -> None:
        sources = data.get("sources", [])
        if not sources:
            return

        # Add the map file itself
        self.ctx.map.upsert_node(
            kind=NodeKind.url,
            label=map_url,
            confidence=Confidence(score=1.0, rationale="Fetched successfully"),
            tags=["source_map", "exposure"],
        )

        # Extract source paths
        for src_path in sources:
            # Clean up webpack protocols
            clean_path = src_path.replace("webpack:///", "").replace("webpack://", "")
            
            # We map these as Endpoints for now, tagged as source_file
            self.ctx.map.upsert_node(
                kind=NodeKind.endpoint,
                label=clean_path,
                confidence=Confidence(score=1.0, rationale="Extracted from source map"),
                tags=["source_file", "internal_structure"],
                evidence=[
                    Evidence(
                        pointer=EvidencePointer(kind=EvidenceKind.url_list, url=map_url),
                        excerpt=src_path,
                        parser=self.name
                    )
                ]
            )