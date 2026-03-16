from __future__ import annotations

import uuid
from typing import List

from watt.modules.base import SimpleModule
from watt.models.entities import NodeKind, Finding, FindingSeverity, Evidence


class GhostEndpointModule(SimpleModule):
    """
    Analyzes discovered endpoints (from JS, etc.) and ranks them for manual review.
    """

    name = "intel.ghost_endpoints"
    phase = "analysis"

    # Keywords that suggest administrative or internal functionality
    HIGH_VALUE_KEYWORDS = {
        "admin", "internal", "dashboard", "config", "debug", "test", 
        "upload", "billing", "payment", "webhooks", "v1", "v2", "graphql"
    }

    async def run(self) -> None:
        self.log.info("Ranking ghost endpoints...")
        
        endpoints = self.ctx.map.nodes_by_kind(NodeKind.endpoint)
        if not endpoints:
            self.log.info("No endpoints to analyze.")
            return

        hits = 0
        for node in endpoints:
            score, rationale = self._calculate_score(node.label)
            
            if score >= 50:
                hits += 1
                self._create_finding(node, score, rationale)

        self.log.info("Analyzed %d endpoints, created %d findings.", len(endpoints), hits)

    def _calculate_score(self, path: str) -> tuple[float, List[str]]:
        score = 0.0
        reasons = []
        path_lower = path.lower()

        for kw in self.HIGH_VALUE_KEYWORDS:
            if kw in path_lower:
                score += 20
                reasons.append(f"Contains '{kw}'")

        if "api" in path_lower:
            score += 10
            reasons.append("API route")

        # Boost if it looks like a file upload or export
        if "upload" in path_lower or "export" in path_lower:
            score += 15
            reasons.append("Data movement (upload/export)")

        return min(score, 100.0), reasons

    def _create_finding(self, node: Any, score: float, rationale: List[str]) -> None:
        summary = f"Ghost endpoint discovered in client-side assets: {node.label}. Reasons: {', '.join(rationale)}"
        severity = FindingSeverity.medium if score > 70 else FindingSeverity.low
        
        finding = Finding(
            id=str(uuid.uuid4()),
            title=f"Interesting Ghost Endpoint: {node.label}",
            summary=summary,
            severity=severity,
            score=score,
            tags=["ghost_endpoint", "recon"],
            related_nodes=[node.id],
            evidence=node.evidence,
        )
        
        self.ctx.map.add_finding(finding)