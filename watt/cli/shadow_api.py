from __future__ import annotations

import uuid
import re
from watt.modules.base import SimpleModule
from watt.models.entities import NodeKind, Finding, FindingSeverity


class ShadowApiModule(SimpleModule):
    """
    Infers existence of Shadow APIs based on URL patterns and subdomains.
    """

    name = "intel.shadow_api"
    phase = "analysis"

    API_INDICATORS = re.compile(r"api|gateway|bff|graphql|swagger|v\d+", re.IGNORECASE)

    async def run(self) -> None:
        self.log.info("Inferring Shadow API candidates...")
        
        # 1. Check Hosts
        hosts = self.ctx.map.nodes_by_kind(NodeKind.host)
        for host in hosts:
            if self.API_INDICATORS.search(host.label):
                self._report_shadow_host(host)

        # 2. Check URL clusters (simple version)
        urls = self.ctx.map.nodes_by_kind(NodeKind.url)
        api_families = set()
        
        for url_node in urls:
            # Very naive extraction of "base" API path
            # e.g. https://api.example.com/v1/users -> https://api.example.com/v1
            if "/v1/" in url_node.label or "/v2/" in url_node.label or "/api/" in url_node.label:
                base = self._extract_base(url_node.label)
                if base:
                    api_families.add(base)

        for family in api_families:
            self._report_api_family(family)

    def _extract_base(self, url: str) -> str | None:
        match = re.search(r"(https?://[^/]+(?:/api)?/v\d+)", url)
        if match:
            return match.group(1)
        match_api = re.search(r"(https?://[^/]+/api)", url)
        if match_api:
            return match_api.group(1)
        return None

    def _report_shadow_host(self, node: Any) -> None:
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Potential Shadow API Host: {node.label}",
            summary="Host naming convention suggests API or Gateway role.",
            severity=FindingSeverity.medium,
            score=60.0,
            related_nodes=[node.id]
        ))

    def _report_api_family(self, family_url: str) -> None:
        # In a real graph, we'd link this to a new 'Service' node
        self.log.info("Inferred API Family: %s", family_url)
        # For now, just logging or creating a finding is enough for the requirement