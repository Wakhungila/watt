from __future__ import annotations

import asyncio
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class MisconfigurationModule(SimpleModule):
    """
    Checks for common web server misconfigurations.
    """

    name = "analysis.misconfiguration"
    phase = "analysis"

    # Paths and fingerprints for common misconfigurations
    MISCONFIG_CHECKS = {
        "directory_listing": {
            "paths": ["/", "/uploads/", "/static/", "/images/"],
            "fingerprints": ["<title>Index of /"],
        },
        "debug_page": {
            "paths": ["/debug", "/test.php", "/info.php"],
            "fingerprints": ["phpinfo()", "Environment Variables", "Django Debug"],
        },
        "config_backup": {
            "paths": ["/config.php.bak", "/.env", "/web.config.old"],
            "fingerprints": ["DB_PASSWORD", "connectionString"],
        },
        "api_docs": {
            "paths": ["/swagger-ui.html", "/api/docs", "/docs", "/api-docs", "/openapi.json", "/swagger.json", "/v2/api-docs"],
            "fingerprints": ["swagger", "openapi", "Swagger UI", "Redoc"],
        },
        "graphql_console": {
            "paths": ["/graphiql", "/graphql/console", "/playground"],
            "fingerprints": ["GraphiQL", "GraphQL Playground"],
        },
        "actuator": {
            "paths": ["/actuator", "/actuator/health", "/actuator/env"],
            "fingerprints": ["{\"status\":\"UP\"}", "actuator"],
        },
    }

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Checking for common misconfigurations...")
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        live_urls = [node for node in url_nodes if "service_root" in node.tags]

        tasks = []
        for url_node in live_urls:
            for check_name, check_data in self.MISCONFIG_CHECKS.items():
                for path in check_data["paths"]:
                    for fingerprint in check_data["fingerprints"]:
                        tasks.append(self._check_misconfig(url_node, path, fingerprint, check_name))
        
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _check_misconfig(self, url_node, path: str, fingerprint: str, check_name: str) -> None:
        check_url = f"{url_node.label.rstrip('/')}{path}"
        try:
            resp = await self.client.get(check_url)
            if resp.status_code == 200 and fingerprint in resp.text:
                self._report_misconfig(url_node, check_url, check_name, fingerprint)
        except Exception:
            pass

    def _report_misconfig(self, url_node, url: str, check_name: str, fingerprint: str) -> None:
        self.log.warning("Potential misconfiguration '%s' found at %s", check_name, url)
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Potential Misconfiguration: {check_name.replace('_', ' ').title()}",
            summary=f"The URL {url} may expose a '{check_name}' due to the presence of fingerprint: '{fingerprint}'.",
            severity=FindingSeverity.medium,
            score=40.0,
            tags=["misconfiguration", check_name],
            related_nodes=[url_node.id],
        ))