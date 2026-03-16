from __future__ import annotations

import asyncio
from typing import Set

from watt.models.entities import Confidence, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class CertificateMonitorModule(SimpleModule):
    """
     queries crt.sh to find subdomains from Certificate Transparency logs.
    """

    name = "recon.cert_monitor"
    phase = "recon"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Starting Certificate Transparency monitoring...")
        
        root_domains = {
            t.raw for t in self.ctx.config.targets if t.kind == "domain"
        }

        if not root_domains:
            self.log.info("No root domains to monitor.")
            return

        for domain in root_domains:
            await self._query_crtsh(domain)
            
        await self.client.close()

    async def _query_crtsh(self, domain: str) -> None:
        self.log.info("Querying crt.sh for %s", domain)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        try:
            resp = await self.client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                found_count = 0
                for entry in data:
                    name_value = entry.get("name_value")
                    if name_value:
                        # CRT.sh can return multiple domains per line
                        for sub in name_value.split("\n"):
                            if "*" not in sub: # Ignore wildcard entries
                                self.ctx.map.upsert_node(kind=NodeKind.host, label=sub, confidence=Confidence(score=0.9, rationale="Certificate Transparency Log"), tags=["subdomain", "ct_log"])
                                found_count += 1
                self.log.info("Found %d subdomains for %s via CT logs", found_count, domain)
            else:
                self.log.warning("crt.sh returned status %d", resp.status_code)
        except Exception as e:
            self.log.error("Failed to query crt.sh: %s", e)