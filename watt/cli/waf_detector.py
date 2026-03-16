from __future__ import annotations

import asyncio
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class WafDetectorModule(SimpleModule):
    """
    Identifies Web Application Firewalls (WAFs) from HTTP responses.
    """

    name = "recon.waf_detector"
    phase = "recon"

    # Common WAF fingerprints in headers
    WAF_FINGERPRINTS = {
        "cloudflare": {"server": "cloudflare", "cf-ray": ""},
        "aws_waf": {"server": "awselb", "x-amz-request-id": ""},
        "akamai": {"server": "AkamaiGHost", "x-akamai-transformed": ""},
        "sucuri": {"server": "Sucuri/Cloudproxy", "x-sucuri-id": ""},
        "incapsula": {"x-iinfo": "", "x-cdn": "Incapsula"},
    }

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Detecting WAFs on live services...")
        # We'll check live URLs that have been probed
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        live_urls = [node for node in url_nodes if "service_root" in node.tags]

        tasks = [self._check_url(url_node) for url_node in live_urls]
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _check_url(self, url_node) -> None:
        try:
            resp = await self.client.get(url_node.label)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for waf_name, fingerprints in self.WAF_FINGERPRINTS.items():
                matches = 0
                for header, value in fingerprints.items():
                    if header in headers:
                        if not value or value in headers[header]:
                            matches += 1
                
                if matches == len(fingerprints):
                    self._report_waf(url_node, waf_name)
                    break # Found one, move to next URL

        except Exception as e:
            self.log.debug("WAF check failed for %s: %s", url_node.label, e)

    def _report_waf(self, url_node, waf_name: str) -> None:
        self.log.warning("WAF Detected on %s: %s", url_node.label, waf_name.upper())
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"WAF Detected: {waf_name.upper()}",
            summary=f"The service at {url_node.label} appears to be protected by {waf_name.upper()}.",
            severity=FindingSeverity.info,
            score=5.0,
            tags=["waf", waf_name],
            related_nodes=[url_node.id],
        ))