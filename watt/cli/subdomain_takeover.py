from __future__ import annotations

import asyncio
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class SubdomainTakeoverModule(SimpleModule):
    """
    Checks discovered hosts for signs of subdomain takeover.
    """

    name = "analysis.subdomain_takeover"
    phase = "analysis"

    # Fingerprints for common takeover vulnerabilities.
    # This list is not exhaustive and should be expanded.
    FINGERPRINTS = {
        "There is no such S3 bucket": "AWS S3",
        "NoSuchBucket": "AWS S3",
        "The specified bucket does not exist": "AWS S3",
        "Repository not found": "GitHub Pages",
        "There isn't a GitHub Pages site here.": "GitHub Pages",
        "404 Blog is not found": "Tumblr",
        "The thing you were looking for is no longer here": "Heroku",
        "herokucdn.com/error-pages/no-such-app.html": "Heroku",
        "No such app": "Heroku",
        "Whatever you were looking for doesn't currently exist at this address": "Surge.sh",
        "Project Not Found": "Surge.sh",
        "You are seeing this page because this is not a valid Atom site": "Atom",
        "This page is reserved for artistic dogs.": "Intercom",
        "Unrecognized domain": "Pantheon",
        "The specified bucket does not exist": "AWS S3",
        "Sorry, this shop is currently unavailable": "Shopify",
        "There is no Portal here": "Hubspot",
        "This page is reserved for a future Twilio SendGrid feature": "SendGrid",
        "Fastly error: unknown domain": "Fastly",
        "The feed has not been found.": "Feedpress",
        "Trying to access your Zendesk account?": "Zendesk",
        "Redirecting...": "Cargo Collective",
        "Do you want to register": "Wordpress",
        "Help Center Closed": "Zendesk",
    }

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Checking for potential subdomain takeovers...")
        hosts = self.ctx.map.nodes_by_kind(NodeKind.host)

        if not hosts:
            self.log.info("No hosts to check for takeover.")
            return

        tasks = [self._check_host(host) for host in hosts]
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _check_host(self, host_node) -> None:
        # We check both http and https
        for scheme in ["http", "https"]:
            url = f"{scheme}://{host_node.label}"
            try:
                resp = await self.client.get(url)
                content = resp.text

                for fingerprint, service in self.FINGERPRINTS.items():
                    if fingerprint in content:
                        self._report_takeover(host_node, url, service, fingerprint)
                        # Found a fingerprint, no need to check other fingerprints for this host/scheme
                        break
            except Exception:
                # Ignore connection errors, etc.
                pass

    def _report_takeover(self, host_node, url: str, service: str, fingerprint: str) -> None:
        self.log.warning(
            "Potential subdomain takeover of '%s' via %s (fingerprint: '%s')",
            host_node.label, service, fingerprint
        )
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title=f"Potential Subdomain Takeover on {host_node.label}",
            summary=f"The host {host_node.label} may be vulnerable to takeover via {service}. The response contained the text: '{fingerprint}'.",
            severity=FindingSeverity.high,
            score=80.0,
            tags=["subdomain_takeover", "vulnerability", service.lower().replace(" ", "_")],
            related_nodes=[host_node.id],
        ))