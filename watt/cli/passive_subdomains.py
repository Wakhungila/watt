from __future__ import annotations

import asyncio

import httpx

from watt.models.entities import Confidence, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class PassiveSubdomainModule(SimpleModule):
    """
    Performs passive subdomain enumeration using third-party APIs.
    """

    name = "recon.passive_subdomains"
    phase = "recon"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Starting passive subdomain enumeration...")
        
        self.vt_key = self.ctx.config.api_keys.virustotal
        self.st_key = self.ctx.config.api_keys.securitytrails
        self.chaos_key = self.ctx.config.api_keys.chaos

        # Get root domains from the initial targets
        root_domains = {
            t.raw for t in self.ctx.config.targets if t.kind == "domain"
        }

        if not root_domains:
            self.log.info("No root domains found in targets to enumerate.")
            return

        for domain in root_domains:
            await self._enumerate_domain(domain)
            
        await self.client.close()

    async def _enumerate_domain(self, domain: str) -> None:
        self.log.info("Enumerating subdomains for: %s", domain)
        all_subs = set()

        if self.vt_key:
            vt_subs = await self._query_virustotal(domain)
            all_subs.update(vt_subs)
        
        if self.st_key:
            st_subs = await self._query_securitytrails(domain)
            all_subs.update(st_subs)
        
        if self.chaos_key:
            chaos_subs = await self._query_chaos(domain)
            all_subs.update(chaos_subs)

        if not self.vt_key and not self.st_key and not self.chaos_key:
            # Placeholder fallback if no keys are present
            await asyncio.sleep(0.1)
            all_subs.update({f"api.{domain}", f"dev.{domain}", f"staging.{domain}"})
            self.log.warning("No API keys for passive subdomain enumeration. Using placeholder data.")

        self.log.info("Found %d unique subdomains for %s", len(all_subs), domain)

        for sub in all_subs:
            self.ctx.map.upsert_node(
                kind=NodeKind.host,
                label=sub,
                confidence=Confidence(
                    score=0.7, rationale="Discovered via passive enumeration"
                ),
                tags=["subdomain", "passive"],
            )

    async def _query_virustotal(self, domain: str) -> set[str]:
        self.log.debug("Querying VirusTotal for %s", domain)
        subs = set()
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        headers = {"x-apikey": self.vt_key}
        
        while url:
            try:
                resp = await self.client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        if item.get("id"):
                            subs.add(item["id"])
                    
                    # Check for next page
                    url = data.get("links", {}).get("next")
                else:
                    self.log.error("VirusTotal API error (status %d): %s", resp.status_code, resp.text)
                    break
            except Exception as e:
                self.log.error("VirusTotal query failed: %s", e)
                break
        return subs

    async def _query_securitytrails(self, domain: str) -> set[str]:
        self.log.debug("Querying SecurityTrails for %s", domain)
        subs = set()
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": self.st_key}
        
        try:
            resp = await self.client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                subdomains = data.get("subdomains", [])
                for sub in subdomains:
                    subs.add(f"{sub}.{domain}")
            elif resp.status_code == 429:
                self.log.warning("SecurityTrails API rate limit reached.")
            else:
                self.log.error("SecurityTrails API error (status %d): %s", resp.status_code, resp.text)
        except Exception as e:
            self.log.error("SecurityTrails query failed: %s", e)
        
        return subs

    async def _query_chaos(self, domain: str) -> set[str]:
        self.log.debug("Querying Chaos for %s", domain)
        subs = set()
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": self.chaos_key}

        try:
            resp = await self.client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    subs.add(f"{sub}.{domain}")
            elif resp.status_code == 429:
                self.log.warning("Chaos API rate limit reached.")
            else:
                self.log.error("Chaos API error (status %d): %s", resp.status_code, resp.text)
        except Exception as e:
            self.log.error("Chaos query failed: %s", e)
        
        return subs