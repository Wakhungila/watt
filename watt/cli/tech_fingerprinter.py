from __future__ import annotations

import asyncio
import re

from watt.models.entities import NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class TechnologyFingerprinterModule(SimpleModule):
    """
    Identifies technology stacks from HTTP responses.
    """

    name = "analysis.tech_fingerprinter"
    phase = "analysis"

    # This is a simplified list. A real-world tool would use a much larger
    # and more detailed fingerprint database (like Wappalyzer's).
    TECH_FINGERPRINTS = {
        # Headers
        "django": {"headers": {"x-powered-by": "Django", "set-cookie": "csrftoken="}},
        "express": {"headers": {"x-powered-by": "Express", "etag": "W/"}},
        "php": {"headers": {"x-powered-by": "PHP", "set-cookie": "PHPSESSID="}},
        "nextjs": {"headers": {"x-powered-by": "Next.js", "x-nextjs-cache": ""}},
        "ruby_on_rails": {"headers": {"x-powered-by": "Phusion Passenger", "server": "nginx/1."}},
        "laravel": {"headers": {"set-cookie": "laravel_session="}},
        "asp_net": {"headers": {"x-aspnet-version": ""}},

        # Body content
        "react": {"body": [r'data-react-id', r'react-dom\.development\.js', r'id="___gatsby"']},
        "vuejs": {"body": [r'data-v-[a-f0-9]{8}', r'id="app"']},
        "angular": {"body": [r'ng-app', r'ng-version']},
        "webpack": {"body": [r'webpackJsonp']},
        "wordpress": {"body": [r'wp-content', r'wp-includes']},
        "joomla": {"body": [r'com_content']},
        "drupal": {"body": [r'Drupal\.settings', r'sites/all/modules']},
        "shopify": {"body": [r'cdn\.shopify\.com']},
        "magento": {"body": [r'Mage.Cookies', r'skin/frontend/']},
        "jquery": {"body": [r'jquery\.js', r'jquery.min.js']},
        "bootstrap": {"body": [r'bootstrap\.js', r'bootstrap\.min\.css']},
        "sentry": {"body": [r'sentry\.io/api/']},
        "cloudflare": {"body": [r'cloudflare-static/email-decode.min.js']},
    }

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Fingerprinting technologies on live services...")
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        live_urls = [node for node in url_nodes if "service_root" in node.tags]

        tasks = [self._fingerprint_url(url_node) for url_node in live_urls]
        await asyncio.gather(*tasks)
        await self.client.close()

    async def _fingerprint_url(self, url_node) -> None:
        try:
            resp = await self.client.get(url_node.label)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            content = resp.text

            found_tech = []

            for tech, fingerprints in self.TECH_FINGERPRINTS.items():
                # Check headers
                if "headers" in fingerprints:
                    for header, value in fingerprints["headers"].items():
                        if header in headers and value in headers[header]:
                            found_tech.append(tech)
                
                # Check body
                if "body" in fingerprints and content:
                    for pattern in fingerprints["body"]:
                        if re.search(pattern, content, re.IGNORECASE):
                            found_tech.append(tech)
                            break # One body pattern is enough
            
            if found_tech:
                unique_tech = sorted(list(set(found_tech)))
                self.log.info("Found technologies on %s: %s", url_node.label, ", ".join(unique_tech))
                
                # Update the URL node with the new tags
                self.ctx.map.upsert_node(
                    kind=NodeKind.url,
                    label=url_node.label,
                    confidence=url_node.confidence,
                    tags=[f"tech:{t}" for t in unique_tech],
                    attrs={"technologies": unique_tech}
                )

        except Exception as e:
            self.log.debug("Tech fingerprinting failed for %s: %s", url_node.label, e)