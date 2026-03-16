from __future__ import annotations

import re
import hashlib
import uuid
from typing import Set

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.models.evidence import Evidence, EvidencePointer, EvidenceKind


class EmailExtractorPlugin(SimpleModule):
    """
    An example plugin that finds email addresses in crawled pages.
    """

    name = "plugin.email_extractor"
    phase = "analysis"  # Run after crawling

    # A simple regex to find email-like strings
    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    async def run(self) -> None:
        self.log.info("Running Email Extractor Plugin...")

        # 1. Find all crawled pages
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        crawled_nodes = [node for node in url_nodes if "crawled" in node.tags]

        if not crawled_nodes:
            self.log.info("No crawled pages found to analyze for emails.")
            return

        found_count = 0
        # 2. For each page, read its cached content
        for node in crawled_nodes:
            try:
                cache_dir = self.ctx.workspace.cache_dir / "pages"
                filename = hashlib.sha256(node.label.encode()).hexdigest() + ".html"
                cache_path = cache_dir / filename

                if not cache_path.exists():
                    continue

                content = cache_path.read_text(encoding="utf-8")

                # 3. Find unique emails
                emails: Set[str] = set(self.EMAIL_REGEX.findall(content))

                # 4. Create findings
                for email in emails:
                    found_count += 1
                    self.log.warning("Found potential email address: %s in %s", email, node.label)
                    self.ctx.map.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title=f"Email Address Found: {email}",
                        summary=f"An email address was discovered on page {node.label}.",
                        severity=FindingSeverity.info,
                        score=5.0,
                        tags=["pii", "email"],
                        related_nodes=[node.id],
                        evidence=[Evidence(pointer=EvidencePointer(kind=EvidenceKind.url_list, url=node.label), excerpt=email, parser=self.name)],
                    ))
            except Exception as e:
                self.log.error("Failed to process page %s for emails: %s", node.label, e)

        self.log.info("Email Extractor finished. Found %d potential emails.", found_count)