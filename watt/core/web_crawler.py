from __future__ import annotations

import asyncio
from typing import Set, Optional
import hashlib
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright, Browser, Playwright
except ImportError:
    Browser = None
    Playwright = None
    # This allows the module to be imported even if playwright is not installed,
    # a runtime check will prevent its use.

from watt.models.entities import Confidence, EdgeKind, NodeKind
from watt.models.evidence import Evidence, EvidenceKind, EvidencePointer
from watt.modules.base import ModuleContext, SimpleModule
from watt.utils.network import SmartClient


class WebCrawlerModule(SimpleModule):
    """
    An advanced, scope-aware web crawler.

    Responsibilities:
    - Discover new pages (URLs) within the target's scope.
    - Discover JavaScript assets (<script src=...>) for later analysis.
    - Build the relationship graph (page -> contains -> script).
    """

    name = "crawl.web_crawler"
    phase = "crawl"

    def __init__(self, ctx: ModuleContext) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)
        self.queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self.visited: Set[str] = set()
        self.scope_hosts: Set[str] = set()
        self.pages_crawled = 0
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None

    async def run(self) -> None:
        if not self.ctx.config.crawler.enabled:
            self.log.info("Crawler module is disabled by config.")
            return

        # 1. Define scope
        self._define_scope()
        if not self.scope_hosts:
            self.log.warning("Crawler could not determine scope. No hosts found from targets.")
            return

        # 1a. Setup headless browser if enabled
        if self.ctx.config.crawler.headless:
            if Browser is None:
                self.log.error(
                    "Headless mode requires 'playwright'. Please run `pip install playwright && playwright install`"
                )
                return
            self.log.info("Headless mode enabled. Launching browser...")
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)


        # 2. Seed the queue
        await self._seed_queue()

        # 3. Start crawling
        self.log.info(
            "Starting crawl (max_depth=%d, max_pages=%d) across %d workers.",
            self.ctx.config.crawler.max_depth,
            self.ctx.config.crawler.max_pages,
            self.ctx.config.network.max_concurrency,
        )
        workers = [
            asyncio.create_task(self._worker())
            for _ in range(self.ctx.config.network.max_concurrency)
        ]

        await self.queue.join()

        # All work is done, cancel workers
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await self.client.close()

        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.log.info("Crawl finished. Visited %d pages.", self.pages_crawled)

    def _define_scope(self) -> None:
        """Populate scope_hosts from initial targets."""
        for target in self.ctx.config.targets:
            try:
                host = urlparse(target.raw).hostname
                if host:
                    self.scope_hosts.add(host)
            except Exception:
                self.scope_hosts.add(target.raw)  # For non-URL targets

    async def _seed_queue(self) -> None:
        """Add initial URLs from the graph to the crawl queue."""
        # Find URLs that were validated by the prober
        service_roots = self.ctx.map.nodes_by_kind(NodeKind.url)
        for node in service_roots:
            if "service_root" in node.tags:
                await self.queue.put((node.label, 0))
                self.visited.add(node.label)

    async def _worker(self) -> None:
        while True:
            url, depth = await self.queue.get()
            try:
                if (
                    depth > self.ctx.config.crawler.max_depth
                    or self.pages_crawled >= self.ctx.config.crawler.max_pages
                ):
                    continue

                self.log.debug("Crawling (depth %d): %s", depth, url)

                if self.ctx.config.crawler.headless and self.browser:
                    page_content = await self._get_content_headless(url)
                else:
                    resp = await self.client.get(url)
                    content_type = resp.headers.get("content-type", "")
                    page_content = resp.text if "text/html" in content_type else None

                self.pages_crawled += 1

                if page_content:
                    await self._parse_html(url, page_content, depth)

            except Exception as e:
                self.log.debug("Failed to crawl %s: %s", url, e)
            finally:
                self.queue.task_done()

    async def _get_content_headless(self, url: str) -> str | None:
        if not self.browser:
            return None
        page = await self.browser.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            # TODO: Add logic for scrolling, clicking, etc. to trigger more JS loading
            return await page.content()
        finally:
            await page.close()

    async def _parse_html(self, base_url: str, html_content: str, depth: int) -> None:
        # Save content to cache for other modules
        try:
            cache_dir = self.ctx.workspace.cache_dir / "pages"
            cache_dir.mkdir(parents=True, exist_ok=True)
            filename = hashlib.sha256(base_url.encode()).hexdigest() + ".html"
            cache_path = cache_dir / filename
            cache_path.write_text(html_content, encoding="utf-8")
        except Exception as e:
            self.log.error("Failed to write page cache for %s: %s", base_url, e)

        soup = BeautifulSoup(html_content, "html.parser")
        base_url_node = self.ctx.map.upsert_node(
            kind=NodeKind.url,
            label=base_url,
            confidence=Confidence(score=0.8, rationale="Crawled"),
            tags=["crawled"])

        # Find script tags
        for script in soup.find_all("script", src=True):
            script_url = urljoin(base_url, script["src"])
            if script_url not in self.visited:
                self.log.info("Discovered script: %s", script_url)
                script_node = self.ctx.map.upsert_node(
                    kind=NodeKind.url,
                    label=script_url,
                    confidence=Confidence(score=0.9, rationale="Found in <script> tag"),
                    tags=["script"],
                    evidence=[Evidence(pointer=EvidencePointer(kind=EvidenceKind.html, url=base_url), excerpt=str(script))],
                )
                self.ctx.map.add_edge(src=base_url_node.id, dst=script_node.id, kind=EdgeKind.references, confidence=Confidence(score=1.0, rationale="Directly linked"))

        # Find anchor tags
        for link in soup.find_all("a", href=True):
            new_url = urljoin(base_url, link["href"]).split("#")[0]  # Normalize and remove fragment
            if new_url in self.visited:
                continue

            parsed_url = urlparse(new_url)
            if parsed_url.hostname and parsed_url.hostname in self.scope_hosts:
                self.visited.add(new_url)
                self.log.debug("Queuing new link: %s", new_url)
                await self.queue.put((new_url, depth + 1))