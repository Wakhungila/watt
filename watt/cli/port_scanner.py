from __future__ import annotations

import asyncio
import socket
from typing import List

from watt.models.entities import Confidence, NodeKind
from watt.modules.base import SimpleModule


class PortScanModule(SimpleModule):
    """
    Performs a simple asyncio-based connect scan on discovered hosts.
    """

    name = "recon.port_scanner"
    phase = "recon"

    async def run(self) -> None:
        self.log.info("Starting active port scan...")
        hosts = self.ctx.map.nodes_by_kind(NodeKind.host)

        if not hosts:
            self.log.info("No hosts to scan.")
            return

        ports_to_scan = self.ctx.config.recon.ports

        # Global semaphore to limit total concurrent connections
        sem = asyncio.Semaphore(100)
        
        # We can limit scanning to a subset if needed, but for now we scan all discovered hosts
        tasks = []
        for host in hosts:
            tasks.append(self._scan_host(host, sem))
        
        await asyncio.gather(*tasks)

    async def _scan_host(self, host_node, sem: asyncio.Semaphore) -> None:
        target = host_node.label
        open_ports = []

        # Create tasks for each port
        port_tasks = [self._check_port(target, port, sem) for port in self.ctx.config.recon.ports]
        results = await asyncio.gather(*port_tasks)

        for port, is_open in results:
            if is_open:
                open_ports.append(port)

        if open_ports:
            self.log.info("Open ports for %s: %s", target, open_ports)
            
            # Update host node
            self.ctx.map.upsert_node(
                kind=NodeKind.host,
                label=target,
                confidence=host_node.confidence,
                attrs={"open_ports": open_ports}
            )
            
            # Optionally create Service/URL nodes for http/https ports?
            # For now, we just enrich the host node.

    async def _check_port(self, host: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool]:
        async with sem:
            try:
                # Wait for 3 seconds max
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=3.0)
                writer.close()
                await writer.wait_closed()
                return port, True
            except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
                return port, False
            except Exception:
                return port, False