from __future__ import annotations

import asyncio
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule
from watt.utils.network import SmartClient


class GraphqlIntrospectionModule(SimpleModule):
    """
    Checks GraphQL endpoints for enabled introspection.
    """

    name = "analysis.graphql_introspection"
    phase = "analysis"

    # Standard introspection query to check if schema is exposed
    INTROSPECTION_QUERY = {
        "query": """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
            }
          }
        }
        """
    }

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.client = SmartClient(ctx.config.network)

    async def run(self) -> None:
        self.log.info("Checking for GraphQL Introspection...")
        
        # Find potential GraphQL endpoints from the graph
        # 1. Endpoints tagged with 'graphql'
        # 2. URLs that look like graphql endpoints
        candidates = set()
        
        url_nodes = self.ctx.map.nodes_by_kind(NodeKind.url)
        for node in url_nodes:
            if "graphql" in node.label.lower() or "graphql" in node.tags:
                candidates.add(node)
        
        # Also check endpoints discovered by ShadowApiModule or others
        endpoint_nodes = self.ctx.map.nodes_by_kind(NodeKind.endpoint)
        for node in endpoint_nodes:
             if "graphql" in node.label.lower():
                 # Note: Endpoint nodes are relative paths usually, we need to resolve them to a host
                 # For simplicity in this pass, we focus on absolute URLs found.
                 # A more complex implementation would trace back the host edge.
                 pass

        tasks = [self._check_introspection(node) for node in candidates]
        if tasks:
            await asyncio.gather(*tasks)
        
        await self.client.close()

    async def _check_introspection(self, node) -> None:
        try:
            resp = await self.client._request("POST", node.label, content=self.INTROSPECTION_QUERY)
            if resp.status_code == 200 and "queryType" in resp.text and "__schema" in resp.text:
                self._report_finding(node)
        except Exception:
            pass

    def _report_finding(self, node) -> None:
        self.log.warning("GraphQL Introspection Enabled: %s", node.label)
        self.ctx.map.add_finding(Finding(
            id=str(uuid.uuid4()),
            title="GraphQL Introspection Enabled",
            summary=f"The GraphQL endpoint at {node.label} has introspection enabled, allowing full schema extraction.",
            severity=FindingSeverity.medium,
            score=60.0,
            tags=["graphql", "introspection", "schema_exposure"],
            related_nodes=[node.id],
        ))