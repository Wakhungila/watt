from __future__ import annotations

import json
import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from watt.modules.base import SimpleModule
from watt.models.entities import NodeKind


class ReportingModule(SimpleModule):
    """
    Exports the Hunter Map and findings to structured formats (JSON, HTML).
    """

    name = "reporting.exporter"
    phase = "report"

    async def run(self) -> None:
        self.log.info("Starting reporting phase...")
        
        # Gather data from the map
        # Assuming HunterMap exposes methods to get all data or we iterate kinds
        nodes = []
        for kind in NodeKind:
            nodes.extend(self.ctx.map.nodes_by_kind(kind))
            
        edges = self.ctx.map.get_all_edges() if hasattr(self.ctx.map, "get_all_edges") else []
        findings = self.ctx.map.get_all_findings() if hasattr(self.ctx.map, "get_all_findings") else []

        # 1. Export JSON
        await self._export_json(nodes, edges, findings)

        # 2. Export HTML
        await self._export_html(nodes, edges, findings)

        self.log.info("Reporting complete. Artifacts in %s", self.ctx.workspace.root)

    async def _export_json(self, nodes: List[Any], edges: List[Any], findings: List[Any]) -> None:
        data = {
            "meta": {
                "generated_at": datetime.utcnow().isoformat(),
                "targets": [t.raw for t in self.ctx.config.targets],
                "run_id": self.ctx.config.workspace.run_id,
            },
            "stats": {
                "nodes": len(nodes),
                "edges": len(edges),
                "findings": len(findings),
            },
            "findings": [f.model_dump(mode="json") for f in findings],
            "graph": {
                "nodes": [n.model_dump(mode="json") for n in nodes],
                "edges": [e.model_dump(mode="json") for e in edges],
            }
        }
        
        outfile = self.ctx.workspace.root / "hunter_map.json"
        outfile.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.log.info("Wrote JSON report to %s", outfile)

        # Archive to run directory if run_id is present
        if self.ctx.config.workspace.run_id:
            run_dir = self.ctx.workspace.runs_dir / self.ctx.config.workspace.run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            run_outfile = run_dir / "hunter_map.json"
            run_outfile.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.log.info("Archived report to %s", run_outfile)

    async def _export_html(self, nodes: List[Any], edges: List[Any], findings: List[Any]) -> None:
        outfile = self.ctx.workspace.root / "hunter_report.html"
        
        # Simple HTML Template
        rows = []
        for f in findings:
            rows.append(f"""
            <tr class="severity-{f.severity}">
                <td><span class="badge {f.severity}">{f.severity.upper()}</span></td>
                <td>{html.escape(f.title)}</td>
                <td>{html.escape(f.summary)}</td>
                <td>{f.score}</td>
            </tr>
            """)
        
        findings_html = "\n".join(rows) if rows else "<tr><td colspan='4'>No findings generated yet.</td></tr>"

        template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WATT Hunter Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #111; color: #eee; }}
        h1, h2 {{ color: #00ff9d; }}
        .stats {{ display: flex; gap: 2rem; margin-bottom: 2rem; }}
        .stat-box {{ background: #222; padding: 1rem; border-radius: 4px; border: 1px solid #333; }}
        .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ text-align: left; border-bottom: 2px solid #444; padding: 0.5rem; }}
        td {{ border-bottom: 1px solid #333; padding: 0.5rem; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; color: #000; }}
        .badge.critical {{ background: #ff0055; color: white; }}
        .badge.high {{ background: #ff5500; color: white; }}
        .badge.medium {{ background: #ffaa00; }}
        .badge.low {{ background: #ffff00; }}
        .badge.info {{ background: #00aaff; }}
    </style>
</head>
<body>
    <h1>WATT Hunter Report</h1>
    <div class="stats">
        <div class="stat-box"><div>Nodes</div><div class="stat-value">{len(nodes)}</div></div>
        <div class="stat-box"><div>Edges</div><div class="stat-value">{len(edges)}</div></div>
        <div class="stat-box"><div>Findings</div><div class="stat-value">{len(findings)}</div></div>
    </div>
    
    <h2>Findings</h2>
    <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Summary</th><th>Score</th></tr></thead>
        <tbody>{findings_html}</tbody>
    </table>
</body></html>"""

        outfile.write_text(template, encoding="utf-8")
        self.log.info("Wrote HTML report to %s", outfile)