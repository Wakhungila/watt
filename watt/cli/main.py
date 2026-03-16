from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from watt.core.config import WattConfig
from watt.core.controller import ScanController
from watt.core.module_registry import ModuleRegistry
from watt.graph.hunter_map import HunterMap
from watt.modules.recon.http_prober import HttpProberModule
from watt.modules.recon.passive_subdomains import PassiveSubdomainModule
from watt.modules.recon.cloud_scanner import CloudScanModule
from watt.modules.recon.dns_resolver import DnsResolverModule
from watt.modules.crawl.web_crawler import WebCrawlerModule
from watt.modules.intel.js_analyzer import JsIntelModule
from watt.modules.intel.ghost_endpoints import GhostEndpointModule
from watt.modules.intel.shadow_api import ShadowApiModule
from watt.modules.reporting.exporter import ReportingModule
from watt.modules.intel.sourcemap import SourceMapModule
from watt.modules.intel.secrets import SecretsModule
from watt.modules.analysis.subdomain_takeover import SubdomainTakeoverModule
from watt.modules.recon.cert_monitor import CertificateMonitorModule
from watt.modules.recon.port_scanner import PortScanModule
from watt.modules.recon.waf_detector import WafDetectorModule
from watt.modules.analysis.tech_fingerprinter import TechnologyFingerprinterModule
from watt.modules.recon.robots_txt import RobotsTxtModule
from watt.modules.analysis.source_leak import SourceLeakModule
from watt.modules.analysis.misconfiguration import MisconfigurationModule
from watt.modules.analysis.graphql_introspection import GraphqlIntrospectionModule
from watt.modules.analysis.nuclei_integration import NucleiIntegrationModule
from watt.modules.analysis.retirejs_integration import RetireJSIntegrationModule
from watt.modules.analysis.gitrob_integration import GitRobIntegrationModule


app = typer.Typer(help="WATT - Web Attack & Threat Telescope")
console = Console()

WATT_BANNER = r"""
                               
                               
██     ██ ▄████▄ ██████ ██████ 
██ ▄█▄ ██ ██▄▄██   ██     ██   
 ▀██▀██▀  ██  ██   ██     ██   
                               
Web Attack & Threat Telescope
"""


def _print_banner() -> None:
    console.print(f"[bold cyan]{WATT_BANNER}[/bold cyan]")


def _build_controller(
    targets: List[str],
    workspace: Path,
    log_level: str,
    json_logs: bool,
) -> ScanController:
    _print_banner()
    config = WattConfig.from_cli(
        targets=targets,
        workspace_root=workspace,
        log_level=log_level,
        json_logs=json_logs,
    )
    registry = ModuleRegistry()
    controller = ScanController(config=config, registry=registry)
    controller.initialize()

    # Build context and register core modules
    ctx = controller.build_module_context()
    
    # Load plugins from the workspace. This allows users to add their own modules.
    # Plugins are loaded before core modules, but registration order doesn't
    # imply execution order (which is phase-based).
    plugins_dir = workspace / "plugins"
    plugins_dir.mkdir(exist_ok=True)  # Ensure plugins directory exists
    registry.load_plugins(plugins_dir, ctx)
    
    # Phase: Recon
    registry.register(HttpProberModule(ctx))
    registry.register(PassiveSubdomainModule(ctx))
    registry.register(CloudScanModule(ctx))
    registry.register(DnsResolverModule(ctx))
    registry.register(CertificateMonitorModule(ctx))
    registry.register(PortScanModule(ctx))
    registry.register(WafDetectorModule(ctx))
    registry.register(RobotsTxtModule(ctx))
    
    # Phase: Crawl
    registry.register(WebCrawlerModule(ctx))

    # Phase: Intel
    registry.register(JsIntelModule(ctx))
    registry.register(SourceMapModule(ctx))
    registry.register(SecretsModule(ctx))

    # Phase: Analysis
    registry.register(GhostEndpointModule(ctx))
    registry.register(ShadowApiModule(ctx))
    registry.register(SubdomainTakeoverModule(ctx))
    registry.register(TechnologyFingerprinterModule(ctx))
    registry.register(SourceLeakModule(ctx))
    registry.register(MisconfigurationModule(ctx))
    registry.register(GraphqlIntrospectionModule(ctx))
    registry.register(NucleiIntegrationModule(ctx))
    registry.register(RetireJSIntegrationModule(ctx))
    registry.register(GitRobIntegrationModule(ctx))

    # Phase: Report
    registry.register(ReportingModule(ctx))
    # Note: CLI run command needs to default to running these phases if not specified

    return controller


@app.command("targets")
def show_targets(
    targets: List[str] = typer.Argument(..., help="Targets (domains, URLs, hosts) to ingest"),
    workspace: Path = typer.Option(
        Path("./watt-workspace"),
        "--workspace",
        "-w",
        help="Workspace directory for this run",
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level (e.g. INFO, DEBUG)"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Emit structured JSON logs"),
) -> None:
    """
    Ingest targets and display normalized view.

    This is the first tangible operator interaction and wires through
    the core configuration and workspace systems.
    """
    controller = _build_controller(
        targets=targets,
        workspace=workspace,
        log_level=log_level,
        json_logs=json_logs,
    )

    table = Table(title="WATT Target Ingestion")
    table.add_column("Raw", style="cyan")
    table.add_column("Kind", style="magenta")

    for t in controller.config.targets:
        table.add_row(t.raw, t.kind)

    console.print(table)


@app.command("run")
def run_all(
    targets: List[str] = typer.Argument(..., help="Targets (domains, URLs, hosts) to scan"),
    workspace: Path = typer.Option(
        Path("./watt-workspace"),
        "--workspace",
        "-w",
        help="Workspace directory for this run",
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level (e.g. INFO, DEBUG)"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Emit structured JSON logs"),
    phases: Optional[List[str]] = typer.Option(
        None,
        "--phase",
        "-p",
        help="Phases to run (default: all phases registered by modules)",
    ),
    diff: Optional[str] = typer.Option(
        None,
        "--diff",
        "-d",
        help="Compare results against a previous Run ID",
    ),
) -> None:
    """
    Entry point for running WATT phases.

    Phase 1 does not yet register concrete modules; this command
    primarily validates configuration, workspace, and controller wiring.
    """
    controller = _build_controller(
        targets=targets,
        workspace=workspace,
        log_level=log_level,
        json_logs=json_logs,
    )

    async def _runner() -> None:
        run_phases = phases
        if not phases:
            # If no phases are specified, run all registered phases in a sensible order.
            # This order is important for the data pipeline.
            all_known_phases = ["recon", "crawl", "intel", "analysis", "report"]
            run_phases = [
                p
                for p in all_known_phases
                if list(controller.registry.iter_by_phase(p))
            ]
            console.print(
                f"[cyan]No phases specified, running default sequence: {' -> '.join(run_phases)}[/cyan]"
            )

        if not run_phases:
            console.print("[yellow]No phases to run.[/yellow]")
            return

        await controller.run_all(run_phases)

        if diff:
            _run_diff(controller, diff)

    asyncio.run(_runner())


@app.command("resume")
def resume_scan(
    workspace: Path = typer.Option(
        Path("./watt-workspace"),
        "--workspace",
        "-w",
        help="Workspace directory to resume",
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level (e.g. INFO, DEBUG)"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Emit structured JSON logs"),
) -> None:
    """
    Resume the last scan run in the workspace.
    """
    # 1. Find the last run configuration
    config_path = workspace / "config.json"
    if not config_path.exists():
        console.print(f"[bold red]Error:[/] No configuration found in {workspace}. Cannot resume.")
        raise typer.Exit(code=1)

    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
        # We need to reconstruct the config object.
        # Note: We are re-using the targets from the original run.
        # If run_id was set in the original config, we might want to reuse it or rely on controller state.
        
        # Re-instantiate from the saved config to ensure consistent settings
        config = WattConfig(**config_data)
        
        # Override logging settings from current CLI args if provided? 
        # For now, let's respect the CLI args for logging visibility.
        config.logging.level = log_level.upper()
        config.logging.json_logs = json_logs
        
    except Exception as e:
        console.print(f"[bold red]Error:[/] Failed to load previous config: {e}")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Resuming run with {len(config.targets)} targets...[/cyan]")
    
    # 2. Invoke the runner logic
    # We delegate to the same logic as 'run', but passing the reconstituted config
    # is slightly complex with the current _build_controller helper which takes raw args.
    # So we'll bypass _build_controller and construct manually.
    
    _print_banner()
    registry = ModuleRegistry()
    controller = ScanController(config=config, registry=registry)
    controller.initialize()

    # Build context and register core modules (DUPLICATED LOGIC - should refactor in real app)
    ctx = controller.build_module_context()
    plugins_dir = workspace / "plugins"
    if plugins_dir.exists():
         registry.load_plugins(plugins_dir, ctx)

    # Phase: Recon
    registry.register(HttpProberModule(ctx))
    registry.register(PassiveSubdomainModule(ctx))
    registry.register(CloudScanModule(ctx))
    registry.register(DnsResolverModule(ctx))
    registry.register(CertificateMonitorModule(ctx))
    registry.register(PortScanModule(ctx))
    registry.register(WafDetectorModule(ctx))
    registry.register(RobotsTxtModule(ctx))
    
    # Phase: Crawl
    registry.register(WebCrawlerModule(ctx))

    # Phase: Intel
    registry.register(JsIntelModule(ctx))
    registry.register(SourceMapModule(ctx))
    registry.register(SecretsModule(ctx))

    # Phase: Analysis
    registry.register(GhostEndpointModule(ctx))
    registry.register(ShadowApiModule(ctx))
    registry.register(SubdomainTakeoverModule(ctx))
    registry.register(TechnologyFingerprinterModule(ctx))
    registry.register(SourceLeakModule(ctx))
    registry.register(MisconfigurationModule(ctx))
    registry.register(GraphqlIntrospectionModule(ctx))
    registry.register(NucleiIntegrationModule(ctx))

    # Phase: Report
    registry.register(ReportingModule(ctx))

    async def _runner() -> None:
        all_known_phases = ["recon", "crawl", "intel", "analysis", "report"]
        run_phases = [
            p
            for p in all_known_phases
            if list(controller.registry.iter_by_phase(p))
        ]
        await controller.run_all(run_phases)

    asyncio.run(_runner())


@app.command("findings")
def list_findings(
    workspace: Path = typer.Option(
        Path("./watt-workspace"),
        "--workspace",
        "-w",
        help="Workspace directory to read findings from",
    ),
) -> None:
    """
    List findings from a completed run.
    """
    report_path = workspace / "hunter_map.json"
    if not report_path.exists():
        console.print(f"[bold red]Error:[/] Report file not found at {report_path}")
        console.print("Please run a scan first or specify the correct workspace.")
        raise typer.Exit(code=1)

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/] Could not parse report file at {report_path}")
        raise typer.Exit(code=1)

    if not findings:
        console.print("[yellow]No findings in report.[/yellow]")
        return

    table = Table(title="WATT Findings")
    table.add_column("Severity", style="cyan", justify="right")
    table.add_column("Score", style="magenta", justify="right")
    table.add_column("Title", style="green")

    findings.sort(key=lambda f: f.get("score", 0), reverse=True)

    for f in findings:
        severity = f.get("severity", "info")
        color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "blue"}.get(severity, "white")
        table.add_row(f"[{color}]{severity.upper()}[/{color}]", f"{f.get('score', 0):.1f}", f.get("title", "N/A"))

    console.print(table)


@app.command("graph")
def export_graph(
    workspace: Path = typer.Option(
        Path("./watt-workspace"),
        "--workspace",
        "-w",
        help="Workspace directory to read database from",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Output path for the GraphML file (e.g., map.graphml)",
    ),
) -> None:
    """
    Export the attack surface graph to GraphML for visualization.
    """
    console.print(f"Reading database from workspace: {workspace}")
    db_path = workspace / "watt.sqlite"
    if not db_path.exists():
        console.print(f"[bold red]Error:[/] Database file not found at {db_path}")
        console.print("Please run a scan first or specify the correct workspace.")
        raise typer.Exit(code=1)

    try:
        hunter_map = HunterMap(db_path=db_path)
        hunter_map.write_graphml(output)
        console.print(f"[bold green]Success![/bold green] Graph exported to {output}")
    except ImportError as e:
        console.print(
            f"[bold red]Error:[/] Missing dependency for graph export: {e}"
        )
        console.print("Please run `pip install networkx` to enable this feature.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An error occurred during export: {e}[/bold red]")
        raise typer.Exit(code=1)


def _run_diff(controller: ScanController, prev_run_id: str) -> None:
    """
    Compare current run results with a previous run.
    """
    console.rule("[bold]Differential Analysis[/bold]")
    
    current_path = controller.workspace.root / "hunter_map.json"
    prev_path = controller.workspace.root / "runs" / prev_run_id / "hunter_map.json"

    if not prev_path.exists():
        console.print(f"[bold red]Previous run report not found:[/bold red] {prev_path}")
        return

    try:
        curr_data = json.loads(current_path.read_text(encoding="utf-8"))
        prev_data = json.loads(prev_path.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Failed to load reports for diff: {e}[/red]")
        return

    # Diff Findings (by Title)
    curr_titles = {f["title"] for f in curr_data.get("findings", [])}
    prev_titles = {f["title"] for f in prev_data.get("findings", [])}
    new_findings = curr_titles - prev_titles

    if new_findings:
        console.print(f"[bold green]+ {len(new_findings)} New Findings[/bold green]")
        for title in sorted(new_findings):
            console.print(f"  [green]+ {title}[/green]")
    else:
        console.print("[dim]No new findings compared to previous run.[/dim]")

    # Diff Stats
    curr_nodes = len(curr_data.get("graph", {}).get("nodes", []))
    prev_nodes = len(prev_data.get("graph", {}).get("nodes", []))
    diff_nodes = curr_nodes - prev_nodes
    sign = "+" if diff_nodes >= 0 else ""
    console.print(f"\n[bold]Graph Growth:[/bold] {prev_nodes} -> {curr_nodes} nodes ({sign}{diff_nodes})")


if __name__ == "__main__":
    app()
