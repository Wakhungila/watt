from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl, TypeAdapter, model_validator


class Target(BaseModel):
    """
    Canonical representation of a scan target.

    Phase 1 keeps this intentionally simple; later phases can extend
    this model (e.g. with org identifiers, scopes, labels).
    """

    raw: str = Field(..., description="Raw target string as provided by the operator")
    kind: str = Field(..., description="Target kind: domain|subdomain|url|api_host|org")


class NetworkSettings(BaseModel):
    timeout: float = Field(10.0, ge=1.0, le=120.0)
    max_concurrency: int = Field(20, ge=1, le=1024)
    retry_attempts: int = Field(3, ge=0, le=10)
    retry_backoff_base: float = Field(0.5, ge=0.1, le=10.0)
    max_redirects: int = Field(10, ge=0, le=50)
    user_agent: str = Field(
        "WATT/0.1 (authorized research; contact: security@watt.local)",
        max_length=200,
    )
    honor_retry_after: bool = Field(
        True,
        description="Respect Retry-After on 429/503 responses",
    )
    per_host_max_concurrency: int = Field(
        4,
        ge=1,
        le=64,
        description="Limit concurrent requests per host to reduce rate-limit pressure",
    )
    rate_limit_cooldown_s: float = Field(
        30.0,
        ge=1.0,
        le=3600.0,
        description="Cooldown after rate-limit signal when Retry-After absent",
    )
    requests_per_second: float = Field(
        0.0,
        ge=0.0,
        le=1000.0,
        description="Global rate limit in requests per second (0 = unlimited)",
    )


class CrawlerSettings(BaseModel):
    enabled: bool = Field(True, description="Enable the web crawler module.")
    max_depth: int = Field(3, ge=1, le=20, description="Maximum link depth to crawl from a seed URL.")
    max_pages: int = Field(500, ge=10, le=10000, description="Maximum number of pages to crawl per run.")
    headless: bool = Field(
        False,
        description="Use headless browser for SPA crawling (requires Playwright). Not implemented in this version.",
    )


class WorkspaceSettings(BaseModel):
    root: Path = Field(..., description="Workspace root directory where state is stored")
    run_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional logical run identifier. When provided, allows resuming"
            " scans and correlating multiple phases."
        ),
    )

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def database_path(self) -> Path:
        return self.root / "watt.sqlite"


class LoggingSettings(BaseModel):
    level: str = Field("INFO", description="Log level name")
    json_logs: bool = Field(False, description="Emit logs as structured JSON")
    rich: bool = Field(True, description="Enable rich console logging")


class ApiKeys(BaseModel):
    virustotal: Optional[str] = Field(None, description="VirusTotal API Key")
    securitytrails: Optional[str] = Field(None, description="SecurityTrails API Key")
    chaos: Optional[str] = Field(None, description="ProjectDiscovery Chaos API Key")
    github: Optional[str] = Field(None, description="GitHub API Key for OSINT tools")


class ReconSettings(BaseModel):
    ports: List[int] = Field(
        default=[80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000],
        description="List of ports to scan in the port_scanner module.",
    )


class AnalysisSettings(BaseModel):
    nuclei_templates: List[str] = Field(
        default=[],
        description="List of custom Nuclei template directories or files to use.",
    )


class WattConfig(BaseModel):
    """
    Root configuration object for a WATT run.

    This is the single source of truth for configuration and is intended
    to be:
    - serializable to/from JSON/YAML
    - stable across versions via explicit fields
    """

    targets: List[Target] = Field(..., min_length=1)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    workspace: WorkspaceSettings
    crawler: CrawlerSettings = Field(default_factory=CrawlerSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    api_keys: ApiKeys = Field(default_factory=ApiKeys)
    recon: ReconSettings = Field(default_factory=ReconSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)

    @model_validator(mode="after")
    def _validate_targets(self) -> "WattConfig":
        if not self.targets:
            raise ValueError("At least one target must be provided")
        return self

    @classmethod
    def from_cli(
        cls,
        targets: List[str],
        workspace_root: Path,
        log_level: str = "INFO",
        json_logs: bool = False,
    ) -> "WattConfig":
        """
        Convenience constructor for CLI invocations.

        Performs minimal normalization of targets and wires workspace + logging.
        """
        normalized_targets: List[Target] = []
        for raw in targets:
            normalized_targets.append(Target(raw=raw, kind=_infer_target_kind(raw)))

        ws = WorkspaceSettings(root=workspace_root)
        logging_settings = LoggingSettings(level=log_level.upper(), json_logs=json_logs)
        return cls(targets=normalized_targets, workspace=ws, logging=logging_settings)


def _infer_target_kind(raw: str) -> str:
    """
    Heuristic to infer the target kind from the raw string.

    This is intentionally simple in Phase 1 and will be refined
    in later phases.
    """
    value = raw.strip()
    if "://" in value:
        # URL or API URL
        try:
            TypeAdapter(HttpUrl).validate_python(value)
        except Exception:
            return "url"  # best effort; validation will happen elsewhere
        return "url"

    if "/" in value:
        # Could be a path-only or malformed URL. Treat as org id-like for now.
        return "org"

    # Domain vs subdomain: extremely naive heuristic
    parts = value.split(".")
    if len(parts) <= 2:
        return "domain"
    return "subdomain"
