from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EvidenceKind(str, Enum):
    artifact = "artifact"
    js = "js"
    sourcemap = "sourcemap"
    har = "har"
    sitemap = "sitemap"
    openapi = "openapi"
    url_list = "url_list"
    manual = "manual"


class EvidencePointer(BaseModel):
    """
    Points to where a piece of intelligence came from.

    The pointer is designed to be traceable without requiring WATT to
    store full raw artifacts inline.
    """

    kind: EvidenceKind
    artifact_id: Optional[str] = Field(default=None, description="Workspace artifact identifier")
    path: Optional[str] = Field(default=None, description="Original file path (if local ingest)")
    url: Optional[str] = Field(default=None, description="Original URL (if supplied)")
    sha256: Optional[str] = Field(default=None, description="Hash of the source content, if available")

    line_start: Optional[int] = None
    line_end: Optional[int] = None
    byte_start: Optional[int] = None
    byte_end: Optional[int] = None

    note: Optional[str] = Field(default=None, description="Operator-friendly explanation")


class Evidence(BaseModel):
    """
    A single evidence record supporting a discovered claim.
    """

    pointer: EvidencePointer
    excerpt: Optional[str] = Field(
        default=None,
        description="A short excerpt (sanitized) that supports the claim",
        max_length=4000,
    )
    captured_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    parser: str = Field(..., description="Component that produced this evidence, e.g. jsintel.regex")
    parse_warnings: List[str] = Field(default_factory=list)

    extra: Dict[str, Any] = Field(default_factory=dict)

