from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .evidence import Evidence


class NodeKind(str, Enum):
    target = "target"
    host = "host"
    url = "url"
    endpoint = "endpoint"
    parameter = "parameter"
    script = "script"
    service = "service"
    api = "api"
    graphql_operation = "graphql_operation"
    auth_surface = "auth_surface"
    integration = "integration"


class EdgeKind(str, Enum):
    extracted_from = "extracted_from"
    references = "references"
    calls = "calls"
    belongs_to = "belongs_to"
    variant_of = "variant_of"
    same_as = "same_as"


class Confidence(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    rationale: str = Field(..., max_length=500)


class HunterNode(BaseModel):
    """
    Canonical node stored in the Hunter Map.
    """

    id: str
    kind: NodeKind
    label: str
    tags: List[str] = Field(default_factory=list)
    confidence: Confidence
    evidence: List[Evidence] = Field(default_factory=list)
    attrs: Dict[str, Any] = Field(default_factory=dict)


class HunterEdge(BaseModel):
    """
    Canonical edge stored in the Hunter Map.
    """

    src: str
    dst: str
    kind: EdgeKind
    tags: List[str] = Field(default_factory=list)
    confidence: Confidence
    evidence: List[Evidence] = Field(default_factory=list)
    attrs: Dict[str, Any] = Field(default_factory=dict)


class FindingSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    """
    A ranked lead for human triage (NOT an auto-verified vulnerability).
    """

    id: str
    title: str
    summary: str
    severity: FindingSeverity = FindingSeverity.info
    score: float = Field(..., ge=0.0, le=100.0)
    tags: List[str] = Field(default_factory=list)
    related_nodes: List[str] = Field(default_factory=list)
    related_edges: List[Dict[str, str]] = Field(default_factory=list)  # {src,dst,kind}
    evidence: List[Evidence] = Field(default_factory=list)
    attrs: Dict[str, Any] = Field(default_factory=dict)

