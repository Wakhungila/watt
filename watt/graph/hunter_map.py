from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

try:
    import networkx as nx
except ImportError:
    nx = None

from watt.core.logging import get_logger
from watt.models.entities import (
    Confidence,
    EdgeKind,
    Finding,
    HunterEdge,
    HunterNode,
    NodeKind,
)


@dataclass(frozen=True)
class NodeKey:
    kind: NodeKind
    label: str


class HunterMap:
    """
    Relationship graph for WATT, backed by a persistent SQLite database.

    Implementation notes:
    - Provides stable IDs and de-duplication by (kind, label) via UNIQUE constraints.
    - Complex attributes (tags, confidence, evidence, attrs) are stored as JSON text.
    - Methods reconstruct Pydantic models from database rows on query.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        # `check_same_thread=False` is safe for our async/concurrent model where
        # each module action is short-lived and doesn't hold long transactions.
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._findings: List[Finding] = []
        self._logger = get_logger(__name__)
        self._create_schema()

    def _create_schema(self) -> None:
        """
        Initializes the database schema if it doesn't exist.
        """
        cursor = self._conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                tags TEXT,
                confidence TEXT,
                evidence TEXT,
                attrs TEXT,
                UNIQUE(kind, label)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS edges (
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                kind TEXT NOT NULL,
                tags TEXT,
                confidence TEXT,
                evidence TEXT,
                attrs TEXT,
                PRIMARY KEY (src, dst, kind)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT,
                score REAL,
                tags TEXT,
                related_nodes TEXT,
                related_edges TEXT,
                evidence TEXT,
                attrs TEXT
            );
            """
        )
        self._conn.commit()

    def _row_to_node(self, row: sqlite3.Row) -> HunterNode:
        return HunterNode(
            id=row["id"],
            kind=NodeKind(row["kind"]),
            label=row["label"],
            tags=json.loads(row["tags"] or "[]"),
            confidence=Confidence.model_validate(json.loads(row["confidence"] or "{}")),
            evidence=[Evidence.model_validate(e) for e in json.loads(row["evidence"] or "[]")],
            attrs=json.loads(row["attrs"] or "{}"),
        )

    def _row_to_edge(self, row: sqlite3.Row) -> HunterEdge:
        return HunterEdge(
            src=row["src"],
            dst=row["dst"],
            kind=EdgeKind(row["kind"]),
            tags=json.loads(row["tags"] or "[]"),
            confidence=Confidence.model_validate(json.loads(row["confidence"] or "{}")),
            evidence=[Evidence.model_validate(e) for e in json.loads(row["evidence"] or "[]")],
            attrs=json.loads(row["attrs"] or "{}"),
        )

    def upsert_node(
        self,
        *,
        kind: NodeKind,
        label: str,
        confidence: Confidence,
        tags: Optional[List[str]] = None,
        attrs: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Evidence]] = None,
    ) -> HunterNode:
        node_id = self._make_node_id(kind, label)
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO nodes (id, kind, label, tags, confidence, evidence, attrs)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, label) DO UPDATE SET
                tags = json_insert(
                    tags,
                    '$.' || json_array_length(tags),
                    json_extract(excluded.tags, '$[0]')
                ),
                evidence = json_insert(
                    evidence,
                    '$.' || json_array_length(evidence),
                    json_extract(excluded.evidence, '$[0]')
                ),
                confidence = CASE
                    WHEN json_extract(excluded.confidence, '$.score') > json_extract(confidence, '$.score')
                    THEN excluded.confidence
                    ELSE confidence
                END
            """,
            (
                node_id,
                kind.value,
                label,
                json.dumps(tags or []),
                confidence.model_dump_json(),
                json.dumps([e.model_dump() for e in evidence] if evidence else []),
                json.dumps(attrs or {}),
            ),
        )
        self._conn.commit()

        # Fetch the final state of the node
        cursor.execute("SELECT * FROM nodes WHERE id = ?", (node_id,))
        row = cursor.fetchone()
        return self._row_to_node(row)

    def add_edge(
        self,
        *,
        src: str,
        dst: str,
        kind: EdgeKind,
        confidence: Confidence,
        tags: Optional[List[str]] = None,
        attrs: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Evidence]] = None,
    ) -> HunterEdge:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO edges (src, dst, kind, tags, confidence, evidence, attrs)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(src, dst, kind) DO NOTHING
            """,
            (
                src,
                dst,
                kind.value,
                json.dumps(tags or []),
                confidence.model_dump_json(),
                json.dumps([e.model_dump() for e in evidence] if evidence else []),
                json.dumps(attrs or {}),
            ),
        )
        self._conn.commit()
        return HunterEdge(src=src, dst=dst, kind=kind, confidence=confidence, tags=tags or [], attrs=attrs or {}, evidence=evidence or [])

    def nodes_by_kind(self, kind: NodeKind) -> List[HunterNode]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM nodes WHERE kind = ?", (kind.value,))
        return [self._row_to_node(row) for row in cursor.fetchall()]

    def edges_by_kind(self, kind: EdgeKind) -> List[HunterEdge]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM edges WHERE kind = ?", (kind.value,))
        return [self._row_to_edge(row) for row in cursor.fetchall()]

    def get_all_edges(self) -> List[HunterEdge]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM edges")
        return [self._row_to_edge(row) for row in cursor.fetchall()]

    def add_finding(self, finding: Finding) -> None:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (id, title, summary, severity, score, tags, related_nodes, related_edges, evidence, attrs)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET title=excluded.title, summary=excluded.summary
            """,
            (
                finding.id,
                finding.title,
                finding.summary,
                finding.severity.value,
                finding.score,
                json.dumps(finding.tags),
                json.dumps(finding.related_nodes),
                json.dumps(finding.related_edges),
                json.dumps([e.model_dump() for e in finding.evidence]),
                json.dumps(finding.attrs),
            ),
        )
        self._conn.commit()
        self._logger.info("Added finding: %s", finding.title)

    def get_all_findings(self) -> List[Finding]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM findings")
        return [Finding.model_validate(dict(row)) for row in cursor.fetchall()]

    def write_graphml(self, path: Path) -> None:
        """
        GraphML export for Gephi / yEd workflows.
        """
        if nx is None:
            self._logger.error("networkx is not installed. Please run `pip install networkx`")
            raise ImportError("networkx library is required for GraphML export.")

        g = nx.MultiDiGraph()
        cursor = self._conn.cursor()

        # Add nodes
        cursor.execute("SELECT * FROM nodes")
        for row in cursor.fetchall():
            model = self._row_to_node(row)
            g.add_node(
                model.id,
                kind=model.kind.value,
                label=model.label,
                tags=",".join(model.tags),
                confidence=float(model.confidence.score),
                model_json=json.dumps(model.model_dump(mode="json")),
            )

        # Add edges
        cursor.execute("SELECT * FROM edges")
        for row in cursor.fetchall():
            model = self._row_to_edge(row)
            g.add_edge(
                model.src,
                model.dst,
                key=self._edge_key(model.src, model.dst, model.kind),
                kind=model.kind.value,
                tags=",".join(model.tags),
                confidence=float(model.confidence.score),
                model_json=json.dumps(model.model_dump(mode="json")),
            )

        nx.write_graphml(g, path)
        self._logger.info("Wrote GraphML to %s", path)

    # ---------------- internal helpers ----------------

    def _make_node_id(self, kind: NodeKind, label: str) -> str:
        # Stable-enough IDs for a single workspace; persistence layer will
        # optionally replace this with deterministic IDs based on hashing.
        base = f"{kind.value}:{label}"
        return f"n_{abs(hash(base))}"

    def _edge_key(self, src: str, dst: str, kind: EdgeKind) -> str:
        return f"{kind.value}:{src}->{dst}"
