from watt.graph.hunter_map import HunterMap
from watt.models.entities import Confidence, EdgeKind, NodeKind


def test_hunter_map_upsert_and_edge() -> None:
    hm = HunterMap()

    n1 = hm.upsert_node(
        kind=NodeKind.url,
        label="https://example.com/app.js",
        confidence=Confidence(score=0.9, rationale="operator supplied"),
        tags=["script"],
    )
    n2 = hm.upsert_node(
        kind=NodeKind.endpoint,
        label="GET https://api.example.com/v1/users",
        confidence=Confidence(score=0.7, rationale="extracted from JS"),
        tags=["hidden_endpoint"],
    )
    hm.add_edge(
        src=n1.id,
        dst=n2.id,
        kind=EdgeKind.references,
        confidence=Confidence(score=0.6, rationale="string literal match"),
        tags=["extracted_from_js"],
    )

    # Upsert merges tags and keeps best confidence
    n1b = hm.upsert_node(
        kind=NodeKind.url,
        label="https://example.com/app.js",
        confidence=Confidence(score=0.4, rationale="duplicate"),
        tags=["bundle"],
    )
    assert n1b.id == n1.id
    assert "bundle" in n1b.tags
    assert n1b.confidence.score == 0.9

    exported = hm.export_json()
    assert len(exported["nodes"]) == 2
    assert len(exported["edges"]) == 1

