"""Tests for FindingGraph and AttackPathFinder."""

import json
import pytest
from src.graph import (
    FindingGraph, AttackPathFinder,
    NetworkNode, ServiceNode, VulnerabilityNode, ExploitNode, FindingEdge,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def graph(tmp_path):
    return FindingGraph(
        session_id="test",
        wal_path=tmp_path / "graph.wal",
        json_path=tmp_path / "graph.json",
    )


@pytest.fixture
def nmap_meta():
    return {
        "hosts": [
            {"ip": "192.168.1.50", "hostname": "target.local"},
            {"ip": "192.168.1.51", "hostname": ""},
        ],
        "open_ports": [
            {"host": "192.168.1.50", "port": 22, "protocol": "tcp",
             "service": "ssh", "product": "OpenSSH", "version": "7.4"},
            {"host": "192.168.1.50", "port": 80, "protocol": "tcp",
             "service": "http", "product": "Apache", "version": "2.4.49"},
            {"host": "192.168.1.51", "port": 3306, "protocol": "tcp",
             "service": "mysql", "product": "MySQL", "version": "5.7"},
        ],
        "os_matches": [{"host": "192.168.1.50", "os": "Linux", "accuracy": 95}],
    }


@pytest.fixture
def attack_graph(tmp_path):
    """Graph with all three attack path states."""
    g = FindingGraph(session_id="t", wal_path=tmp_path / "g.wal")

    # Host 1 — complete chain
    net1 = NetworkNode(ip="192.168.1.50")
    svc1 = ServiceNode(host="192.168.1.50", port=80, service="http",
                       product="Apache", version="2.4.49")
    vuln1 = VulnerabilityNode(cve_id="CVE-2021-41773",
                              description="Path traversal", cvss_score=9.8)
    exp1 = ExploitNode(title="Apache 2.4.49 Path Traversal RCE")
    g.add_node(net1); g.add_node(svc1); g.add_node(vuln1); g.add_node(exp1)
    g.add_edge(FindingEdge(source_id=net1.node_id, target_id=svc1.node_id,
                           relationship="has_service"))
    g.add_edge(FindingEdge(source_id=svc1.node_id, target_id=vuln1.node_id,
                           relationship="has_vulnerability"))
    g.add_edge(FindingEdge(source_id=vuln1.node_id, target_id=exp1.node_id,
                           relationship="has_exploit"))

    # Host 2 — partial_known_gap (vuln but no exploit)
    net2 = NetworkNode(ip="192.168.1.51")
    svc2 = ServiceNode(host="192.168.1.51", port=22, service="ssh",
                       product="OpenSSH", version="7.4")
    vuln2 = VulnerabilityNode(cve_id="CVE-2023-38408",
                              description="OpenSSH vuln", cvss_score=7.5)
    g.add_node(net2); g.add_node(svc2); g.add_node(vuln2)
    g.add_edge(FindingEdge(source_id=net2.node_id, target_id=svc2.node_id,
                           relationship="has_service"))
    g.add_edge(FindingEdge(source_id=svc2.node_id, target_id=vuln2.node_id,
                           relationship="has_vulnerability"))

    # Host 3 — partial_unknown_gap (service but no vuln)
    net3 = NetworkNode(ip="192.168.1.52")
    svc3 = ServiceNode(host="192.168.1.52", port=3306, service="mysql",
                       product="MySQL", version="5.7.38")
    g.add_node(net3); g.add_node(svc3)
    g.add_edge(FindingEdge(source_id=net3.node_id, target_id=svc3.node_id,
                           relationship="has_service"))

    return g


# ---------------------------------------------------------------------------
# Nodes and Edges
# ---------------------------------------------------------------------------

def test_add_all_node_types(graph):
    graph.add_node(NetworkNode(ip="192.168.1.50"))
    graph.add_node(ServiceNode(host="192.168.1.50", port=22, service="ssh"))
    graph.add_node(VulnerabilityNode(cve_id="CVE-2021-41773", description="test"))
    graph.add_node(ExploitNode(title="Apache RCE"))

    assert len(graph.get_network_nodes()) == 1
    assert len(graph.get_service_nodes()) == 1
    assert len(graph.get_vulnerability_nodes()) == 1
    assert len(graph.get_exploit_nodes()) == 1


def test_edge_traversal_network_to_service(graph):
    net = NetworkNode(ip="192.168.1.50")
    svc = ServiceNode(host="192.168.1.50", port=22, service="ssh")
    graph.add_node(net)
    graph.add_node(svc)
    graph.add_edge(FindingEdge(source_id=net.node_id, target_id=svc.node_id,
                               relationship="has_service"))

    neighbors = graph.get_neighbors(net.node_id, "has_service")
    assert len(neighbors) == 1
    assert neighbors[0].port == 22


def test_wal_entries(tmp_path):
    g = FindingGraph(session_id="t", wal_path=tmp_path / "g.wal")
    net = NetworkNode(ip="192.168.1.50")
    svc = ServiceNode(host="192.168.1.50", port=22)
    vuln = VulnerabilityNode(description="test")
    exp = ExploitNode(title="test")
    g.add_node(net); g.add_node(svc); g.add_node(vuln); g.add_node(exp)
    g.add_edge(FindingEdge(source_id=net.node_id, target_id=svc.node_id,
                           relationship="has_service"))
    g.add_edge(FindingEdge(source_id=svc.node_id, target_id=vuln.node_id,
                           relationship="has_vulnerability"))
    g.add_edge(FindingEdge(source_id=vuln.node_id, target_id=exp.node_id,
                           relationship="has_exploit"))

    lines = (tmp_path / "g.wal").read_text(encoding="utf-8").strip().split("\n")
    events = [json.loads(l)["event"] for l in lines]
    assert events.count("node_added") == 4
    assert events.count("edge_added") == 3


# ---------------------------------------------------------------------------
# Nmap Ingestion
# ---------------------------------------------------------------------------

def test_nmap_ingestion_node_counts(graph, nmap_meta):
    created = graph.add_nmap_result(nmap_meta)
    assert len(graph.get_network_nodes()) == 2
    assert len(graph.get_service_nodes()) == 3
    assert len(created) == 5


def test_nmap_no_duplicates_on_re_ingest(graph, nmap_meta):
    graph.add_nmap_result(nmap_meta)
    graph.add_nmap_result(nmap_meta)
    assert len(graph.get_network_nodes()) == 2
    assert len(graph.get_service_nodes()) == 3


def test_nmap_service_edges(graph, nmap_meta):
    graph.add_nmap_result(nmap_meta)
    net = next(n for n in graph.get_network_nodes() if n.ip == "192.168.1.50")
    assert len(graph.get_neighbors(net.node_id, "has_service")) == 2


def test_summary_for_llm_contains_hosts_and_ports(graph, nmap_meta):
    graph.add_nmap_result(nmap_meta)
    summary = graph.summary_for_llm()
    assert "192.168.1.50" in summary
    assert "22" in summary


# ---------------------------------------------------------------------------
# WAL Persistence and Checkpoint
# ---------------------------------------------------------------------------

def test_wal_written_before_checkpoint(tmp_path):
    g = FindingGraph(session_id="t",
                     wal_path=tmp_path / "g.wal",
                     json_path=tmp_path / "g.json")
    g.add_node(NetworkNode(ip="192.168.1.50"))
    assert (tmp_path / "g.wal").exists()
    assert not (tmp_path / "g.json").exists()


def test_checkpoint_materializes_json(tmp_path):
    g = FindingGraph(session_id="t",
                     wal_path=tmp_path / "g.wal",
                     json_path=tmp_path / "g.json")
    g.add_node(NetworkNode(ip="192.168.1.50"))
    g.add_node(ServiceNode(host="192.168.1.50", port=22))
    g.checkpoint()
    data = json.loads((tmp_path / "g.json").read_text(encoding="utf-8"))
    assert len(data["nodes"]) == 2


def test_resume_from_checkpoint(tmp_path):
    g1 = FindingGraph(session_id="t",
                      wal_path=tmp_path / "g.wal",
                      json_path=tmp_path / "g.json")
    g1.add_node(NetworkNode(ip="192.168.1.50"))
    g1.checkpoint()

    g2 = FindingGraph(session_id="t",
                      wal_path=tmp_path / "g.wal",
                      json_path=tmp_path / "g.json")
    assert len(g2.get_network_nodes()) == 1
    assert g2.get_network_nodes()[0].ip == "192.168.1.50"


def test_wal_is_append_only(tmp_path):
    g = FindingGraph(session_id="t", wal_path=tmp_path / "g.wal")
    g.add_node(NetworkNode(ip="192.168.1.50"))
    g.add_node(ServiceNode(host="192.168.1.50", port=22))
    before = len((tmp_path / "g.wal").read_text(encoding="utf-8").strip().split("\n"))
    g.add_node(NetworkNode(ip="192.168.1.51"))
    after = len((tmp_path / "g.wal").read_text(encoding="utf-8").strip().split("\n"))
    assert after == before + 1


def test_to_json_structure(graph, nmap_meta):
    graph.add_nmap_result(nmap_meta)
    data = graph.to_json()
    assert "nodes" in data and "edges" in data and "session_id" in data


def test_to_report_structure(graph, nmap_meta):
    graph.add_nmap_result(nmap_meta)
    report = graph.to_report()
    assert "hosts" in report
    assert "services" in report
    assert "vulnerabilities" in report
    assert "exploits" in report


# ---------------------------------------------------------------------------
# AttackPathFinder
# ---------------------------------------------------------------------------

def test_three_states_present(attack_graph):
    finder = AttackPathFinder(attack_graph)
    states = {p.state for p in finder.get_attack_paths()}
    assert states == {"complete", "partial_known_gap", "partial_unknown_gap"}


def test_complete_path_chain_and_cvss(attack_graph):
    finder = AttackPathFinder(attack_graph)
    complete = [p for p in finder.get_attack_paths() if p.is_complete()]
    assert len(complete) == 1
    assert complete[0].cvss_score == 9.8
    assert len(complete[0].chain) == 4


def test_known_gap_has_recommendation(attack_graph):
    finder = AttackPathFinder(attack_graph)
    known_gap = [p for p in finder.get_attack_paths() if p.state == "partial_known_gap"]
    assert len(known_gap) == 1
    assert known_gap[0].recommended_next_step is not None
    assert known_gap[0].cvss_score == 7.5


def test_unknown_gap_has_rag_query(attack_graph):
    finder = AttackPathFinder(attack_graph)
    unknown = [p for p in finder.get_attack_paths() if p.state == "partial_unknown_gap"]
    assert len(unknown) == 1
    assert unknown[0].rag_query is not None


def test_paths_sorted_by_priority(attack_graph):
    finder = AttackPathFinder(attack_graph)
    scores = [p.priority_score() for p in finder.get_attack_paths()]
    assert scores == sorted(scores, reverse=True)


def test_rag_queue_returns_unknown_gap_queries(attack_graph):
    finder = AttackPathFinder(attack_graph)
    queue = finder.get_rag_queue()
    assert len(queue) == 1
    assert isinstance(queue[0], str)


def test_summary_for_llm_has_complete_and_partial_sections(attack_graph):
    summary = AttackPathFinder(attack_graph).summary_for_llm()
    assert "COMPLETE" in summary
    assert "PARTIAL" in summary
