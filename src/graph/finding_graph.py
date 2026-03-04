"""
Unified Finding Graph
Central data structure for VenomX agent state across tool calls.

Problem it solves:
  nmap, nikto, and searchsploit each produce independent ParsedOutput objects
  that are read by the LLM and discarded. By iteration 8, the LLM is re-deriving
  relationships it derived in iteration 3, and the context window is bloated with
  raw tool outputs.

This module replaces that pattern: every tool write goes into the graph instead
of producing ephemeral ParsedOutput objects. The graph persists, accumulates, and
provides structured summaries to the LLM at each iteration.

Persistence strategy: Write-Ahead Log (WAL)
  - Every node/edge write appends one JSON line to graph.wal (append-only, fast)
  - graph.json is materialized only on session close or explicit checkpoint
  - On crash recovery: replay WAL from last checkpoint
  - Nick (to_report()) and Jordan (to_json()) consumers read from graph.json,
    which is guaranteed current at session close
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node Types
# ---------------------------------------------------------------------------

@dataclass
class NetworkNode:
    """A discovered host on the network."""
    node_id: str = field(default_factory=lambda: uuid4().hex)
    node_type: str = "network"
    ip: str = ""
    hostname: str = ""
    os: str = ""
    os_confidence: int = 0          # 0-100 from nmap OS detection
    source_tool: str = "nmap"
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ServiceNode:
    """An open port/service on a network node."""
    node_id: str = field(default_factory=lambda: uuid4().hex)
    node_type: str = "service"
    host: str = ""
    port: int = 0
    protocol: str = "tcp"           # tcp, udp
    service: str = ""               # ssh, http, mysql, etc.
    product: str = ""               # OpenSSH, Apache, etc.
    version: str = ""               # 7.4p1, 2.4.49, etc.
    source_tool: str = "nmap"
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VulnerabilityNode:
    """A confirmed or suspected vulnerability."""
    node_id: str = field(default_factory=lambda: uuid4().hex)
    node_type: str = "vulnerability"
    cve_id: str = ""                # CVE-2021-41773 or empty if no CVE
    description: str = ""
    cvss_score: float = 0.0         # 0.0-10.0 CVSS v3 base score
    affected_service: str = ""      # service name this vuln affects
    exploit_available: bool = False
    source_tool: str = ""           # nikto, searchsploit, manual
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExploitNode:
    """A known exploit for a vulnerability."""
    node_id: str = field(default_factory=lambda: uuid4().hex)
    node_type: str = "exploit"
    title: str = ""
    path: str = ""                  # exploitdb path or local path
    cve_id: str = ""
    metasploit_module: str = ""     # e.g. exploit/multi/http/apache_normalize_path_rce
    platform: str = ""
    exploit_type: str = ""          # Remote, Local, WebApp, etc.
    validated: bool = False         # Has this been confirmed to work against target?
    source_tool: str = "searchsploit"
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


# Union type for all node types
Node = NetworkNode | ServiceNode | VulnerabilityNode | ExploitNode


@dataclass
class FindingEdge:
    """
    A directed relationship between two nodes.

    relationship examples:
      "has_service"        NetworkNode -> ServiceNode
      "has_vulnerability"  ServiceNode -> VulnerabilityNode
      "has_exploit"        VulnerabilityNode -> ExploitNode
      "same_host"          ServiceNode -> ServiceNode (for credential reuse tracking)
    """
    edge_id: str = field(default_factory=lambda: uuid4().hex)
    source_id: str = ""
    target_id: str = ""
    relationship: str = ""
    source_tool: str = ""
    confidence: float = 1.0         # 0.0-1.0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Finding Graph
# ---------------------------------------------------------------------------

_NODE_TYPE_MAP = {
    "network": NetworkNode,
    "service": ServiceNode,
    "vulnerability": VulnerabilityNode,
    "exploit": ExploitNode,
}


class FindingGraph:
    """
    Persistent finding graph for a VenomX pentest session.

    Every tool result writes into the graph. The graph accumulates across
    iterations and provides the LLM with a compact, structured summary at
    each iteration - replacing bloated raw tool output in the context window.

    Persistence:
      graph.wal  - append-only write-ahead log (one JSON line per event)
      graph.json - materialized snapshot (written on checkpoint or session close)
    """

    def __init__(
        self,
        session_id: str,
        wal_path: Optional[Path] = None,
        json_path: Optional[Path] = None,
    ):
        """
        Args:
            session_id: UUID for this pentest session
            wal_path:   Path to graph.wal. If None, WAL writes are skipped (in-memory only)
            json_path:  Path to graph.json checkpoint file
        """
        self.session_id = session_id
        self.wal_path = wal_path
        self.json_path = json_path

        self._nodes: dict[str, Node] = {}       # node_id -> Node
        self._edges: dict[str, FindingEdge] = {}  # edge_id -> FindingEdge

        # Indexes for fast lookup
        self._nodes_by_type: dict[str, list[str]] = {
            t: [] for t in _NODE_TYPE_MAP
        }
        self._edges_by_source: dict[str, list[str]] = {}   # source_id -> [edge_ids]
        self._edges_by_target: dict[str, list[str]] = {}   # target_id -> [edge_ids]

        # Load from checkpoint if it exists, then replay WAL
        if json_path and json_path.exists():
            self._load_checkpoint()
        if wal_path and wal_path.exists():
            self._replay_wal()

    # -------------------------------------------------------------------------
    # Node Write API
    # -------------------------------------------------------------------------

    def add_node(self, node: Node) -> str:
        """
        Add a node to the graph and append to WAL.

        Args:
            node: Any Node type

        Returns:
            node_id of the added node
        """
        self._nodes[node.node_id] = node
        self._nodes_by_type[node.node_type].append(node.node_id)
        self._wal_append("node_added", node.to_dict())
        logger.debug("[FindingGraph] Added %s node: %s", node.node_type, node.node_id)
        return node.node_id

    def add_edge(self, edge: FindingEdge) -> str:
        """
        Add an edge between two nodes and append to WAL.

        Args:
            edge: FindingEdge connecting two nodes

        Returns:
            edge_id of the added edge
        """
        self._edges[edge.edge_id] = edge

        self._edges_by_source.setdefault(edge.source_id, []).append(edge.edge_id)
        self._edges_by_target.setdefault(edge.target_id, []).append(edge.edge_id)

        self._wal_append("edge_added", edge.to_dict())
        logger.debug(
            "[FindingGraph] Added edge: %s -[%s]-> %s",
            edge.source_id, edge.relationship, edge.target_id
        )
        return edge.edge_id

    # -------------------------------------------------------------------------
    # Convenience ingestion methods (called by output_parser.py)
    # -------------------------------------------------------------------------

    def add_nmap_result(self, metadata: dict) -> list[str]:
        """
        Ingest a parsed nmap result into the graph.

        Creates NetworkNode and ServiceNode objects and edges between them.

        Args:
            metadata: metadata dict from NmapTool.parse_output()

        Returns:
            List of node_ids created
        """
        created = []

        # Index existing network nodes by IP for dedup
        existing_network = {
            self._nodes[nid].ip: nid
            for nid in self._nodes_by_type["network"]
            if hasattr(self._nodes[nid], "ip")
        }

        for host_info in metadata.get("hosts", []):
            ip = host_info.get("ip", "")
            hostname = host_info.get("hostname", "")

            # Dedup: reuse existing network node for this IP
            if ip in existing_network:
                network_id = existing_network[ip]
            else:
                os_matches = metadata.get("os_matches", [])
                os_match = next((m for m in os_matches if m.get("host") == ip), {})

                net_node = NetworkNode(
                    ip=ip,
                    hostname=hostname,
                    os=os_match.get("os", ""),
                    os_confidence=os_match.get("accuracy", 0),
                    source_tool="nmap",
                )
                network_id = self.add_node(net_node)
                existing_network[ip] = network_id
                created.append(network_id)

        # Index existing service nodes by host:port for dedup
        existing_services = {
            f"{self._nodes[nid].host}:{self._nodes[nid].port}": nid
            for nid in self._nodes_by_type["service"]
        }

        for port_info in metadata.get("open_ports", []):
            host = port_info.get("host", "")
            port = port_info.get("port", 0)
            svc_key = f"{host}:{port}"

            if svc_key in existing_services:
                continue  # Already in graph

            svc_node = ServiceNode(
                host=host,
                port=port,
                protocol=port_info.get("protocol", "tcp"),
                service=port_info.get("service", ""),
                product=port_info.get("product", ""),
                version=port_info.get("version", ""),
                source_tool="nmap",
            )
            svc_id = self.add_node(svc_node)
            created.append(svc_id)
            existing_services[svc_key] = svc_id

            # Edge: NetworkNode -[has_service]-> ServiceNode
            network_id = existing_network.get(host)
            if network_id:
                edge = FindingEdge(
                    source_id=network_id,
                    target_id=svc_id,
                    relationship="has_service",
                    source_tool="nmap",
                    confidence=1.0,
                )
                self.add_edge(edge)

        return created

    def add_searchsploit_result(self, metadata: dict, for_service: Optional[str] = None) -> list[str]:
        """
        Ingest parsed searchsploit results into the graph.

        Creates VulnerabilityNode and ExploitNode objects.

        Args:
            metadata:    metadata dict from SearchsploitTool.parse_output()
            for_service: Optional service name to link exploits to existing ServiceNodes

        Returns:
            List of node_ids created
        """
        created = []

        for exploit in metadata.get("exploits", []):
            # Create ExploitNode
            exp_node = ExploitNode(
                title=exploit.get("title", ""),
                path=exploit.get("path", ""),
                cve_id=self._extract_cve(exploit.get("title", "")),
                platform=exploit.get("platform", ""),
                exploit_type=exploit.get("type", ""),
                source_tool="searchsploit",
            )
            exp_id = self.add_node(exp_node)
            created.append(exp_id)

            # If there's a CVE, create or find a VulnerabilityNode and link
            if exp_node.cve_id:
                vuln_node = VulnerabilityNode(
                    cve_id=exp_node.cve_id,
                    description=exp_node.title,
                    affected_service=for_service or "",
                    exploit_available=True,
                    source_tool="searchsploit",
                )
                vuln_id = self.add_node(vuln_node)
                created.append(vuln_id)

                # Edge: VulnerabilityNode -[has_exploit]-> ExploitNode
                self.add_edge(FindingEdge(
                    source_id=vuln_id,
                    target_id=exp_id,
                    relationship="has_exploit",
                    source_tool="searchsploit",
                    confidence=1.0,
                ))

                # Link to ServiceNodes if service name matches
                if for_service:
                    for svc_id in self._nodes_by_type["service"]:
                        svc = self._nodes[svc_id]
                        if hasattr(svc, "service") and svc.service.lower() == for_service.lower():
                            self.add_edge(FindingEdge(
                                source_id=svc_id,
                                target_id=vuln_id,
                                relationship="has_vulnerability",
                                source_tool="searchsploit",
                                confidence=0.8,
                            ))

        return created

    def add_nikto_result(self, findings: list[dict], host: str, port: int) -> list[str]:
        """
        Ingest parsed nikto findings into the graph as VulnerabilityNodes.

        Args:
            findings: List of finding dicts from OutputParser._parse_nikto()
            host:     Target host
            port:     Target port

        Returns:
            List of node_ids created
        """
        created = []
        svc_key = f"{host}:{port}"

        # Find the ServiceNode for this host:port
        svc_id = next(
            (nid for nid in self._nodes_by_type["service"]
             if f"{self._nodes[nid].host}:{self._nodes[nid].port}" == svc_key),
            None
        )

        for finding in findings:
            vuln_node = VulnerabilityNode(
                cve_id=self._extract_cve(finding.get("description", "")),
                description=finding.get("description", ""),
                cvss_score=0.0,  # Nikto doesn't provide CVSS
                affected_service="http",
                exploit_available=False,
                source_tool="nikto",
            )
            vuln_id = self.add_node(vuln_node)
            created.append(vuln_id)

            if svc_id:
                self.add_edge(FindingEdge(
                    source_id=svc_id,
                    target_id=vuln_id,
                    relationship="has_vulnerability",
                    source_tool="nikto",
                    confidence=0.7,
                ))

        return created

    # -------------------------------------------------------------------------
    # Read API
    # -------------------------------------------------------------------------

    def get_network_nodes(self) -> list[NetworkNode]:
        return [self._nodes[nid] for nid in self._nodes_by_type["network"]]

    def get_service_nodes(self) -> list[ServiceNode]:
        return [self._nodes[nid] for nid in self._nodes_by_type["service"]]

    def get_vulnerability_nodes(self) -> list[VulnerabilityNode]:
        return [self._nodes[nid] for nid in self._nodes_by_type["vulnerability"]]

    def get_exploit_nodes(self) -> list[ExploitNode]:
        return [self._nodes[nid] for nid in self._nodes_by_type["exploit"]]

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str, relationship: Optional[str] = None) -> list[Node]:
        """Get all nodes reachable from node_id via outgoing edges."""
        edge_ids = self._edges_by_source.get(node_id, [])
        result = []
        for eid in edge_ids:
            edge = self._edges[eid]
            if relationship and edge.relationship != relationship:
                continue
            target = self._nodes.get(edge.target_id)
            if target:
                result.append(target)
        return result

    def summary_for_llm(self) -> str:
        """
        Compact graph summary injected at the top of every agent iteration.

        Replaces bloated raw tool outputs in the LLM context window with a
        structured, always-current view of what has been discovered.

        Returns:
            Formatted string, or empty string if graph is empty.
        """
        nets = self.get_network_nodes()
        svcs = self.get_service_nodes()
        exploits = self.get_exploit_nodes()

        if not nets and not svcs:
            return ""

        lines = ["FINDING GRAPH SUMMARY:"]

        for net in nets:
            os_str = f" [{net.os} {net.os_confidence}%]" if net.os else ""
            lines.append(f"  HOST: {net.ip}{' (' + net.hostname + ')' if net.hostname else ''}{os_str}")

            host_svcs = [s for s in svcs if s.host == net.ip]
            for svc in sorted(host_svcs, key=lambda s: s.port):
                ver_str = f"{svc.product} {svc.version}".strip()
                svc_str = f"{svc.service}  {ver_str}" if ver_str else svc.service
                lines.append(f"    PORT {svc.port}/{svc.protocol}  {svc_str}")

                # Vulns on this service
                svc_vulns = self.get_neighbors(svc.node_id, "has_vulnerability")
                for vuln in svc_vulns:
                    cve_str = f" ({vuln.cve_id})" if hasattr(vuln, 'cve_id') and vuln.cve_id else ""
                    lines.append(f"      VULN:{cve_str} {vuln.description[:80]}")

        if exploits:
            lines.append(f"  EXPLOITS AVAILABLE: {len(exploits)}")
            for exp in exploits[:5]:  # Cap at 5 to avoid context bloat
                lines.append(f"    - {exp.title[:70]}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Export API (for Jordan and Nick)
    # -------------------------------------------------------------------------

    def to_json(self) -> dict:
        """
        Full graph serialization for Jordan's network topology visualization.
        Returns a dict with nodes and edges arrays.
        """
        return {
            "session_id": self.session_id,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    def to_report(self) -> dict:
        """
        Structured report payload for Nick's PDF report generator.
        No LLM output parsing required.
        """
        return {
            "session_id": self.session_id,
            "hosts": [n.to_dict() for n in self.get_network_nodes()],
            "services": [n.to_dict() for n in self.get_service_nodes()],
            "vulnerabilities": [n.to_dict() for n in self.get_vulnerability_nodes()],
            "exploits": [n.to_dict() for n in self.get_exploit_nodes()],
            "edge_count": len(self._edges),
        }

    # -------------------------------------------------------------------------
    # WAL-Based Persistence
    # -------------------------------------------------------------------------

    def _wal_append(self, event: str, data: dict) -> None:
        """Append a single JSON event line to graph.wal."""
        if not self.wal_path:
            return
        entry = {
            "event": event,
            "data": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self.wal_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.wal_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            logger.error("[FindingGraph] WAL write failed: %s", e)

    def checkpoint(self) -> None:
        """
        Materialize graph.json from current in-memory state.

        Called on session close. Nick and Jordan's consumers read from
        graph.json which is guaranteed current after this call.
        """
        if not self.json_path:
            return
        try:
            self.json_path.parent.mkdir(parents=True, exist_ok=True)
            self.json_path.write_text(
                json.dumps(self.to_json(), indent=2), encoding="utf-8"
            )
            logger.info("[FindingGraph] Checkpoint written: %s", self.json_path)
        except OSError as e:
            logger.error("[FindingGraph] Checkpoint write failed: %s", e)

    def _load_checkpoint(self) -> None:
        """Load graph state from graph.json checkpoint."""
        try:
            data = json.loads(self.json_path.read_text(encoding="utf-8"))
            for node_dict in data.get("nodes", []):
                node = self._deserialize_node(node_dict)
                if node:
                    self._nodes[node.node_id] = node
                    self._nodes_by_type[node.node_type].append(node.node_id)
            for edge_dict in data.get("edges", []):
                edge = FindingEdge(**{
                    k: v for k, v in edge_dict.items()
                    if k in FindingEdge.__dataclass_fields__
                })
                self._edges[edge.edge_id] = edge
                self._edges_by_source.setdefault(edge.source_id, []).append(edge.edge_id)
                self._edges_by_target.setdefault(edge.target_id, []).append(edge.edge_id)
            logger.info(
                "[FindingGraph] Loaded checkpoint: %d nodes, %d edges",
                len(self._nodes), len(self._edges)
            )
        except (OSError, json.JSONDecodeError) as e:
            logger.error("[FindingGraph] Failed to load checkpoint: %s", e)

    def _replay_wal(self) -> None:
        """
        Replay WAL events that occurred after the last checkpoint.
        Events already reflected in the loaded checkpoint are skipped
        (idempotent: adding an already-present node_id is a no-op).
        """
        try:
            with open(self.wal_path, "r", encoding="utf-8") as f:
                replayed = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        event = entry.get("event")
                        data = entry.get("data", {})

                        if event == "node_added":
                            node = self._deserialize_node(data)
                            if node and node.node_id not in self._nodes:
                                self._nodes[node.node_id] = node
                                self._nodes_by_type[node.node_type].append(node.node_id)
                                replayed += 1
                        elif event == "edge_added":
                            edge = FindingEdge(**{
                                k: v for k, v in data.items()
                                if k in FindingEdge.__dataclass_fields__
                            })
                            if edge.edge_id not in self._edges:
                                self._edges[edge.edge_id] = edge
                                self._edges_by_source.setdefault(edge.source_id, []).append(edge.edge_id)
                                self._edges_by_target.setdefault(edge.target_id, []).append(edge.edge_id)
                                replayed += 1
                    except (json.JSONDecodeError, TypeError):
                        continue  # Skip malformed WAL lines
            if replayed:
                logger.info("[FindingGraph] Replayed %d WAL events", replayed)
        except OSError as e:
            logger.error("[FindingGraph] WAL replay failed: %s", e)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_cve(text: str) -> str:
        """Extract first CVE ID from a string, or return empty string."""
        import re
        match = re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        return match.group(0).upper() if match else ""

    @staticmethod
    def _deserialize_node(data: dict) -> Optional[Node]:
        """Reconstruct a typed node from a dict (used in checkpoint load and WAL replay)."""
        node_type = data.get("node_type")
        cls = _NODE_TYPE_MAP.get(node_type)
        if not cls:
            return None
        try:
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except TypeError:
            return None
