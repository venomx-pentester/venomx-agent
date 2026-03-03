"""
Attack Path Traversal
Identifies and classifies attack chains in the FindingGraph.

The three-state model:
  complete             - Full chain: Network -> Service -> Vuln -> Exploit
                         Surfaced as actionable, pending human approval.

  partial_known_gap    - CVE confirmed but no Metasploit module / validated exploit.
                         LLM receives a specific next-step recommendation and the
                         CVSS score so it can prioritize which gaps to close first.

  partial_unknown_gap  - Service detected but no CVE match yet.
                         Routed to Coleman's RAG as a gap-resolution query before
                         LLM context assembly. May be upgraded before LLM sees it.

Returning all three states (not just complete) is intentional.
Partial paths are often more valuable for the demo: they show the agent reasoning
under uncertainty rather than executing a scripted playbook.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .finding_graph import (
        FindingGraph,
        NetworkNode,
        ServiceNode,
        VulnerabilityNode,
        ExploitNode,
        Node,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AttackPath dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttackPath:
    """
    A single attack chain with classification and actionable metadata.

    state:
        "complete"             - Full chain confirmed. Actionable.
        "partial_known_gap"    - Chain exists but has a known missing link.
        "partial_unknown_gap"  - Chain started but no CVE/vuln match found yet.

    chain:
        Ordered list of node dicts from NetworkNode through to ExploitNode
        (or as far as the chain reaches for partial paths).

    gap_description:
        Human-readable description of what is missing. None for complete paths.

    recommended_next_step:
        Specific actionable suggestion for the LLM. None for complete paths.

    cvss_score:
        CVSS base score of the highest-severity vulnerability in the chain.
        Used to prioritize which partial paths to resolve first.
        0.0 if no vulnerability with a score exists in the chain.

    rag_query:
        For partial_unknown_gap paths: the query string to send to Coleman's
        RAG system to attempt gap resolution. None for other states.
    """

    state: Literal["complete", "partial_known_gap", "partial_unknown_gap"]
    chain: list[dict]                    # Serialized node dicts in chain order
    gap_description: Optional[str] = None
    recommended_next_step: Optional[str] = None
    cvss_score: float = 0.0
    rag_query: Optional[str] = None      # For partial_unknown_gap RAG integration

    def is_complete(self) -> bool:
        return self.state == "complete"

    def is_partial(self) -> bool:
        return self.state != "complete"

    def priority_score(self) -> float:
        """
        Numeric score for sorting paths by priority.
        Complete paths outrank partial; within partial, higher CVSS = higher priority.
        """
        if self.state == "complete":
            return 100.0 + self.cvss_score
        elif self.state == "partial_known_gap":
            return 50.0 + self.cvss_score
        else:
            return 10.0 + self.cvss_score

    def to_llm_summary(self) -> str:
        """
        Format this attack path for injection into LLM context.
        """
        if not self.chain:
            return ""

        first = self.chain[0]
        last = self.chain[-1]

        host = first.get("ip", first.get("host", "unknown"))
        chain_types = " -> ".join(n.get("node_type", "?").upper() for n in self.chain)

        lines = [f"  [{self.state.upper()}] {host}  chain: {chain_types}"]

        if self.cvss_score:
            lines.append(f"    CVSS: {self.cvss_score:.1f}")

        if self.gap_description:
            lines.append(f"    Gap: {self.gap_description}")

        if self.recommended_next_step:
            lines.append(f"    Recommended: {self.recommended_next_step}")

        if self.rag_query:
            lines.append(f"    RAG query pending: {self.rag_query}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# AttackPathFinder
# ---------------------------------------------------------------------------

class AttackPathFinder:
    """
    Traverses a FindingGraph to identify and classify attack chains.

    Usage:
        finder = AttackPathFinder(graph)
        paths = finder.get_attack_paths()

        complete = [p for p in paths if p.is_complete()]
        partial = [p for p in paths if p.is_partial()]
        rag_queue = [p.rag_query for p in paths if p.rag_query]
    """

    def __init__(self, graph: "FindingGraph"):
        self.graph = graph

    def get_attack_paths(self) -> list[AttackPath]:
        """
        Traverse the graph and return all attack paths in all three states,
        sorted by priority_score() descending (highest priority first).

        The LLM receives this list at the start of each iteration as part of
        the graph summary. Complete paths are surfaced as actionable; partial
        paths include specific recommendations or RAG queries.

        Returns:
            List of AttackPath objects, sorted by priority descending.
        """
        paths: list[AttackPath] = []

        for net_node in self.graph.get_network_nodes():
            svc_nodes = self.graph.get_neighbors(net_node.node_id, "has_service")

            for svc_node in svc_nodes:
                vuln_nodes = self.graph.get_neighbors(svc_node.node_id, "has_vulnerability")

                if not vuln_nodes:
                    # partial_unknown_gap: service found, no CVE yet
                    path = self._make_unknown_gap(net_node, svc_node)
                    paths.append(path)
                    continue

                for vuln_node in vuln_nodes:
                    exploit_nodes = self.graph.get_neighbors(vuln_node.node_id, "has_exploit")

                    if exploit_nodes:
                        # complete: full chain exists
                        for exp_node in exploit_nodes:
                            path = self._make_complete(net_node, svc_node, vuln_node, exp_node)
                            paths.append(path)
                    else:
                        # partial_known_gap: vuln known, no exploit in graph yet
                        path = self._make_known_gap(net_node, svc_node, vuln_node)
                        paths.append(path)

        paths.sort(key=lambda p: p.priority_score(), reverse=True)
        logger.debug(
            "[AttackPathFinder] Found %d attack path(s): %d complete, %d partial",
            len(paths),
            sum(1 for p in paths if p.is_complete()),
            sum(1 for p in paths if p.is_partial()),
        )
        return paths

    # -------------------------------------------------------------------------
    # Path constructors
    # -------------------------------------------------------------------------

    def _make_complete(
        self,
        net: "NetworkNode",
        svc: "ServiceNode",
        vuln: "VulnerabilityNode",
        exp: "ExploitNode",
    ) -> AttackPath:
        """Build a complete attack path (full chain confirmed)."""
        return AttackPath(
            state="complete",
            chain=[net.to_dict(), svc.to_dict(), vuln.to_dict(), exp.to_dict()],
            cvss_score=vuln.cvss_score,
        )

    def _make_known_gap(
        self,
        net: "NetworkNode",
        svc: "ServiceNode",
        vuln: "VulnerabilityNode",
    ) -> AttackPath:
        """
        Build a partial_known_gap path: CVE confirmed, no exploit in graph yet.
        Provides a specific next-step recommendation so the LLM doesn't go silent.
        """
        cve_str = vuln.cve_id if vuln.cve_id else "unknown CVE"
        cvss_str = f" (CVSS {vuln.cvss_score:.1f})" if vuln.cvss_score else ""

        gap = f"{cve_str} confirmed on {svc.host}:{svc.port} {svc.service}{cvss_str} — no validated exploit in graph"

        # Specific next-step based on what we know
        if vuln.cvss_score >= 9.0:
            rec = (
                f"Critical severity. Search searchsploit for '{svc.product} {svc.version}' "
                f"or check Metasploit for {cve_str} module."
            )
        elif vuln.cvss_score >= 7.0:
            rec = (
                f"High severity. Run searchsploit '{svc.product} {svc.version}' "
                f"to find exploit code for {cve_str}."
            )
        else:
            rec = (
                f"Manual exploitation or searchsploit review recommended for {cve_str}."
            )

        return AttackPath(
            state="partial_known_gap",
            chain=[net.to_dict(), svc.to_dict(), vuln.to_dict()],
            gap_description=gap,
            recommended_next_step=rec,
            cvss_score=vuln.cvss_score,
        )

    def _make_unknown_gap(
        self,
        net: "NetworkNode",
        svc: "ServiceNode",
    ) -> AttackPath:
        """
        Build a partial_unknown_gap path: service detected, no CVE match yet.
        Generates a RAG query for Coleman's RAG system to attempt gap resolution
        before this path reaches the LLM context.
        """
        ver_str = f"{svc.product} {svc.version}".strip() if svc.product else svc.service
        gap = f"{svc.host}:{svc.port} {ver_str} — no CVE or vulnerability match in graph yet"
        rec = f"Run searchsploit '{ver_str}' or query NVD for known vulnerabilities."

        # RAG query for Coleman's integration point
        rag_query = (
            f"CVE vulnerabilities for {ver_str} on {svc.service} port {svc.port}"
            if svc.product else
            f"CVE vulnerabilities for {svc.service} service"
        )

        return AttackPath(
            state="partial_unknown_gap",
            chain=[net.to_dict(), svc.to_dict()],
            gap_description=gap,
            recommended_next_step=rec,
            cvss_score=0.0,
            rag_query=rag_query,
        )

    # -------------------------------------------------------------------------
    # Summary helpers
    # -------------------------------------------------------------------------

    def summary_for_llm(self) -> str:
        """
        Format all attack paths for LLM context injection.
        Called by agent_loop.py at each iteration alongside graph.summary_for_llm().

        Returns:
            Formatted string or empty string if no paths found.
        """
        paths = self.get_attack_paths()
        if not paths:
            return ""

        complete = [p for p in paths if p.is_complete()]
        partial = [p for p in paths if p.is_partial()]

        lines = ["ATTACK PATHS:"]

        if complete:
            lines.append(f"  COMPLETE ({len(complete)}) - actionable, pending human approval:")
            for p in complete:
                lines.append(p.to_llm_summary())

        if partial:
            lines.append(f"  PARTIAL ({len(partial)}) - gaps to resolve:")
            for p in partial:
                lines.append(p.to_llm_summary())

        return "\n".join(lines)

    def get_rag_queue(self) -> list[str]:
        """
        Return all RAG queries from partial_unknown_gap paths.

        Called by agent_loop.py before LLM context assembly each iteration.
        Coleman's RAG integration resolves these queries and may upgrade paths
        to known_gap or complete before the LLM context is assembled.

        Returns:
            List of query strings (may be empty)
        """
        paths = self.get_attack_paths()
        return [
            p.rag_query for p in paths
            if p.state == "partial_unknown_gap" and p.rag_query
        ]
