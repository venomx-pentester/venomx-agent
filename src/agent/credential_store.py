"""
Credential Store
Persistent, structured memory for credentials discovered during a pentest session.

Problem it solves:
  Hydra finds SSH creds -> they land in a tool result summary -> LLM may or may not
  remember them 4 iterations later. Real attack chains depend on credential reuse:
  SSH creds on port 22 should be tried against MySQL on 3306 of the same host, and
  against all other hosts on the network.

This module gives discovered credentials a structured home that persists across
iterations, is injected into LLM context at every iteration, and can be queried
programmatically by other tools and modules.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """
    A single discovered credential.

    source_tool:  Which tool produced this (hydra, metasploit, manual, default-creds)
    validated:    Has this credential actually been confirmed working?
                  False = candidate from default-creds list; True = confirmed by tool
    """
    host: str
    port: int
    service: str                   # ssh, ftp, mysql, http-basic, rdp, smb, etc.
    username: str
    password: str
    hash: Optional[str] = None     # For pass-the-hash scenarios
    source_tool: str = "unknown"   # hydra, metasploit, manual, default-creds
    validated: bool = False        # True = confirmed working
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    session_id: str = ""

    @property
    def key(self) -> str:
        """Deduplication key: host:port:username"""
        return f"{self.host}:{self.port}:{self.username}"

    def to_dict(self) -> dict:
        return asdict(self)


class CredentialStore:
    """
    Structured, persistent credential store for a VenomX pentest session.

    Credentials are:
      - Written immediately to credentials.json on add() for persistence
      - Injected into LLM context via summary_for_llm() at every iteration
      - Queryable by host, service, or validation status
      - Pre-populated from known default credentials before Hydra runs

    Thread safety: single-threaded agent loop assumed; no locking.
    """

    def __init__(self, session_id: str, persist_path: Optional[Path] = None):
        """
        Args:
            session_id:   UUID for this pentest session (from session.py)
            persist_path: Path to credentials.json.
                          If None, credentials are in-memory only (useful for testing).
        """
        self.session_id = session_id
        self.persist_path = persist_path
        self._store: dict[str, Credential] = {}  # key -> Credential

        # Load existing credentials if resuming a session
        if persist_path and persist_path.exists():
            self._load()

    # -------------------------------------------------------------------------
    # Write API
    # -------------------------------------------------------------------------

    def add(self, credential: Credential) -> bool:
        """
        Add a credential to the store.

        If a credential with the same host:port:username already exists,
        the incoming credential wins only if it is validated and the existing
        one is not (i.e., confirmation upgrades a candidate).

        Args:
            credential: Credential to add

        Returns:
            True if added or updated, False if duplicate with no upgrade
        """
        # Stamp with session ID
        credential.session_id = self.session_id

        existing = self._store.get(credential.key)
        if existing:
            # Only upgrade: unvalidated -> validated
            if credential.validated and not existing.validated:
                existing.validated = True
                existing.source_tool = credential.source_tool
                existing.password = credential.password
                existing.hash = credential.hash
                logger.info(
                    "[CredentialStore] Upgraded credential %s to VALIDATED (source: %s)",
                    credential.key, credential.source_tool
                )
                self._persist()
                return True
            logger.debug("[CredentialStore] Duplicate credential ignored: %s", credential.key)
            return False

        self._store[credential.key] = credential
        logger.info(
            "[CredentialStore] Added credential: %s | %s:%s | %s | validated=%s",
            credential.key, credential.username, credential.password,
            credential.source_tool, credential.validated
        )
        self._persist()
        return True

    def add_from_hydra_output(self, parsed_metadata: dict) -> int:
        """
        Convenience method: bulk-add validated credentials from a parsed Hydra result.

        Args:
            parsed_metadata: metadata dict from HydraTool.parse_output()
                             Expected key: "credentials" -> list of dicts with
                             host, port, service, username, password fields

        Returns:
            Number of credentials added
        """
        added = 0
        for cred_dict in parsed_metadata.get("credentials", []):
            cred = Credential(
                host=cred_dict.get("host", ""),
                port=int(cred_dict.get("port", 0)),
                service=cred_dict.get("service", "unknown"),
                username=cred_dict.get("username", ""),
                password=cred_dict.get("password", ""),
                source_tool="hydra",
                validated=True,
            )
            if cred.host and cred.username:
                if self.add(cred):
                    added += 1
        return added

    def add_default_candidates(self, host: str, port: int, service: str, defaults: list[dict]) -> int:
        """
        Pre-populate unvalidated credential candidates from a default-creds list.
        Called before Hydra runs to give the LLM visibility into what will be tried.

        Args:
            host:     Target host
            port:     Target port
            service:  Service name (ssh, ftp, mysql, etc.)
            defaults: List of {"username": ..., "password": ...} dicts

        Returns:
            Number of candidates added
        """
        added = 0
        for entry in defaults:
            cred = Credential(
                host=host,
                port=port,
                service=service,
                username=entry.get("username", ""),
                password=entry.get("password", ""),
                source_tool="default-creds",
                validated=False,
            )
            if cred.username:
                if self.add(cred):
                    added += 1
        return added

    # -------------------------------------------------------------------------
    # Read API
    # -------------------------------------------------------------------------

    def get_by_host(self, host: str) -> list[Credential]:
        """All credentials for a specific host."""
        return [c for c in self._store.values() if c.host == host]

    def get_by_service(self, service: str) -> list[Credential]:
        """All credentials for a specific service across all hosts."""
        return [c for c in self._store.values() if c.service.lower() == service.lower()]

    def get_validated(self) -> list[Credential]:
        """Only confirmed working credentials."""
        return [c for c in self._store.values() if c.validated]

    def get_candidates(self) -> list[Credential]:
        """Unvalidated candidates (from default-creds lists)."""
        return [c for c in self._store.values() if not c.validated]

    def all(self) -> list[Credential]:
        return list(self._store.values())

    def is_empty(self) -> bool:
        return len(self._store) == 0

    # -------------------------------------------------------------------------
    # Export API
    # -------------------------------------------------------------------------

    def to_hydra_format(self, service: Optional[str] = None) -> str:
        """
        Export validated credentials in Hydra-compatible colon-separated format
        for credential stuffing against other services.

        Format: username:password (one per line)

        Args:
            service: Filter to credentials from a specific service.
                     If None, all validated credentials are exported.

        Returns:
            Multiline string, or empty string if no validated credentials exist
        """
        creds = self.get_validated()
        if service:
            creds = [c for c in creds if c.service.lower() == service.lower()]

        if not creds:
            return ""

        lines = [f"{c.username}:{c.password}" for c in creds]
        return "\n".join(lines)

    def summary_for_llm(self) -> str:
        """
        Compact credential summary injected at the top of every agent iteration.

        The LLM is always explicitly told what credentials are known rather than
        depending on context window memory from tool results several iterations back.

        Returns:
            Formatted string for injection into LLM system context,
            or empty string if no credentials are known.
        """
        if self.is_empty():
            return ""

        lines = ["KNOWN CREDENTIALS:"]

        # Validated first, then candidates
        for cred in sorted(self.get_validated(), key=lambda c: (c.host, c.port)):
            lines.append(
                f"  - {cred.host}:{cred.port}  {cred.service.upper():<12} "
                f"{cred.username}:{cred.password}  [VALIDATED]"
            )

        candidates = self.get_candidates()
        if candidates:
            lines.append(f"  (+ {len(candidates)} unvalidated default-cred candidate(s))")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------------

    def _persist(self) -> None:
        """Write current store to credentials.json (full rewrite - file is small)."""
        if not self.persist_path:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "session_id": self.session_id,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "credentials": [c.to_dict() for c in self._store.values()],
            }
            self.persist_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as e:
            logger.error("[CredentialStore] Failed to persist credentials: %s", e)

    def _load(self) -> None:
        """Load credentials from credentials.json on startup."""
        try:
            data = json.loads(self.persist_path.read_text(encoding="utf-8"))
            for cred_dict in data.get("credentials", []):
                cred = Credential(**{
                    k: v for k, v in cred_dict.items()
                    if k in Credential.__dataclass_fields__
                })
                self._store[cred.key] = cred
            logger.info(
                "[CredentialStore] Loaded %d credential(s) from %s",
                len(self._store), self.persist_path
            )
        except (OSError, json.JSONDecodeError, TypeError) as e:
            logger.error("[CredentialStore] Failed to load credentials: %s", e)
