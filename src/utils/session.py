"""
Session Manager
UUID-based session management shared across the graph, credential store, and audit log.

Centralizes the session_id and per-session file paths so every module that needs
a path just calls session.get_path("graph.wal") rather than constructing paths
independently.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# Default base directory for session data
_DEFAULT_DATA_ROOT = Path(__file__).resolve().parents[2] / "data" / "sessions"


class Session:
    """
    Manages a single pentest session's identity and file paths.

    All session data lives under:
        data/sessions/{session_id}/
            graph.wal          - append-only finding graph event log
            graph.json         - materialized graph checkpoint (on session close)
            credentials.json   - credential store
            audit.log          - security event audit log (PromptGuard writes here)
            session.json       - session metadata (created_at, target, etc.)
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        data_root: Optional[Path] = None,
        target_network: Optional[str] = None,
    ):
        """
        Args:
            session_id:     Existing session UUID to resume. If None, a new
                            session UUID is generated.
            data_root:      Base directory for all session data.
                            Defaults to data/sessions/ relative to project root.
            target_network: CIDR or IP of the target network (for metadata).
        """
        self.session_id = session_id or uuid4().hex
        self.data_root = data_root or _DEFAULT_DATA_ROOT
        self.target_network = target_network
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.resumed = session_id is not None

        # Ensure session directory exists
        self.session_dir.mkdir(parents=True, exist_ok=True)

        if self.resumed:
            self._load_metadata()
            logger.info("[Session] Resumed session %s from %s", self.session_id, self.session_dir)
        else:
            self._write_metadata()
            logger.info("[Session] New session %s at %s", self.session_id, self.session_dir)

    @property
    def session_dir(self) -> Path:
        return self.data_root / self.session_id

    # -------------------------------------------------------------------------
    # Path accessors - single source of truth for all file paths
    # -------------------------------------------------------------------------

    @property
    def wal_path(self) -> Path:
        """graph.wal - append-only write-ahead log for FindingGraph"""
        return self.session_dir / "graph.wal"

    @property
    def graph_json_path(self) -> Path:
        """graph.json - materialized checkpoint (written on session close)"""
        return self.session_dir / "graph.json"

    @property
    def credentials_path(self) -> Path:
        """credentials.json - CredentialStore persistence"""
        return self.session_dir / "credentials.json"

    @property
    def audit_log_path(self) -> Path:
        """audit.log - PromptGuard security event log"""
        return self.session_dir / "audit.log"

    @property
    def session_metadata_path(self) -> Path:
        return self.session_dir / "session.json"

    def get_path(self, filename: str) -> Path:
        """
        Generic path accessor for any file in the session directory.

        Args:
            filename: Filename within the session directory

        Returns:
            Full Path object
        """
        return self.session_dir / filename

    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------

    def _write_metadata(self) -> None:
        """Write session.json with session identity and creation metadata."""
        metadata = {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "target_network": self.target_network,
            "resumed": False,
        }
        try:
            self.session_metadata_path.write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
        except OSError as e:
            logger.error("[Session] Failed to write session metadata: %s", e)

    def _load_metadata(self) -> None:
        """Load session.json to restore metadata for a resumed session."""
        try:
            if self.session_metadata_path.exists():
                data = json.loads(self.session_metadata_path.read_text(encoding="utf-8"))
                self.created_at = data.get("created_at", self.created_at)
                self.target_network = data.get("target_network", self.target_network)
        except (OSError, json.JSONDecodeError) as e:
            logger.error("[Session] Failed to load session metadata: %s", e)

    def summary(self) -> str:
        """Human-readable session summary for logging."""
        return (
            f"Session {self.session_id[:8]}... | "
            f"Target: {self.target_network or 'unset'} | "
            f"Dir: {self.session_dir}"
        )


# ---------------------------------------------------------------------------
# Module-level convenience: create or resume a session
# ---------------------------------------------------------------------------

def new_session(
    target_network: Optional[str] = None,
    data_root: Optional[Path] = None,
) -> Session:
    """Create a new pentest session with a fresh UUID."""
    return Session(target_network=target_network, data_root=data_root)


def resume_session(
    session_id: str,
    data_root: Optional[Path] = None,
) -> Session:
    """Resume an existing session by ID."""
    return Session(session_id=session_id, data_root=data_root)
