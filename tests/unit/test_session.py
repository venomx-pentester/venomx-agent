"""Tests for Session manager."""

import json
from src.utils import new_session, resume_session


def test_new_session_has_id(tmp_path):
    s = new_session(data_root=tmp_path)
    assert len(s.session_id) > 0


def test_session_dir_created(tmp_path):
    s = new_session(data_root=tmp_path)
    assert s.session_dir.exists()


def test_all_file_paths_under_session_dir(tmp_path):
    s = new_session(data_root=tmp_path)
    assert s.wal_path.parent == s.session_dir
    assert s.graph_json_path.parent == s.session_dir
    assert s.credentials_path.parent == s.session_dir
    assert s.audit_log_path.parent == s.session_dir


def test_metadata_file_created(tmp_path):
    s = new_session(target_network="192.168.1.0/24", data_root=tmp_path)
    assert s.session_metadata_path.exists()
    data = json.loads(s.session_metadata_path.read_text(encoding="utf-8"))
    assert data["session_id"] == s.session_id


def test_resume_preserves_target_network(tmp_path):
    s1 = new_session(target_network="192.168.1.0/24", data_root=tmp_path)
    s2 = resume_session(session_id=s1.session_id, data_root=tmp_path)
    assert s2.target_network == "192.168.1.0/24"


def test_get_path_returns_path_under_session_dir(tmp_path):
    s = new_session(data_root=tmp_path)
    assert s.get_path("custom.json") == s.session_dir / "custom.json"


def test_summary_string(tmp_path):
    s = new_session(target_network="192.168.1.0/24", data_root=tmp_path)
    summary = s.summary()
    assert s.session_id[:8] in summary
    assert "192.168.1.0/24" in summary
