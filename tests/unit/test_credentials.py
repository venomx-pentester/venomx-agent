"""Tests for CredentialStore."""

import pytest
from src.agent.credential_store import CredentialStore, Credential


@pytest.fixture
def store():
    return CredentialStore(session_id="test-session")


def _cred(**kwargs):
    defaults = dict(host="192.168.1.50", port=22, service="ssh",
                    username="admin", password="password123", validated=True)
    defaults.update(kwargs)
    return Credential(**defaults)


# ---------------------------------------------------------------------------
# Write API
# ---------------------------------------------------------------------------

def test_add_validated_credential(store):
    assert store.add(_cred())
    assert len(store.all()) == 1


def test_add_second_credential_different_service(store):
    store.add(_cred(port=22, service="ssh", username="admin"))
    assert store.add(_cred(port=21, service="ftp", username="anonymous", password=""))
    assert len(store.all()) == 2


def test_duplicate_rejected(store):
    store.add(_cred())
    assert not store.add(_cred())


def test_unvalidated_candidate_upgraded_to_validated(store):
    store.add(_cred(validated=False, source_tool="default-creds"))
    confirmed = _cred(validated=True, source_tool="hydra")
    assert store.add(confirmed)
    assert store.all()[0].validated
    assert store.all()[0].source_tool == "hydra"


def test_add_default_candidates(store):
    added = store.add_default_candidates(
        host="192.168.1.50", port=22, service="ssh",
        defaults=[{"username": "root", "password": "toor"},
                  {"username": "admin", "password": "admin"}],
    )
    assert added == 2
    assert all(not c.validated for c in store.get_candidates())


def test_add_from_hydra_output(store):
    metadata = {
        "credentials": [
            {"host": "192.168.1.50", "port": 22, "service": "ssh",
             "username": "admin", "password": "pass"},
        ]
    }
    assert store.add_from_hydra_output(metadata) == 1
    assert store.get_validated()[0].source_tool == "hydra"


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------

def test_get_by_host(store):
    store.add(_cred(port=22, service="ssh"))
    store.add(_cred(port=21, service="ftp", username="anon", password=""))
    assert len(store.get_by_host("192.168.1.50")) == 2


def test_get_by_service(store):
    store.add(_cred(host="192.168.1.50", port=22, service="ssh", username="admin"))
    store.add(_cred(host="192.168.1.51", port=22, service="ssh", username="root", password="toor"))
    assert len(store.get_by_service("ssh")) == 2


def test_get_validated(store):
    store.add(_cred(validated=True))
    store.add(_cred(port=21, service="ftp", username="anon", password="", validated=False))
    assert len(store.get_validated()) == 1


def test_get_candidates(store):
    store.add(_cred(validated=False, source_tool="default-creds"))
    assert len(store.get_candidates()) == 1


# ---------------------------------------------------------------------------
# Export API
# ---------------------------------------------------------------------------

def test_to_hydra_format(store):
    store.add(_cred(username="admin", password="pass"))
    assert "admin:pass" in store.to_hydra_format()


def test_summary_for_llm_empty(store):
    assert store.summary_for_llm() == ""


def test_summary_for_llm_with_validated_creds(store):
    store.add(_cred())
    summary = store.summary_for_llm()
    assert "192.168.1.50" in summary
    assert "VALIDATED" in summary


def test_summary_shows_candidate_count(store):
    store.add(_cred(validated=True))
    store.add(_cred(port=21, service="ftp", username="anon", password="", validated=False))
    assert "unvalidated" in store.summary_for_llm()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_credentials_json_created(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(session_id="s1", persist_path=path)
    store.add(_cred())
    assert path.exists()


def test_credential_reloaded_after_restart(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(session_id="s1", persist_path=path).add(_cred())

    store2 = CredentialStore(session_id="s1", persist_path=path)
    assert len(store2.all()) == 1
    assert store2.all()[0].username == "admin"
