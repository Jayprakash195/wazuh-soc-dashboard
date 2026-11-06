import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from app import create_app, PAGES

@pytest.fixture
def client(tmp_path):
    return create_app(tmp_path / "t.db").test_client()

def test_pages_render(client):
    for p in PAGES: assert client.get("/" + p).status_code == 200
    assert client.get("/nope").status_code == 404

def test_health_and_demo_default(client):
    d = client.get("/api/health").get_json()["data"]
    assert d["status"] == "up" and d["mode"] == "DEMO"

def test_db_seed(client):
    assert len(client.get("/api/experiments").get_json()["data"]) == 5
    assert all(a["agent_status"] == "Unknown / Not verified" for a in client.get("/api/assets").get_json()["data"])
    assert client.get("/api/alerts").get_json()["total"] == 11

def test_dashboard_matches_db(client):
    d = client.get("/api/dashboard").get_json()["data"]
    assert d["total_alerts"] == sum(d["severity"].values()) == 11

def test_alert_update_and_invalid(client):
    assert client.patch("/api/alerts/1", json={"status": "Resolved", "notes": "n"}).get_json()["data"]["status"] == "Resolved"
    assert client.patch("/api/alerts/1", json={"status": "bad"}).status_code == 400
    assert client.get("/api/alerts/9999").status_code == 404

def test_incident_flow(client):
    assert client.post("/api/incidents", json={"title": " "}).status_code == 400
    r = client.post("/api/incidents", json={"title": "SSH brute force", "severity": "High", "alert_id": 3})
    assert r.status_code == 201
    i = r.get_json()["data"]["id"]
    assert client.patch(f"/api/incidents/{i}", json={"status": "Resolved", "remediation": "block IP"}).get_json()["data"]["status"] == "Resolved"
    assert client.patch(f"/api/incidents/{i}", json={"status": "x"}).status_code == 400
    assert client.get("/api/incidents/999").status_code == 404

def test_evidence_and_reports(client):
    assert client.post("/api/evidence", json={}).status_code == 400
    assert client.post("/api/evidence", json={"filename": "a.png"}).status_code == 201
    for f in ("json", "csv", "html"): assert client.get(f"/api/reports?type=alerts&format={f}").status_code == 200
    assert client.get("/api/reports?type=x").status_code == 400

def test_live_requires_sync_and_sync_unconfigured(client, monkeypatch):
    monkeypatch.delenv("WAZUH_API_PASSWORD", raising=False)
    assert client.post("/api/mode", json={"mode": "LIVE"}).status_code == 409
    assert client.post("/api/sync").status_code == 400

def test_normalize_missing_fields():
    from backend.alert_processor import normalize
    n = normalize({"rule": {"id": "5710", "level": 5}}, "IMPORTED")
    assert n["src_ip"] is None and n["mitre"] is None and n["agent"] is None


def test_import_deduplicates_stable_alert_ids(client):
    alert = {
        "id": "wazuh-alert-abc",
        "timestamp": "2026-11-05T10:00:00Z",
        "agent": {"name": "test-agent", "ip": "10.0.0.2"},
        "rule": {"id": "5710", "description": "test alert", "level": 5, "groups": ["authentication"]},
        "data": {"srcip": "10.0.0.9"}
    }
    first = client.post("/api/import", json=[alert])
    second = client.post("/api/import", json=[alert])
    assert first.status_code == 201
    assert first.get_json()["data"]["imported"] == 1
    assert second.status_code == 201
    assert second.get_json()["data"]["imported"] == 0


def test_import_without_stable_id_preserves_repeated_events(client):
    alert = {
        "timestamp": "2026-11-05T10:00:00Z",
        "agent": {"name": "test-agent"},
        "rule": {"id": "5710", "description": "repeat event", "level": 5},
        "data": {}
    }
    assert client.post("/api/import", json=[alert]).get_json()["data"]["imported"] == 1
    # Without a stable source ID, do not suppress a potentially legitimate repeat.
    assert client.post("/api/import", json=[alert]).get_json()["data"]["imported"] == 1


def test_windows_event_normalization():
    from backend.alert_processor import normalize
    alert = {
        "timestamp": "2026-11-05T10:00:00Z",
        "agent": {"name": "windows-agent", "ip": "192.168.21.1"},
        "rule": {"id": "60122", "level": 5, "groups": ["windows"]},
        "data": {"win": {"system": {"computer": "WIN-LAB"},
                         "eventdata": {"ipAddress": "127.0.0.1", "targetUserName": "student"}}}
    }
    normalized = normalize(alert, "LIVE")
    assert normalized["src_ip"] == "127.0.0.1"
    assert normalized["target"] == "student"
    assert normalized["agent"] == "windows-agent"


def test_settings_mode_default_exists_for_existing_asset_database(tmp_path):
    import sqlite3
    db_path = tmp_path / "existing.db"
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE assets(id INTEGER PRIMARY KEY, name TEXT, ip TEXT, os TEXT, role TEXT, agent_status TEXT, description TEXT);
        INSERT INTO assets(name,ip) VALUES('existing asset','10.1.1.1');
    """)
    conn.commit()
    conn.close()
    app = create_app(db_path)
    with app.test_client() as c:
        assert c.get("/api/health").get_json()["data"]["mode"] == "DEMO"


def test_evidence_rejects_invalid_reference_ids(client):
    response = client.post("/api/evidence", json={"filename": "evidence.png", "incident_id": "not-a-number"})
    assert response.status_code == 400


def test_sync_deduplicates_indexer_ids_and_updates_sync_time(client, monkeypatch):
    for key, value in {
        "WAZUH_API_URL": "https://example.invalid:55000",
        "WAZUH_API_USERNAME": "test",
        "WAZUH_API_PASSWORD": "not-a-real-secret",
        "WAZUH_INDEXER_URL": "https://example.invalid:9200",
        "WAZUH_INDEXER_USERNAME": "test",
        "WAZUH_INDEXER_PASSWORD": "not-a-real-secret",
    }.items():
        monkeypatch.setenv(key, value)

    alert = {
        "_wazuh_indexer_id": "idx-001",
        "timestamp": "2026-11-05T10:00:00Z",
        "agent": {"name": "ubuntu-victim", "ip": "192.168.21.144"},
        "rule": {"id": "5710", "description": "test", "level": 5},
        "data": {"srcip": "192.168.21.142"},
    }
    monkeypatch.setattr("app.wazuh_api.fetch_raw_alerts", lambda: [alert])
    monkeypatch.setattr("app.wazuh_api.get_agents", lambda: [
        {"name": "ubuntu-victim", "ip": "192.168.21.144", "status": "active"}
    ])

    first = client.post("/api/sync")
    second = client.post("/api/sync")
    assert first.status_code == 200
    assert first.get_json()["data"]["imported"] == 1
    assert second.status_code == 200
    assert second.get_json()["data"]["imported"] == 0
    settings = client.get("/api/settings").get_json()["data"]
    assert settings["has_successful_sync"] is True
    assert settings["last_sync"]
