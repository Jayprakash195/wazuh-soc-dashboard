"""Wazuh API and Indexer integration.

Manager API (port 55000) provides agent status. Alert documents are read from
Wazuh Indexer (wazuh-alerts-*). Credentials are loaded from environment/.env.
"""
import os
import requests


def _verify():
    """Return requests' TLS verify value: bool or CA bundle path."""
    value = os.environ.get("WAZUH_VERIFY_TLS", "true").strip()
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def configured():
    required = (
        "WAZUH_API_URL",
        "WAZUH_API_PASSWORD",
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USERNAME",
        "WAZUH_INDEXER_PASSWORD",
    )
    return all(os.environ.get(key) for key in required)


def get_agents():
    base = os.environ["WAZUH_API_URL"].rstrip("/")
    response = requests.post(
        base + "/security/user/authenticate?raw=true",
        auth=(
            os.environ.get("WAZUH_API_USERNAME", ""),
            os.environ["WAZUH_API_PASSWORD"],
        ),
        timeout=10,
        verify=_verify(),
    )
    response.raise_for_status()
    token = response.text.strip()
    if not token:
        raise RuntimeError("Wazuh manager returned an empty authentication token")

    response = requests.get(
        base + "/agents?select=name,ip,status&limit=100",
        headers={"Authorization": "Bearer " + token},
        timeout=10,
        verify=_verify(),
    )
    response.raise_for_status()
    payload = response.json()
    return payload.get("data", {}).get("affected_items", [])


def fetch_raw_alerts(limit=100):
    url = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
    response = requests.post(
        url + "/wazuh-alerts-*/_search",
        json={
            "size": max(1, min(int(limit), 1000)),
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        },
        auth=(
            os.environ["WAZUH_INDEXER_USERNAME"],
            os.environ["WAZUH_INDEXER_PASSWORD"],
        ),
        timeout=15,
        verify=_verify(),
    )
    response.raise_for_status()
    payload = response.json()
    hits = payload.get("hits", {}).get("hits", [])
    alerts = []
    for hit in hits:
        source = hit.get("_source")
        if not isinstance(source, dict):
            continue
        # Indexer document _id is stable across repeated searches and is not
        # always present inside _source. Store it as metadata for deduplication.
        alert = dict(source)
        if hit.get("_id") is not None:
            alert["_wazuh_indexer_id"] = str(hit["_id"])
        alerts.append(alert)
    return alerts
