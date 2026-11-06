"""Normalize Wazuh alerts into dashboard fields without inventing evidence."""
import json


def severity(level):
    try:
        level = int(level or 0)
    except (TypeError, ValueError):
        level = 0
    return "Critical" if level >= 12 else "High" if level >= 8 else "Medium" if level >= 5 else "Low"


def normalize(alert, source):
    """Normalize common Linux and Windows Wazuh fields; preserve original JSON."""
    alert = alert if isinstance(alert, dict) else {}
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}

    win = data.get("win") or {}
    eventdata = win.get("eventdata") or {}
    system = win.get("system") or {}

    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or eventdata.get("ipAddress")
        or eventdata.get("sourceAddress")
        or eventdata.get("clientAddress")
    )

    target = (
        eventdata.get("targetUserName")
        or eventdata.get("subjectUserName")
        or eventdata.get("accountName")
        or data.get("dstuser")
        or data.get("srcuser")
        or eventdata.get("targetUser")
        or agent.get("ip")
    )

    mitre = (rule.get("mitre") or {}).get("id")
    if isinstance(mitre, list):
        mitre = ",".join(str(item) for item in mitre)

    groups = rule.get("groups") or []
    category = groups[0] if groups else None

    # Use event computer when available, otherwise the Wazuh agent name.
    agent_name = agent.get("name") or system.get("computer")

    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0

    return {
        "ts": alert.get("timestamp") or alert.get("@timestamp"),
        "agent": agent_name,
        "src_ip": src_ip,
        "target": target,
        "rule_id": str(rule["id"]) if rule.get("id") is not None else None,
        "rule_desc": rule.get("description"),
        "level": level,
        "mitre": mitre,
        "category": category,
        "source": source,
        "raw": json.dumps(alert, ensure_ascii=False, default=str),
    }
