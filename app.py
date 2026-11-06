import csv, io, json, sqlite3, html, logging
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template, Response, g
import config
from backend import wazuh_api
from backend.alert_processor import normalize, severity

PAGES = {"": ("Overview", "overview"), "alerts": ("Security Alerts", "alerts"), "incidents": ("Incident Investigation", "incidents"),
         "mitre": ("MITRE ATT&CK", "mitre"), "experiments": ("Security Experiments", "experiments"), "assets": ("Lab Assets", "assets"),
         "evidence": ("Evidence", "evidence"), "reports": ("Reports", "reports"), "settings": ("Settings", "settings")}
A_STATUS, I_STATUS, SEV = ("New", "Investigating", "Resolved"), ("Open", "Investigating", "Resolved"), ("Low", "Medium", "High", "Critical")
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, agent TEXT, src_ip TEXT, target TEXT, rule_id TEXT,
 rule_desc TEXT, level INTEGER, severity TEXT, mitre TEXT, category TEXT, status TEXT DEFAULT 'New', notes TEXT DEFAULT '',
 source TEXT, exp INTEGER, raw TEXT);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '', severity TEXT,
 src_ip TEXT, target TEXT, rule TEXT, mitre TEXT, notes TEXT DEFAULT '', evidence_refs TEXT DEFAULT '', remediation TEXT DEFAULT '',
 status TEXT DEFAULT 'Open', alert_id INTEGER, created TEXT, updated TEXT);
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, name TEXT, ip TEXT, os TEXT, role TEXT, agent_status TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS experiments(id INTEGER PRIMARY KEY, name TEXT, description TEXT, attacker TEXT, target TEXT, detection TEXT,
 rules TEXT, mitre TEXT, evidence TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, type TEXT, description TEXT,
 incident_id INTEGER, experiment_id INTEGER, source TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
UNK = "Unknown / Not verified"
ASSETS = [("Wazuh Server", "192.168.21.138", "Linux (Wazuh 4.14.8)", "SIEM manager / indexer / dashboard", "Wazuh Dashboard: https://192.168.21.138"),
          ("Ubuntu Victim", "192.168.21.144", "Ubuntu (OpenSSH 10.2p1)", "Monitored target", "SSH, FIM (/home/ubuntu/fim-lab), nmap log monitoring"),
          ("Kali Attacker", "192.168.21.142", "Kali Linux", "Attacker", "SSH brute force and Nmap source"),
          ("Windows Agent", "192.168.21.1", "Windows", "Monitored endpoint", "Security Event ID 4625 source")]
EXPS = [("SSH Authentication and Brute Force", "Kali attempted invalid-user and failed-password SSH logins against Ubuntu.", "Kali 192.168.21.142", "Ubuntu 192.168.21.144",
         "Wazuh (auth.log)", "5710, 2502, custom 100100 (level 10, 5 failures/60s per source IP)", "T1110 Brute Force", "Register screenshots in Evidence", "Completed"),
        ("File Integrity Monitoring", "FIM on /home/ubuntu/fim-lab; create, modify, delete tested.", "Local action on Ubuntu", "Ubuntu 192.168.21.144",
         "Wazuh syscheck", "Syscheck FIM rules", None, "Register screenshots in Evidence", "Completed"),
        ("Nmap Reconnaissance", "Kali scanned Ubuntu: SSH/22 open, OpenSSH 10.2p1 Ubuntu 2ubuntu3.8; SYN probes/RST seen in tcpdump. Scan logs monitored by Wazuh. "
         "NO automatic custom Nmap alert rule exists.", "Kali 192.168.21.142", "Ubuntu 192.168.21.144", "tcpdump + Wazuh log monitoring (no detection rule)",
         "None (no custom rule)", None, "Nmap evidence stored on Ubuntu", "Partially implemented"),
        ("Suspicious User Creation", "User 'hydratest' created on Ubuntu.", "Local action on Ubuntu", "Ubuntu 192.168.21.144", "Wazuh",
         "5901, 5902, 5904, 5555", None, "Register screenshots in Evidence", "Completed"),
        ("Windows Failed Logon", "Windows Security Event 4625 detected.", "Failed logon attempt", "Windows 192.168.21.1", "Wazuh Windows agent",
         "60122 (level 5)", None, "Register screenshots in Evidence", "Completed")]

def now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def rows(cur): return [dict(r) for r in cur.fetchall()]

def init_db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # Safe additive migration for existing user databases; never drop/recreate tables.
    alert_columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
    if "external_id" not in alert_columns:
        db.execute("ALTER TABLE alerts ADD COLUMN external_id TEXT")
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_source_external_id "
        "ON alerts(source, external_id)"
    )
    if not db.execute("SELECT 1 FROM assets LIMIT 1").fetchone():
        db.executemany(
            "INSERT INTO assets(name,ip,os,role,agent_status,description) VALUES(?,?,?,?,?,?)",
            [(n, ip, o, r, UNK, d) for n, ip, o, r, d in ASSETS]
        )
    if not db.execute("SELECT 1 FROM experiments LIMIT 1").fetchone():
        db.executemany(
            "INSERT INTO experiments(name,description,attacker,target,detection,rules,mitre,evidence,status) VALUES(?,?,?,?,?,?,?,?,?)",
            EXPS
        )
    db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('mode','DEMO')")
    if not db.execute("SELECT 1 FROM alerts WHERE source='DEMO'").fetchone():
        for a in json.loads(config.DEMO_FILE.read_text(encoding="utf-8")):
            db.execute("INSERT INTO alerts(ts,agent,src_ip,target,rule_id,rule_desc,level,severity,mitre,category,source,exp,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (a["ts"], a["agent"], a["src_ip"], a["target"], a["rule_id"], a["rule_desc"], a["level"], severity(a["level"]), a["mitre"],
                        a["category"], "DEMO", a["exp"], json.dumps(a)))
    db.commit(); db.close()

def create_app(db_path=None):
    config.load_env()
    app = Flask(__name__)
    app.config["DB"] = str(db_path or config.DB_PATH)
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB JSON import limit
    init_db(app.config["DB"])

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB"], timeout=15); g.db.row_factory = sqlite3.Row
        return g.db
    @app.teardown_appcontext
    def close(_):
        d = g.pop("db", None)
        if d: d.close()
    def err(msg, code=400): return jsonify({"ok": False, "error": msg}), code
    def ok(data=None, **kw): return jsonify({"ok": True, "data": data, **kw})
    def mode():
        row = db().execute("SELECT value FROM settings WHERE key='mode'").fetchone()
        return row["value"] if row else "DEMO"

    @app.errorhandler(sqlite3.Error)
    def dberr(e):
        app.logger.exception("Database operation failed")
        return err("Database error", 500)

    @app.errorhandler(413)
    def too_large(e):
        return err("Request body too large (maximum 10 MB)", 413)

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Unhandled application error")
        return err("Internal server error", 500)
    @app.errorhandler(404)
    def nf(e): return err("Not found", 404)

    @app.route("/", defaults={"p": ""})
    @app.route("/<p>")
    def page(p):
        if p not in PAGES: return err("Not found", 404)
        return render_template("base.html", title=PAGES[p][0], page=PAGES[p][1], pages=PAGES)

    @app.get("/api/health")
    def health(): return ok({"status": "up", "mode": mode(), "wazuh_configured": wazuh_api.configured(), "time": now()})

    def alert_where():
        q, a = ["source=?"], [request.args.get("source") or mode()]
        for f in ("severity", "category", "agent", "status"):
            if request.args.get(f): q.append(f + "=?"); a.append(request.args[f])
        if request.args.get("q"):
            q.append("(rule_desc LIKE ? OR rule_id LIKE ? OR src_ip LIKE ? OR target LIKE ?)"); a += ["%" + request.args["q"] + "%"] * 4
        return " AND ".join(q), a

    @app.get("/api/alerts")
    def alerts():
        w, a = alert_where()
        sort = request.args.get("sort", "ts")
        sort = sort if sort in ("ts", "level", "agent", "rule_id", "status", "severity") else "ts"
        order = "ASC" if request.args.get("dir") == "asc" else "DESC"
        try:
            page = max(1, int(request.args.get("page", 1)))
            size = min(200, max(1, int(request.args.get("size", 25))))
        except (ValueError, TypeError):
            return err("page/size must be integers")
        total = db().execute(f"SELECT COUNT(*) FROM alerts WHERE {w}", a).fetchone()[0]
        data = rows(db().execute(f"SELECT id,ts,agent,src_ip,target,rule_id,rule_desc,level,severity,mitre,category,status,source FROM alerts WHERE {w} ORDER BY {sort} {order} LIMIT ? OFFSET ?", a + [size, (page - 1) * size]))
        return ok(data, total=total, page=page)

    @app.get("/api/alerts/<int:i>")
    def alert(i):
        r = db().execute("SELECT * FROM alerts WHERE id=?", (i,)).fetchone()
        return ok(dict(r)) if r else err("Alert not found", 404)

    @app.patch("/api/alerts/<int:i>")
    def alert_patch(i):
        b = request.get_json(silent=True) or {}
        if "status" in b and b["status"] not in A_STATUS: return err("Invalid status")
        if "notes" in b and (not isinstance(b["notes"], str) or len(b["notes"]) > 5000): return err("Invalid notes")
        if not db().execute("SELECT 1 FROM alerts WHERE id=?", (i,)).fetchone(): return err("Alert not found", 404)
        for k in ("status", "notes"):
            if k in b: db().execute(f"UPDATE alerts SET {k}=? WHERE id=?", (b[k], i))
        db().commit(); return alert(i)

    def inc_clean(b, creating):
        out = {}
        if creating and not str(b.get("title", "")).strip(): raise ValueError("title is required")
        for k in ("title", "description", "src_ip", "target", "rule", "mitre", "notes", "evidence_refs", "remediation"):
            if k in b:
                if not isinstance(b[k], str) or len(b[k]) > 5000: raise ValueError(f"invalid {k}")
                out[k] = b[k].strip()
        if "severity" in b or creating:
            if b.get("severity", "Medium") not in SEV: raise ValueError("invalid severity")
            out["severity"] = b.get("severity", "Medium")
        if "status" in b:
            if b["status"] not in I_STATUS: raise ValueError("invalid status")
            out["status"] = b["status"]
        if b.get("alert_id") is not None: out["alert_id"] = int(b["alert_id"])
        return out

    @app.get("/api/incidents")
    def incidents(): return ok(rows(db().execute("SELECT * FROM incidents ORDER BY id DESC")))

    @app.post("/api/incidents")
    def inc_create():
        try: d = inc_clean(request.get_json(silent=True) or {}, True)
        except (ValueError, TypeError) as e: return err(str(e))
        d["created"] = d["updated"] = now()
        cur = db().execute(f"INSERT INTO incidents({','.join(d)}) VALUES({','.join('?' * len(d))})", list(d.values()))
        if d.get("alert_id"): db().execute("UPDATE alerts SET status='Investigating' WHERE id=? AND status='New'", (d["alert_id"],))
        db().commit()
        return jsonify({"ok": True, "data": dict(db().execute("SELECT * FROM incidents WHERE id=?", (cur.lastrowid,)).fetchone())}), 201

    @app.get("/api/incidents/<int:i>")
    def inc_get(i):
        r = db().execute("SELECT * FROM incidents WHERE id=?", (i,)).fetchone()
        return ok(dict(r)) if r else err("Incident not found", 404)

    @app.patch("/api/incidents/<int:i>")
    def inc_patch(i):
        if not db().execute("SELECT 1 FROM incidents WHERE id=?", (i,)).fetchone(): return err("Incident not found", 404)
        try: d = inc_clean(request.get_json(silent=True) or {}, False)
        except (ValueError, TypeError) as e: return err(str(e))
        d.pop("alert_id", None); d["updated"] = now()
        db().execute(f"UPDATE incidents SET {','.join(k + '=?' for k in d)} WHERE id=?", list(d.values()) + [i]); db().commit()
        return inc_get(i)

    @app.get("/api/assets")
    def assets():
        data = rows(db().execute("SELECT * FROM assets"))
        return ok(data, note="Agent status is only shown when verified through the Wazuh API (LIVE sync).")

    @app.get("/api/experiments")
    def experiments(): return ok(rows(db().execute("SELECT * FROM experiments")))

    @app.get("/api/evidence")
    def evidence_list():
        q = "%" + request.args.get("q", "") + "%"
        return ok(rows(db().execute("SELECT * FROM evidence WHERE filename LIKE ? OR description LIKE ? OR type LIKE ? ORDER BY id DESC", (q, q, q))))

    @app.post("/api/evidence")
    def evidence_add():
        b = request.get_json(silent=True) or {}
        if not str(b.get("filename", "")).strip(): return err("filename is required")
        for k in ("filename", "type", "description", "source"):
            if not isinstance(b.get(k, ""), str) or len(b.get(k, "")) > 1000: return err(f"invalid {k}")
        def optional_id(key):
            value = b.get(key)
            if value in (None, ""):
                return None
            try:
                parsed = int(value)
                if parsed < 1:
                    raise ValueError
                return parsed
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a positive integer")

        try:
            incident_id = optional_id("incident_id")
            experiment_id = optional_id("experiment_id")
        except ValueError as e:
            return err(str(e))
        cur = db().execute(
            "INSERT INTO evidence(filename,type,description,incident_id,experiment_id,source,ts) VALUES(?,?,?,?,?,?,?)",
            (b["filename"].strip(), b.get("type", ""), b.get("description", ""),
             incident_id, experiment_id, b.get("source", ""), now())
        )
        db().commit()
        return jsonify({"ok": True, "data": {"id": cur.lastrowid}}), 201

    @app.get("/api/dashboard")
    def dashboard():
        w = "source=?"; m = mode()
        def grp(t, col, extra=w, a=(m,)): return {r[0] or "Unknown": r[1] for r in db().execute(f"SELECT {col},COUNT(*) FROM {t} WHERE {extra} GROUP BY {col}", a)}
        sev, inc = grp("alerts", "severity"), grp("incidents", "status", "1=1", ())
        return ok({"mode": m, "total_alerts": sum(sev.values()), "severity": sev, "categories": grp("alerts", "category"),
                   "timeline": grp("alerts", "substr(ts,1,10)"), "incident_status": inc, "alert_status": grp("alerts", "status"),
                   "experiment_status": grp("experiments", "status", "1=1", ()),
                   "assets": db().execute("SELECT COUNT(*) FROM assets").fetchone()[0],
                   "recent": rows(db().execute("SELECT id,ts,agent,rule_id,rule_desc,severity,source FROM alerts WHERE source=? ORDER BY ts DESC LIMIT 6", (m,)))})

    @app.post("/api/mode")
    def set_mode():
        mo = (request.get_json(silent=True) or {}).get("mode")
        if mo not in ("DEMO", "IMPORTED", "LIVE"): return err("Invalid mode")
        if mo == "LIVE" and not db().execute("SELECT 1 FROM alerts WHERE source='LIVE'").fetchone():
            return err("No LIVE alerts yet. Run a successful sync first.", 409)
        db().execute("INSERT OR REPLACE INTO settings VALUES('mode',?)", (mo,)); db().commit(); return ok({"mode": mo})

    def store(raws, source, commit=True):
        """Store normalized alerts and skip only alerts with a stable duplicate identity."""
        if source not in ("IMPORTED", "LIVE"):
            raise ValueError("Unsupported alert source")
        if not isinstance(raws, list):
            raise ValueError("Alert payload must be a list")

        imported = 0
        for raw_alert in raws:
            if not isinstance(raw_alert, dict):
                continue

            # Wazuh Indexer document IDs are attached by wazuh_api.fetch_raw_alerts.
            # For imported exports, use the original Wazuh alert ID if available.
            external_id = raw_alert.get("_wazuh_indexer_id")
            if external_id is not None:
                external_id = "indexer:" + str(external_id)
            elif raw_alert.get("id") is not None:
                external_id = "alert:" + str(raw_alert["id"])
            else:
                # No stable ID: preserve the event rather than risk suppressing a
                # legitimate repeated event based on a weak timestamp/content hash.
                external_id = None

            if external_id and db().execute(
                "SELECT 1 FROM alerts WHERE source=? AND external_id=? LIMIT 1",
                (source, external_id)
            ).fetchone():
                continue

            normalized = normalize(raw_alert, source)
            db().execute(
                """INSERT INTO alerts(
                    ts, agent, src_ip, target, rule_id, rule_desc,
                    level, severity, mitre, category, source, raw, external_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    normalized["ts"], normalized["agent"], normalized["src_ip"],
                    normalized["target"], normalized["rule_id"], normalized["rule_desc"],
                    normalized["level"], severity(normalized["level"]),
                    normalized["mitre"], normalized["category"], source,
                    normalized["raw"], external_id
                )
            )
            imported += 1

        if commit:
            db().commit()
        return imported

    @app.post("/api/import")
    def import_alerts():
        b = request.get_json(silent=True)
        if isinstance(b, dict): b = [b]
        if not isinstance(b, list) or not b or not all(isinstance(x, dict) for x in b): return err("Send a JSON array of Wazuh alerts")
        return ok({"imported": store(b, "IMPORTED")}), 201

    @app.post("/api/sync")
    def sync():
        if not wazuh_api.configured():
            return err("Wazuh API/Indexer configuration is incomplete (check .env.example).", 400)
        try:
            # Fetch both sources before touching the local database.
            raw_alerts = wazuh_api.fetch_raw_alerts()
            agents = wazuh_api.get_agents()
            imported = store(raw_alerts, "LIVE", commit=False)
            for ag in agents:
                db().execute(
                    "UPDATE assets SET agent_status=? WHERE ip=?",
                    (ag.get("status"), ag.get("ip"))
                )
            synced_at = now()
            db().execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('last_sync',?)",
                (synced_at,)
            )
            db().commit()
            return ok({"imported": imported, "last_sync": synced_at})
        except Exception as e:
            db().rollback()
            app.logger.exception("Wazuh sync failed")
            return err(f"Wazuh sync failed: {type(e).__name__}", 502)

    @app.get("/api/settings")
    def settings():
        s = {r[0]: r[1] for r in db().execute("SELECT * FROM settings")}
        return ok({"mode": s.get("mode"), "last_sync": s.get("last_sync"), "wazuh_configured": wazuh_api.configured(), "has_successful_sync": bool(s.get("last_sync"))})

    @app.get("/api/reports")
    def reports():
        t, fmt = request.args.get("type", "alerts"), request.args.get("format", "json")
        if t not in ("incident", "alerts", "experiments", "summary") or fmt not in ("json", "csv", "html"): return err("Invalid type/format")
        if t == "incident": data = rows(db().execute("SELECT * FROM incidents ORDER BY id"))
        elif t == "alerts": data = rows(db().execute("SELECT id,ts,agent,src_ip,target,rule_id,rule_desc,severity,mitre,category,status,notes,source FROM alerts WHERE source=?", (mode(),)))
        elif t == "experiments": data = rows(db().execute("SELECT * FROM experiments"))
        else:
            data = [{"section": "alerts_by_severity", "values": dashboard().json["data"]["severity"]},
                    {"section": "incidents", "values": rows(db().execute("SELECT id,title,severity,status,mitre,remediation FROM incidents"))},
                    {"section": "experiments", "values": rows(db().execute("SELECT name,status,rules,mitre FROM experiments"))}]
        if fmt == "json": return Response(json.dumps({"report": t, "mode": mode(), "generated": now(), "rows": data}, indent=2), mimetype="application/json")
        flat = [{k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()} for r in data]
        cols = list(flat[0]) if flat else []
        if fmt == "csv":
            buf = io.StringIO(); w = csv.DictWriter(buf, fieldnames=cols); w.writeheader()
            # prefix formula characters to prevent CSV injection
            w.writerows([{k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()} for r in flat])
            return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={t}_report.csv"})
        th = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        tr = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(c, '') if r.get(c) is not None else ''))}</td>" for c in cols) + "</tr>" for r in flat)
        return Response(f"<!doctype html><meta charset=utf-8><title>{t} report</title><style>body{{font:14px sans-serif}}td,th{{border:1px solid #999;padding:4px}}</style>"
                        f"<h1>{t.title()} report ({mode()} data)</h1><p>Generated {now()}</p><table><tr>{th}</tr>{tr}</table>", mimetype="text/html")
    return app

if __name__ == "__main__":
    a = create_app()
    print("Wazuh SOC Dashboard running in DEMO mode by default: http://127.0.0.1:5000")
    a.run(host="127.0.0.1", port=5000, debug=False)
