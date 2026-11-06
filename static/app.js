const $ = s => document.querySelector(s), view = $("#view");
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (u, o) => { const r = await fetch(u, o && o.body ? { ...o, headers: { "Content-Type": "application/json" } } : o); const j = await r.json(); if (!j.ok) throw new Error(j.error); return j; };
const send = (u, m, b) => api(u, { method: m, body: JSON.stringify(b) });
const pill = (v, c) => `<span class="badge ${esc(c || v)}">${esc(v)}</span>`;
const table = (cols, rs, attr = () => "") => `<div class="wrap"><table><tr>${cols.map(c => `<th data-s="${c[0]}">${c[1]}</th>`).join("")}</tr>` +
  rs.map(r => `<tr class="row" ${attr(r)}>${cols.map(c => `<td>${c[2] ? c[2](r) : esc(r[c[0]])}</td>`).join("")}</tr>`).join("") + `</table></div>` || "";
const stat = (n, l) => `<div class="card stat"><b>${n}</b><span>${l}</span></div>`;
const modal = h => { $("#modalbody").innerHTML = h + `<p><button class="sec" onclick="$('#modal').hidden=true">Close</button></p>`; $("#modal").hidden = false; };
const opts = (a, sel) => a.map(x => `<option ${x === sel ? "selected" : ""}>${x}</option>`).join("");
const fail = e => alert("Error: " + e.message);
const A = ["New", "Investigating", "Resolved"], I = ["Open", "Investigating", "Resolved"], S = ["Low", "Medium", "High", "Critical"];
const P = {};

P.overview = async () => {
  const d = (await api("/api/dashboard")).data, s = d.severity, i = d.incident_status;
  view.innerHTML = `<div class="grid">${stat(d.total_alerts, "Total alerts (" + d.mode + ")")}${S.slice().reverse().map(k => stat(s[k] || 0, k + " alerts")).join("")}
  ${stat(i.Open || 0, "Open incidents")}${stat(i.Investigating || 0, "Investigating")}${stat(i.Resolved || 0, "Resolved")}${stat(d.assets, "Lab assets")}</div>
  <div class="grid grid2"><div class="card"><canvas id="c1"></canvas></div><div class="card"><canvas id="c2"></canvas></div><div class="card"><canvas id="c3"></canvas></div>
  <div class="card"><canvas id="c4"></canvas></div><div class="card"><canvas id="c5"></canvas></div></div>
  <div class="card"><h3>Recent security events</h3>${table([["ts", "Time"], ["agent", "Agent"], ["rule_id", "Rule"], ["rule_desc", "Description"], ["severity", "Severity", r => pill(r.severity)], ["source", "Source", r => pill(r.source)]], d.recent)}</div>`;
  chart("c1", "doughnut", s, "Alerts by severity"); chart("c2", "bar", d.categories, "Alerts by category"); chart("c3", "line", d.timeline, "Alert activity over time");
  chart("c4", "doughnut", d.experiment_status, "Experiment status"); chart("c5", "doughnut", i, "Incident status");
};

let aq = { sort: "ts", dir: "desc", page: 1 };
P.alerts = async () => {
  if (!$("#af")) view.innerHTML = `<div class="bar" id="af"><input id="q" placeholder="Search rule, IP…"><select id="fs"><option value="">Severity</option>${opts(S)}</select>
  <select id="fst"><option value="">Status</option>${opts(A)}</select><input id="fc" placeholder="Category"><input id="fa" placeholder="Agent">
  <button id="go">Apply</button></div><div id="at" class="card"></div>`;
  $("#go").onclick = () => { aq.page = 1; P.alerts(); };
  const p = new URLSearchParams({ ...aq, q: $("#q").value, severity: $("#fs").value, status: $("#fst").value, category: $("#fc").value, agent: $("#fa").value });
  for (const [k, v] of [...p]) if (!v) p.delete(k);
  const r = await api("/api/alerts?" + p);
  $("#at").innerHTML = table([["id", "ID"], ["ts", "Time"], ["agent", "Agent"], ["src_ip", "Source IP"], ["target", "Target"], ["rule_id", "Rule"], ["rule_desc", "Description"],
    ["severity", "Severity", x => pill(x.severity)], ["mitre", "MITRE"], ["category", "Category"], ["status", "Status"], ["source", "Source", x => pill(x.source)]], r.data, x => `data-id="${x.id}"`) +
    `<p>${r.total} alerts · page ${r.page} <button class="sec" id="pv">Prev</button> <button class="sec" id="nx">Next</button></p>`;
  $("#pv").onclick = () => { aq.page = Math.max(1, aq.page - 1); P.alerts(); }; $("#nx").onclick = () => { aq.page++; P.alerts(); };
  document.querySelectorAll("#at th").forEach(th => th.onclick = () => { aq.dir = aq.sort === th.dataset.s && aq.dir === "desc" ? "asc" : "desc"; aq.sort = th.dataset.s; P.alerts(); });
  document.querySelectorAll("#at tr.row").forEach(tr => tr.onclick = () => alertDetail(tr.dataset.id));
};
async function alertDetail(id) {
  const a = (await api("/api/alerts/" + id)).data;
  modal(`<h3>Alert #${a.id} ${pill(a.severity)} ${pill(a.source)}</h3><p>${esc(a.rule_id)} — ${esc(a.rule_desc)}</p><p>${esc(a.ts)} · ${esc(a.agent)} · src ${esc(a.src_ip || "n/a")} → ${esc(a.target || "n/a")}</p>
  <label>Status</label><select id="ast">${opts(A, a.status)}</select><label>Investigation notes</label><textarea id="ano">${esc(a.notes)}</textarea>
  <p><button id="asv">Save</button> <button class="sec" id="aic">Create incident</button></p><h3>Original alert JSON</h3><pre>${esc(JSON.stringify(JSON.parse(a.raw || "{}"), null, 1))}</pre>`);
  $("#asv").onclick = () => send("/api/alerts/" + id, "PATCH", { status: $("#ast").value, notes: $("#ano").value }).then(() => { $("#modal").hidden = true; P.alerts(); }).catch(fail);
  $("#aic").onclick = () => send("/api/incidents", "POST", { title: `${a.rule_id}: ${a.rule_desc}`.slice(0, 200), severity: a.severity, src_ip: a.src_ip || "", target: a.target || "", rule: a.rule_id || "", mitre: a.mitre || "", alert_id: a.id })
    .then(() => { $("#modal").hidden = true; alert("Incident created"); }).catch(fail);
}

P.incidents = async () => {
  const r = (await api("/api/incidents")).data;
  view.innerHTML = `<div class="bar"><button id="ni">+ New incident</button></div><div class="card">${r.length ? table([["id", "ID", x => "INC-" + String(x.id).padStart(4, "0")], ["title", "Title"], ["severity", "Severity", x => pill(x.severity)],
    ["rule", "Rule"], ["mitre", "MITRE"], ["status", "Status"], ["updated", "Updated"]], r, x => `data-id="${x.id}"`) : "No incidents yet. Create one here or from an alert."}</div>`;
  $("#ni").onclick = () => incForm(null);
  document.querySelectorAll("tr.row").forEach(tr => tr.onclick = () => incForm(r.find(x => x.id == tr.dataset.id)));
};
function incForm(i) {
  i = i || { severity: "Medium", status: "Open" };
  const f = (k, l) => `<label>${l}</label><input id="i_${k}" value="${esc(i[k])}">`, t = (k, l) => `<label>${l}</label><textarea id="i_${k}">${esc(i[k])}</textarea>`;
  modal(`<h3>${i.id ? "Incident INC-" + String(i.id).padStart(4, "0") : "New incident"}</h3>${f("title", "Title")}${t("description", "Description")}<label>Severity</label><select id="i_severity">${opts(S, i.severity)}</select>
  ${i.id ? `<label>Status</label><select id="i_status">${opts(I, i.status)}</select>` : ""}${f("src_ip", "Source IP")}${f("target", "Target asset")}${f("rule", "Detection rule")}${f("mitre", "MITRE technique")}
  ${t("notes", "Investigation notes")}${f("evidence_refs", "Evidence references")}${t("remediation", "Remediation")}<p><button id="isv">Save</button>
  ${i.id ? `<a href="/api/reports?type=incident&format=html" target="_blank"><button class="sec">Export report</button></a>` : ""}</p>`);
  $("#isv").onclick = () => {
    const b = {}; ["title", "description", "severity", "status", "src_ip", "target", "rule", "mitre", "notes", "evidence_refs", "remediation"].forEach(k => { const e = $("#i_" + k); if (e) b[k] = e.value; });
    send(i.id ? "/api/incidents/" + i.id : "/api/incidents", i.id ? "PATCH" : "POST", b).then(() => { $("#modal").hidden = true; P.incidents(); }).catch(fail);
  };
}

P.mitre = async () => {
  const al = (await api("/api/alerts?size=200")).data.filter(a => a.mitre), ex = (await api("/api/experiments")).data;
  const rows = al.filter(a => a.mitre === "T1110");
  view.innerHTML = `<div class="card"><h3>T1110 — Brute Force</h3><p>Only mapping confirmed for this lab. No other techniques are asserted.</p>
  ${table([["mitre", "Technique"], ["x", "Name", () => "Brute Force"], ["rule_id", "Associated alert (rule)"], ["x", "Experiment", () => esc(ex[0].name)],
    ["rule_desc", "Detection evidence"], ["status", "Investigation status"]], rows) || ""}${rows.length ? "" : "<p>No T1110 alerts in the current data mode.</p>"}</div>`;
};

P.experiments = async () => {
  const r = (await api("/api/experiments")).data;
  view.innerHTML = r.map(e => `<div class="card ${e.status !== "Completed" ? "warn" : ""}" style="margin-bottom:12px"><h3>${e.id}. ${esc(e.name)} ${pill(e.status, e.status === "Completed" ? "LIVE" : "DEMO")}</h3>
  <p>${esc(e.description)}</p><p><b>Attacker:</b> ${esc(e.attacker)} · <b>Target:</b> ${esc(e.target)}</p><p><b>Detection source:</b> ${esc(e.detection)}</p>
  <p><b>Wazuh rules:</b> ${esc(e.rules)}</p><p><b>MITRE:</b> ${esc(e.mitre || "No mapping recorded")}</p><p><b>Evidence:</b> ${esc(e.evidence)}</p></div>`).join("");
};

P.assets = async () => {
  const r = await api("/api/assets");
  view.innerHTML = `<div class="card">${table([["name", "Asset"], ["ip", "IP"], ["os", "OS"], ["role", "Role"], ["agent_status", "Agent status"], ["description", "Description"]], r.data)}<p>${esc(r.note)}</p></div>`;
};

P.evidence = async () => {
  view.innerHTML = `<div class="bar"><input id="eq" placeholder="Search evidence"><button id="es">Search</button><button id="ea">+ Register evidence</button></div><div class="card" id="et"></div>`;
  const load = async () => { const r = (await api("/api/evidence?q=" + encodeURIComponent($("#eq").value))).data;
    $("#et").innerHTML = r.length ? table([["id", "ID"], ["filename", "Filename"], ["type", "Type"], ["description", "Description"], ["incident_id", "Incident"], ["experiment_id", "Experiment"], ["source", "Source"], ["ts", "Registered"]], r)
      : "No evidence registered. Register files you actually have (metadata only; files are not copied or served)."; };
  $("#es").onclick = load; load();
  $("#ea").onclick = () => { modal(`<h3>Register evidence</h3>${["filename", "type", "description", "incident_id", "experiment_id", "source"].map(k => `<label>${k}</label><input id="e_${k}">`).join("")}<p><button id="esv">Save</button></p>`);
    $("#esv").onclick = () => { const b = {}; ["filename", "type", "description", "incident_id", "experiment_id", "source"].forEach(k => b[k] = $("#e_" + k).value);
      send("/api/evidence", "POST", b).then(() => { $("#modal").hidden = true; load(); }).catch(fail); }; };
};

P.reports = () => {
  const links = (t, n) => `<div class="card"><h3>${n}</h3>${["json", "csv", "html"].map(f => `<a href="/api/reports?type=${t}&format=${f}" target="_blank"><button class="sec">${f.toUpperCase()}</button></a> `).join("")}</div>`;
  view.innerHTML = `<div class="grid grid2">${links("incident", "Incident report")}${links("alerts", "Alert report")}${links("experiments", "Experiment summary")}${links("summary", "SOC investigation summary")}</div>`;
};

P.settings = async () => {
  const s = (await api("/api/settings")).data;
  view.innerHTML = `<div class="card"><h3>Data mode: ${pill(s.mode)}</h3>
  <p>Wazuh configuration: ${s.wazuh_configured ? "configured (credentials remain server-side)" : "incomplete"} · Last successful sync: ${s.has_successful_sync ? esc(s.last_sync) : "not recorded"}</p>
  <div class="bar"><select id="sm">${opts(["DEMO", "IMPORTED", "LIVE"], s.mode)}</select><button id="sb">Set mode</button><button class="sec" id="sy">Sync from Wazuh</button></div>
  <p id="syncstatus" role="status" aria-live="polite"></p>
  <label>Import Wazuh alert export (JSON array)</label><textarea id="im"></textarea><p><button id="ib">Import</button></p><p>Credentials are read from environment/.env only, never sent to the browser.</p></div>`;
  $("#sb").onclick = () => send("/api/mode", "POST", { mode: $("#sm").value }).then(() => location.reload()).catch(fail);
  $("#sy").onclick = async () => {
    const btn = $("#sy"), status = $("#syncstatus");
    btn.disabled = true; btn.textContent = "Syncing…"; status.textContent = "Contacting Wazuh API and Indexer…";
    try {
      const r = await send("/api/sync", "POST", {});
      status.textContent = `Sync successful. New alerts imported: ${r.data.imported}. Last sync: ${r.data.last_sync}`;
      btn.textContent = "Sync again";
      // Refresh mode badge/data while keeping the success result visible.
      const h = (await api("/api/health")).data;
      $("#modebadge").className = "badge " + h.mode;
      $("#modebadge").textContent = h.mode + " MODE";
    } catch (e) {
      status.textContent = "Sync failed: " + e.message;
      btn.textContent = "Retry Wazuh sync";
    } finally {
      btn.disabled = false;
    }
  };
  $("#ib").onclick = () => { try { send("/api/import", "POST", JSON.parse($("#im").value)).then(r => alert("Imported " + r.data.imported)).catch(fail); } catch (e) { fail(e); } };
};

(async () => {
  try { const h = (await api("/api/health")).data; $("#modebadge").className = "badge " + h.mode; $("#modebadge").textContent = h.mode + " MODE"; } catch (e) { $("#modebadge").textContent = "API down"; }
  try { await P[document.body.dataset.page](); } catch (e) { view.innerHTML = `<div class="card warn">Error: ${esc(e.message)}</div>`; }
})();
