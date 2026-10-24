"""Local-only investigation console and read/write incident API."""
import os
from flask import Flask, jsonify, request, render_template_string
from storage import Storage, DEFAULT_DB

app = Flask(__name__)


def db():
    return Storage(os.environ.get('SIEM_DB', DEFAULT_DB))


def with_db(fn):
    store = db()
    try:
        return fn(store)
    finally:
        store.close()


@app.get('/api/overview')
def overview():
    def fetch(s):
        counts = {name: s.conn.execute('SELECT COUNT(*) FROM ' + name).fetchone()[0]
                  for name in ('events', 'alerts', 'incidents')}
        counts['open_incidents'] = s.conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('new','investigating')").fetchone()[0]
        counts['intel_matches'] = s.conn.execute("SELECT COUNT(*) FROM events WHERE json_extract(enrichment,'$.status')='match'").fetchone()[0]
        return jsonify(counts)
    return with_db(fetch)


@app.get('/api/events')
def events():
    return with_db(lambda s: jsonify(s.events(ip=request.args.get('ip'))))


@app.get('/api/alerts')
def alerts():
    return with_db(lambda s: jsonify([{'id': r['id'], 'ts': r['ts'], 'type': r['alert_type'],
                                      'ip': r['ip'], 'details': r['details']}
                                     for r in s.conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100')]))


@app.get('/api/incidents')
def incidents():
    return with_db(lambda s: jsonify(s.incidents()))


@app.get('/api/incidents/<int:incident_id>')
def incident(incident_id):
    item = with_db(lambda s: s.incident(incident_id))
    return (jsonify(item), 200) if item else (jsonify(error='Not found'), 404)


@app.patch('/api/incidents/<int:incident_id>')
def update_incident(incident_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get('status') not in {'new', 'investigating', 'resolved', 'false_positive'}:
        return jsonify(error='Invalid status'), 400
    found = with_db(lambda s: s.set_status(incident_id, payload['status']))
    return (jsonify(status=payload['status']), 200) if found else (jsonify(error='Not found'), 404)


PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini SIEM | Investigation</title><style>
:root{color-scheme:dark;font-family:system-ui,Segoe UI,sans-serif;background:#0d1420;color:#e8edf6}*{box-sizing:border-box}
body{margin:0;max-width:1320px;padding:26px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #344154;padding-bottom:18px}
h1{font-size:25px;margin:0}small,.muted{color:#a5b3c6}.tag{background:#293b52;color:#b9d9f3;padding:5px 9px;border-radius:5px}
h2{font-size:17px;margin:0 0 16px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}.card,section{background:#162334;border:1px solid #344154;border-radius:10px;padding:18px}.card strong{display:block;font-size:29px;margin-top:5px}
.layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.9fr);gap:18px}section{margin-bottom:18px;overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 7px;border-bottom:1px solid #314157;vertical-align:top}th{color:#a5b3c6;font-size:11px;text-transform:uppercase}button,select,input{background:#24364d;border:1px solid #527291;color:#eef4fb;border-radius:5px;padding:8px;cursor:pointer}button:hover{background:#345272}.item{cursor:pointer}.item:hover{background:#253a50}.active{background:#263e54}.severity{color:#ffb66e}.evidence{font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1a29;padding:9px;border-radius:5px;margin:8px 0}.timeline{border-left:2px solid #5b95ba;padding:0 0 12px 14px;margin-left:4px}.error{color:#ff9c9c}
@media(max-width:850px){.layout{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body><header><div><h1>Mini SIEM <span class="tag">Investigation console</span></h1><small>Local analyst workflow · simulated feed is labeled in evidence</small></div><small id="state">Loading…</small></header>
<div class="grid"><div class="card">Events<strong id="events">—</strong></div><div class="card">Alerts<strong id="alerts">—</strong></div><div class="card">Open incidents<strong id="open">—</strong></div><div class="card">Local IOC matches<strong id="ioc">—</strong></div></div>
<div class="layout"><div><section><h2>Incidents</h2><table><thead><tr><th>ID</th><th>Source</th><th>Risk</th><th>Status</th><th>Last event UTC</th></tr></thead><tbody id="incidents"></tbody></table></section><section><h2>Recent alerts</h2><table><thead><tr><th>UTC</th><th>Rule</th><th>Source</th><th>Risk</th></tr></thead><tbody id="recent"></tbody></table></section></div><div><section><h2>Investigation <span id="selected"></span></h2><div id="detail" class="muted">Select an incident to view its detection evidence and timeline.</div></section><section><h2>Events explorer</h2><input id="filter" placeholder="Exact source IP" aria-label="Exact source IP"><button id="search">Filter</button><table><thead><tr><th>UTC</th><th>Type</th><th>IP</th><th>Source</th></tr></thead><tbody id="eventrows"></tbody></table></section></div></div>
<script>
const $=id=>document.getElementById(id); const esc=s=>String(s??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function get(url){let r=await fetch(url);if(!r.ok)throw Error('Request failed: '+r.status);return r.json()}
async function loadEvents(){const rows=await get('/api/events'+($('filter').value?'?ip='+encodeURIComponent($('filter').value):''));$('eventrows').innerHTML=rows.slice(0,30).map(e=>`<tr><td>${esc(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.ip)}</td><td>${esc(e.source)}${e.simulated?' · simulated':''}</td></tr>`).join('')||'<tr><td colspan="4">No events found.</td></tr>'}
async function openIncident(id){let x=await get('/api/incidents/'+id);$('selected').textContent='#'+id;
let alerts=x.alerts.map(a=>{let d=JSON.parse(a.details);return `<div class="timeline"><b>${esc(d.rule_id)} · ${esc(a.alert_type)}</b> <span class="severity">risk ${esc(d.risk)}/100</span><br><small>${esc(a.ts)} · ${esc(d.attack||'No ATT&CK mapping')}</small><div>${esc(d.explanation)}</div>${d.enrichment?.status==='match'?`<div class="evidence">Local simulated IOC match: ${esc(d.enrichment.indicator)} · confidence ${esc(d.enrichment.confidence)} · ${esc(d.enrichment.reason)}</div>`:''}</div>`}).join('');
let evidence=x.events.map(e=>`<div class="evidence">${esc(e.ts)} · ${esc(e.type)} · ${esc(e.ip)}${e.simulated?' · SIMULATED':''}<br>${esc(e.raw_event)}</div>`).join('');
$('detail').innerHTML=`<p>Source ${esc(x.ip)} · heuristic risk ${esc(x.risk)}/100</p><label>Status <select id="status">${['new','investigating','resolved','false_positive'].map(s=>`<option value="${s}" ${s===x.status?'selected':''}>${esc(s)}</option>`).join('')}</select></label><h3>Detection timeline</h3>${alerts}<h3>Supporting events</h3>${evidence}<small>Check identity, host and session activity before containment. Patterns and IOC fixture do not prove compromise.</small>`;
$('status').onchange=async e=>{let r=await fetch('/api/incidents/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:e.target.value})});if(!r.ok)throw Error('Status update failed');await load()};}
async function load(){try{const [o,inc,alerts]=await Promise.all(['/api/overview','/api/incidents','/api/alerts'].map(get));$('events').textContent=o.events;$('alerts').textContent=o.alerts;$('open').textContent=o.open_incidents;$('ioc').textContent=o.intel_matches;$('state').textContent='Ready';$('incidents').innerHTML=inc.map(x=>`<tr class="item" data-id="${x.id}"><td>#${x.id}</td><td>${esc(x.ip)}</td><td class="severity">${x.risk}/100</td><td>${esc(x.status)}</td><td>${esc(x.last_event_ts)}</td></tr>`).join('')||'<tr><td colspan="5">No incidents. Run the demo ingestion command.</td></tr>';$('incidents').querySelectorAll('[data-id]').forEach(row=>row.onclick=()=>openIncident(row.dataset.id));$('recent').innerHTML=alerts.map(a=>{let d=JSON.parse(a.details);return `<tr><td>${esc(a.ts)}</td><td>${esc(d.rule_id)}</td><td>${esc(a.ip)}</td><td>${esc(d.risk)}</td></tr>`}).join('')||'<tr><td colspan="4">No alerts yet.</td></tr>';await loadEvents()}catch(e){$('state').textContent=e.message;$('state').className='error'}}
$('search').onclick=loadEvents;load();
</script></body></html>'''


@app.get('/')
def index():
    return render_template_string(PAGE)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)
