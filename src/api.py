from flask import Flask, jsonify, render_template_string
from storage import Storage


app = Flask(__name__)
store = Storage()


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Mini SIEM Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0f0f13; color: #e8e8f0; font-family: 'Segoe UI', sans-serif; padding: 32px; }
    h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
    .subtitle { font-size: 13px; color: #6b6b8a; margin-bottom: 32px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 32px; }
    .stat { background: #1a1a24; border: 1px solid #2a2a3a; border-radius: 8px; padding: 16px 20px; }
    .stat .label { font-size: 11px; color: #6b6b8a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
    .stat .value { font-size: 24px; font-weight: 700; color: #fff; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; }
    .card { background: #1a1a24; border: 1px solid #2a2a3a; border-radius: 8px; padding: 20px; }
    .card h3 { font-size: 13px; color: #6b6b8a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; }
    th { font-size: 11px; color: #6b6b8a; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2a3a; }
    td { font-size: 13px; padding: 10px 12px; border-bottom: 1px solid #1e1e2a; color: #c8c8d8; }
    tr:last-child td { border-bottom: none; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge.brute_force { background: rgba(239,68,68,0.15); color: #ef4444; }
    .badge.other { background: rgba(234,179,8,0.15); color: #eab308; }
    @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>Mini SIEM Dashboard</h1>
  <p class="subtitle">Real-time security alert monitor</p>

  <div class="stats">
    <div class="stat"><div class="label">Total Alerts</div><div class="value" id="total">—</div></div>
    <div class="stat"><div class="label">Unique IPs</div><div class="value" id="unique-ips">—</div></div>
    <div class="stat"><div class="label">Brute Force</div><div class="value" id="brute-count">—</div></div>
    <div class="stat"><div class="label">Last Alert</div><div class="value" id="last-alert" style="font-size:13px;padding-top:6px">—</div></div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Alerts by Type</h3>
      <div style="position:relative;height:200px;">
        <canvas id="typeChart" role="img" aria-label="Bar chart showing alert counts by type"></canvas>
      </div>
    </div>
    <div class="card">
      <h3>Top IPs</h3>
      <div style="position:relative;height:200px;">
        <canvas id="ipChart" role="img" aria-label="Bar chart showing alert counts by IP address"></canvas>
      </div>
    </div>
  </div>

  <div class="card">
    <h3>Recent Alerts</h3>
    <table>
      <thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead>
      <tbody id="alert-tbody"></tbody>
    </table>
  </div>

  <script>
    async function load() {
      const res = await fetch('/api/alerts');
      const data = await res.json();

      // Stats
      document.getElementById('total').textContent = data.length;
      const ips = [...new Set(data.map(d => d.ip))];
      document.getElementById('unique-ips').textContent = ips.length;
      document.getElementById('brute-count').textContent = data.filter(d => d.type === 'brute_force').length;
      if (data.length > 0) {
        const last = new Date(data[0].ts);
        document.getElementById('last-alert').textContent = last.toLocaleTimeString();
      }

      // Type chart
      const typeCounts = {};
      data.forEach(d => { typeCounts[d.type] = (typeCounts[d.type] || 0) + 1; });
      new Chart(document.getElementById('typeChart'), {
        type: 'bar',
        data: {
          labels: Object.keys(typeCounts),
          datasets: [{ data: Object.values(typeCounts), backgroundColor: '#c1440e', borderRadius: 4 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { ticks: { color: '#6b6b8a' }, grid: { color: '#1e1e2a' } }, y: { ticks: { color: '#6b6b8a' }, grid: { color: '#1e1e2a' } } }
        }
      });

      // IP chart
      const ipCounts = {};
      data.forEach(d => { ipCounts[d.ip] = (ipCounts[d.ip] || 0) + 1; });
      const topIPs = Object.entries(ipCounts).sort((a,b) => b[1]-a[1]).slice(0,5);
      new Chart(document.getElementById('ipChart'), {
        type: 'bar',
        data: {
          labels: topIPs.map(x => x[0]),
          datasets: [{ data: topIPs.map(x => x[1]), backgroundColor: '#185FA5', borderRadius: 4 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { ticks: { color: '#6b6b8a' }, grid: { color: '#1e1e2a' } }, y: { ticks: { color: '#6b6b8a' }, grid: { color: '#1e1e2a' } } }
        }
      });

      // Table
      const tbody = document.getElementById('alert-tbody');
      data.slice(0, 20).forEach(d => {
        const time = new Date(d.ts).toLocaleTimeString();
        tbody.innerHTML += `<tr>
          <td>${time}</td>
          <td><span class="badge ${d.type}">${d.type}</span></td>
          <td>${d.ip}</td>
          <td style="color:#6b6b8a;font-size:12px">${d.details.slice(0,80)}...</td>
        </tr>`;
      });
    }

    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)


@app.route('/api/alerts')
def alerts():
    rows = store.recent_alerts(50)
    return jsonify([{'ts': r[0], 'type': r[1], 'ip': r[2], 'details': r[3]} for r in rows])


if __name__ == '__main__':
    app.run(debug=True, port=5001)