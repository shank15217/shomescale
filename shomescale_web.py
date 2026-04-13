"""shomescale web dashboard - serves HTML + JSON API."""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

logger = logging.getLogger("shomescale-web")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>shomescale Dashboard</title><style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--green:#238636;--red:#da3633;--accent:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:20px}
.header{text-align:center;padding:30px 0 10px}
.header h1{font-size:2.4em;color:var(--accent);margin-bottom:4px}
.header p{color:var(--muted)}
.stats{display:flex;gap:16px;justify-content:center;flex-wrap:wrap;margin:20px 0}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 28px;text-align:center;min-width:140px}
.stat-card .value{font-size:2em;font-weight:bold;margin:4px 0}
.stat-card .label{color:var(--muted);font-size:.85em}
.stat-card.online .value{color:var(--green)}
.stat-card.offline .value{color:var(--red)}
.stat-card.total .value{color:var(--accent)}
.stat-card.uptime .value{color:var(--muted);font-size:1.4em}
table{width:100%;border-collapse:collapse;margin-top:10px;background:var(--card);border-radius:12px;overflow:hidden}
th,td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--border)}
th{background:#1c2128;color:var(--muted);font-weight:600;font-size:.85em;text-transform:uppercase}
tr:hover{background:#1c2128}
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.status-dot.online{background:var(--green)}
.status-dot.offline{background:var(--red)}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:.9em}
.ago{color:var(--muted);font-size:.85em}
.footer{text-align:center;margin-top:20px;color:var(--muted);font-size:.8em}
</style></head><body>
<div class="header"><h1>shomescale</h1><p>Mesh VPN &mdash; auto-refreshes every 3s</p></div>
<div id="loading" style="text-align:center;padding:40px;color:#8b949e">Loading...</div>
<div id="content" style="display:none">
<div class="stats">
<div class="stat-card total"><div class="label">Total Peers</div><div class="value" id="totalPeers">&mdash;</div></div>
<div class="stat-card online"><div class="label">Online</div><div class="value" id="onlinePeers">&mdash;</div></div>
<div class="stat-card offline"><div class="label">Offline</div><div class="value" id="offlinePeers">&mdash;</div></div>
<div class="stat-card uptime"><div class="label">Uptime</div><div class="value" id="uptime">&mdash;</div></div>
</div>
<table><thead><tr><th>Status</th><th>Name</th><th>UUID</th><th>IP</th><th>Endpoint</th><th>Last Hello</th></tr></thead><tbody id="peerTable"></tbody></table>
</div>
<div class="footer">shomescale &middot; WireGuard Mesh VPN</div>
<script>
function fmtU(s){if(!s||s<0)return'--';var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);if(d>0)return d+'d '+h+'h '+m+'m';if(h>0)return h+'h '+m+'m';return m+'m'}
function ago(t){if(!t)return'--';var d=Math.round(Date.now()/1000-t);if(d<5)return'just now';if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago'}
async function refresh(){try{var r=await fetch('/api/status'),d=await r.json();document.getElementById('loading').style.display='none';document.getElementById('content').style.display='block';document.getElementById('totalPeers').textContent=d.total_peers;document.getElementById('onlinePeers').textContent=d.online;document.getElementById('offlinePeers').textContent=d.offline;document.getElementById('uptime').textContent=fmtU(d.uptime);var tb=document.getElementById('peerTable');tb.innerHTML='';for(var p of d.peers){var dot=p.online?'online':'offline',lbl=p.online?ago(p.last_hello):ago(p.last_hello)+' (off)';var tr=document.createElement('tr');tr.innerHTML='<td><span class="status-dot '+dot+'"></span>'+(p.online?'Online':'Offline')+'</td><td><strong>'+p.name+'</strong></td><td class="mono" style="font-size:.75em;color:#8b949e">'+p.uuid.substring(0,8)+'</td><td class="mono">'+p.internal_ip+'</td><td class="mono" style="font-size:.85em">'+(p.endpoint||'N/A')+'</td><td class="ago">'+lbl+'</td>';tb.appendChild(tr)}}catch(e){console.error('refresh failed',e);document.getElementById('loading').textContent='Connection lost. Retrying...'}}
refresh();setInterval(refresh,3000);
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    store = None

    def do_GET(self):
        if self.path == "/api/status":
            self._send_json(200, self.store.get_status())
        elif self.path == "/":
            self._send_html(200, DASHBOARD_HTML)
        else:
            self._send_json(404, {"error": "Not found"})

    def _send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


import shared

def run_web_server(store, port=shared.DEFAULT_WEB_PORT):
    handler = DashboardHandler
    handler.store = store
    srv = HTTPServer(("0.0.0.0", port), handler)
    logger.info("Web dashboard listening on http://0.0.0.0:%d", port)
    srv.serve_forever()
