"""shomescale web dashboard - serves HTML + JSON API."""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

logger = logging.getLogger("shomescale-web")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>shomescale</title><style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--green:#238636;--red:#da3633;--accent:#58a6ff;--gold:#d29922}
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
.stat-card.rules .value{color:var(--gold)}
table{width:100%;border-collapse:collapse;margin-top:10px;background:var(--card);border-radius:12px;overflow:hidden}
th,td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--border)}
th{background:#1c2128;color:var(--muted);font-weight:600;font-size:.85em;text-transform:uppercase}
tr:hover{background:#1c2128}
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.status-dot.online{background:var(--green)}
.status-dot.offline{background:var(--red)}
.status-dot.blocked{background:var(--red);opacity:.5}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:.9em}
.ago{color:var(--muted);font-size:.85em}
.footer{text-align:center;margin-top:20px;color:var(--muted);font-size:.8em}
.tabs{display:flex;gap:4px;justify-content:center;margin:10px 0}
.tab-btn{background:var(--card);color:var(--muted);border:1px solid var(--border);border-radius:8px;padding:8px 20px;cursor:pointer;font-size:.95em}
.tab-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.tab-panel{display:none}
.tab-panel.active{display:block}
#graph-container{width:100%;overflow:auto;background:var(--card);border-radius:12px;border:1px solid var(--border);display:flex;justify-content:center;padding:20px}
#graph-container svg text{font-family:'SF Mono',Consolas,monospace;font-size:11px}
#graph-container svg{max-width:100%}
.legend{display:flex;gap:20px;justify-content:center;padding:10px 0;font-size:.85em;color:var(--muted)}
.legend-item{display:flex;align-items:center;gap:6px}
.legend-line{width:24px;height:2px}
.legend-line.allowed{background:var(--green);height:3px}
.legend-line.blocked{background:var(--red);height:3px;border-top:2px dashed var(--red)}
.acl-action{font-weight:bold;text-transform:uppercase}
.acl-allow{color:var(--green)}
.acl-deny{color:var(--red)}
.rule-summary{color:var(--gold);font-size:1.5em;font-weight:bold}
</style></head><body>
<div class="header"><h1>shomescale</h1><p>WireGuard Mesh VPN &mdash; auto-refreshes every 3s</p></div>
<div id="loading" style="text-align:center;padding:40px;color:#8b949e">Loading...</div>
<div id="content" style="display:none">
<div class="stats">
<div class="stat-card total"><div class="label">Total Peers</div><div class="value" id="totalPeers">&mdash;</div></div>
<div class="stat-card online"><div class="label">Online</div><div class="value" id="onlinePeers">&mdash;</div></div>
<div class="stat-card offline"><div class="label">Offline</div><div class="value" id="offlinePeers">&mdash;</div></div>
<div class="stat-card uptime"><div class="label">Uptime</div><div class="value" id="uptime">&mdash;</div></div>
<div class="stat-card rules"><div class="label">ACL Rules</div><div class="value" id="ruleCount">&mdash;</div></div>
</div>
<div class="tabs">
<button class="tab-btn active" onclick="showTab('peers')">Peer List</button>
<button class="tab-btn" onclick="showTab('graph')">ACL Topology</button>
<button class="tab-btn" onclick="showTab('acls')">ACL Rules</button>
</div>
<div id="tab-peers" class="tab-panel active">
<table><thead><tr><th>Status</th><th>Name</th><th>UUID</th><th>IP</th><th>Endpoint</th><th>Last Hello</th></tr></thead><tbody id="peerTable"></tbody></table>
</div>
<div id="tab-graph" class="tab-panel">
<div class="legend">
<div class="legend-item"><div class="legend-line allowed"></div> Allowed WG tunnel</div>
<div class="legend-item"><div class="legend-line blocked"></div> Blocked by ACL</div>
</div>
<div id="graph-container"><svg id="graphSvg"></svg></div>
</div>
<div id="tab-acls" class="tab-panel">
<table><thead><tr><th>#</th><th>From</th><th>To</th><th>Action</th></tr></thead><tbody id="aclRulesTable"></tbody></table>
</div>
</div>
<div class="footer">shomescale &middot; WireGuard Mesh VPN</div>
<script>
function fmtU(s){if(!s||s<0)return'--';var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);if(d>0)return d+'d '+h+'h '+m+'m';if(h>0)return h+'h '+m+'m';return m+'m'}
function ago(t){if(!t)return'--';var d=Math.round(Date.now()/1000-t);if(d<5)return'just now';if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago'}
function pluralRules(n){var s=n===1?' rule':' rules';return'&#x200B;'+n+s}
function showTab(n){document.querySelectorAll('.tab-panel').forEach(function(e){e.classList.remove('active')});document.querySelectorAll('.tab-btn').forEach(function(e){e.classList.remove('active')});document.getElementById('tab-'+n).classList.add('active');document.querySelectorAll('.tab-btn').forEach(function(e){if(e.textContent.toLowerCase().includes(n))e.classList.add('active')})}
async function refresh(){try{var sr=await fetch('/api/status'),sd=await sr.json();var tr=await fetch('/api/topology'),td=await tr.json();document.getElementById('loading').style.display='none';document.getElementById('content').style.display='block';document.getElementById('totalPeers').textContent=sd.total_peers;document.getElementById('onlinePeers').textContent=sd.online;document.getElementById('offlinePeers').textContent=sd.offline;document.getElementById('uptime').textContent=fmtU(sd.uptime);var rc=document.getElementById('ruleCount');rc.innerHTML=td.rules?pluralRules(td.rules.length):'&#x200B;&#x200B;';var tb=document.getElementById('peerTable');tb.innerHTML='';for(var p of sd.peers){var dot=p.online?'online':'offline',lbl=p.online?ago(p.last_hello):ago(p.last_hello)+' (off)';var tr=document.createElement('tr');tr.innerHTML='<td><span class=\"status-dot '+dot+'\"></span>'+(p.online?'Online':'Offline')+'</td><td><strong>'+p.name+'</strong></td><td class=\"mono\" style=\"font-size:.75em;color:#8b949e\">'+p.uuid.substring(0,8)+'</td><td class=\"mono\">'+p.internal_ip+'</td><td class=\"mono\" style=\"font-size:.85em\">'+(p.endpoint||'N/A')+'</td><td class=\"ago\">'+lbl+'</td>';tb.appendChild(tr)}drawGraph(td,document.getElementById('graphSvg'));var artb=document.getElementById('aclRulesTable');artb.innerHTML='';if(td.rules&&td.rules.length>0){for(var r of td.rules){var actClass=r.action==='allow'?'acl-allow':'acl-deny';var tr2=document.createElement('tr');tr2.innerHTML='<td class=\"mono\">'+r.idx+'</td><td><strong>'+r.from+'</strong></td><td><strong>'+r.to+'</strong></td><td class=\"acl-action '+actClass+'\">'+r.action+'</td>';artb.appendChild(tr2)}}}catch(e){console.error('refresh failed',e);document.getElementById('loading').textContent='Connection lost. Retrying...'}}
function drawGraph(data,svg){var nodes=data.nodes||[],edges=data.edges||[];var n=nodes.length;if(n<2){svg.innerHTML='<text x=\"50%\" y=\"50%\" text-anchor=\"middle\" fill=\"#8b949e\">Need 2+ peers for topology view</text>';return}var r=140+Math.max(0,n-4)*30;var cx=r+60,cy=r+60;var W=2*cx,H=2*cy;var ns='http://www.w3.org/2000/svg';svg.innerHTML='';svg.setAttribute('width',W);svg.setAttribute('height',H);svg.setAttribute('viewBox','0 0 '+W+' '+H);
var pos={};var aStep=2*Math.PI/n;for(var i=0;i<n;i++){var a=i*aStep-Math.PI/2;pos[nodes[i]._k]=[cx+r*Math.cos(a),cy+r*Math.sin(a)]}
for(var idx=0;idx<edges.length;idx++){var e=edges[idx];var f=pos[e.from],t=pos[e.to];if(!f||!t)continue;var dx=t[0]-f[0],dy=t[1]-f[1],len=Math.sqrt(dx*dx+dy*dy);if(len<1)len=1;var nx=dx/len,ny=dy/len;var off=len*0.12;var x1=f[0]+nx*30,y1=f[1]+ny*30;var x2=t[0]-nx*40,y2=t[1]-ny*40;var mx=(x1+x2)/2,my=(y1+y2)/2;var color=e.allowed?'#238636':'#da3633';var dash=!e.allowed?'stroke-dasharray=\"4 4\"':'';
line=document.createElementNS(ns,'line');line.setAttribute('x1',x1);line.setAttribute('y1',y1);line.setAttribute('x2',x2);line.setAttribute('y2',y2);line.setAttribute('stroke',color);line.setAttribute('stroke-width',e.allowed?'2':'1.5');line.setAttribute('opacity','0.6');if(dash)line.setAttribute('stroke-dasharray','4 4');svg.appendChild(line);
if(e.allowed){var arrowX=x2,arrowY=y2;var as=8;var angle=Math.atan2(y2-f[1],x2-f[0]);var ax1=arrowX-as*Math.cos(angle-0.4),ay1=arrowY-as*Math.sin(angle-0.4);var ax2=arrowX-as*Math.cos(angle+0.4),ay2=arrowY-as*Math.sin(angle+0.4);var poly=document.createElementNS(ns,'polygon');poly.setAttribute('points',arrowX+','+arrowY+' '+ax1+','+ay1+' '+ax2+','+ay2);poly.setAttribute('fill',color);poly.setAttribute('opacity','0.6');svg.appendChild(poly)}}
for(var i=0;i<n;i++){var p=nodes[i];var k=p._k;var x=pos[k][0],y=pos[k][1];var col=p.online?'#58a6ff':'#484f58';var circ=document.createElementNS(ns,'circle');circ.setAttribute('cx',x);circ.setAttribute('cy',y);circ.setAttribute('r',24);circ.setAttribute('fill',col);circ.setAttribute('stroke',p.online?'#1f6feb':'#30363d');circ.setAttribute('stroke-width','2');svg.appendChild(circ);
var txt=document.createElementNS(ns,'text');txt.setAttribute('x',x);txt.setAttribute('y',y+4);txt.setAttribute('text-anchor','middle');txt.setAttribute('fill','#e6edf3');txt.setAttribute('font-size','9');txt.setAttribute('font-family','SF Mono,Consolas,monospace');var short=p.name.replace(/-wg$/,'').replace('pi-cluster','pi-');txt.textContent=short;svg.appendChild(txt)}
var info=document.createElementNS(ns,'text');info.setAttribute('x',cx);info.setAttribute('y',H-10);info.setAttribute('text-anchor','middle');info.setAttribute('fill','#8b949e');info.setAttribute('font-size','11');var al=edges.filter(function(e){return e.allowed}).length;var bl=edges.filter(function(e){return !e.allowed}).length;info.textContent='Edges: '+al+' allowed, '+bl+' blocked';svg.appendChild(info)}
refresh();setInterval(refresh,3000);
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    store = None

    def do_GET(self):
        if self.path == "/api/status":
            self._send_json(200, self.store.get_status())
        elif self.path == "/api/topology":
            self._send_json(200, self.store.get_topology())
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
