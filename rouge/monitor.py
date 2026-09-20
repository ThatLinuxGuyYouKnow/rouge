import asyncio
import json
import os
import datetime
from aiohttp import web
from .graph import build_graph, RougeState
from .config import current_model, DEFAULT_MODEL, new_session_id

DEFAULT_PORT = 8765

_HISTORY: list[dict] = []
_SUBSCRIBERS: set[asyncio.Queue] = set()
_STATUS = "idle"
_SCAN_TASK: asyncio.Task | None = None
_LAST_SUMMARY: dict | None = None
_LAST_LOG_PATH: str = ""
_LAST_REPORT_PATH: str = ""


def _now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def _broadcast(event: dict) -> None:
    _HISTORY.append(event)
    for q in list(_SUBSCRIBERS):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


async def _run_scan(target: str, mode: str, model: str) -> None:
    global _STATUS, _LAST_SUMMARY, _LAST_LOG_PATH, _LAST_REPORT_PATH
    os.environ["ROUGE_MODEL"] = model
    new_session_id()

    graph = build_graph()
    initial_state: RougeState = {
        "target_path": os.path.abspath(target),
        "mode": mode,
        "findings": [],
        "confirmed": [],
        "inconclusive": [],
        "prioritized": [],
        "top_vuln": None,
        "patch_result": None,
        "report_path": "",
        "log_path": "",
        "log": [],
        "phase": "recon",
    }

    _broadcast({"type": "status", "status": "running", "ts": _now()})
    _broadcast({
        "type": "log",
        "ts": _now(),
        "node": "monitor",
        "text": f"Scan started — target={target} mode={mode} model={model}",
    })

    final_state: dict = dict(initial_state)
    try:
        async for update in graph.astream(initial_state, stream_mode="updates"):
            for node, delta in update.items():
                for line in delta.get("log", []):
                    _broadcast({"type": "log", "ts": _now(), "node": node, "text": line})
                if "findings" in delta:
                    final_state["findings"] = delta["findings"]
                if "confirmed" in delta:
                    final_state["confirmed"] = delta["confirmed"]
                if "inconclusive" in delta:
                    final_state["inconclusive"] = delta["inconclusive"]
                if "top_vuln" in delta:
                    final_state["top_vuln"] = delta["top_vuln"]
                if "patch_result" in delta:
                    final_state["patch_result"] = delta["patch_result"]
                if "report_path" in delta:
                    final_state["report_path"] = delta["report_path"]
                    _LAST_REPORT_PATH = delta["report_path"]

        from .graph import _write_log_file
        _LAST_LOG_PATH = _write_log_file(final_state)

        confirmed = final_state.get("confirmed", [])
        findings = final_state.get("findings", [])
        inconclusive = final_state.get("inconclusive", [])
        decided = {c.get("function") for c in confirmed} | {c.get("function") for c in inconclusive}
        false_positives = [f for f in findings if f.get("function") not in decided]

        _LAST_SUMMARY = {
            "findings": len(findings),
            "confirmed": len(confirmed),
            "false_positives": len(false_positives),
            "inconclusive": len(inconclusive),
            "vert": len(confirmed) == 0 and len(inconclusive) == 0,
            "log_path": _LAST_LOG_PATH,
            "report_path": _LAST_REPORT_PATH,
        }

        _broadcast({"type": "summary", "ts": _now(), "summary": _LAST_SUMMARY})
        if _LAST_SUMMARY["vert"]:
            _broadcast({"type": "log", "ts": _now(), "node": "monitor",
                        "text": "VERT — Clean bill of health. No exploitable vulnerabilities found."})
        elif not confirmed:
            _broadcast({"type": "log", "ts": _now(), "node": "monitor",
                        "text": f"INCOMPLETE — {len(inconclusive)} finding(s) unverified. NOT a clean bill of health."})
        else:
            _broadcast({"type": "log", "ts": _now(), "node": "monitor",
                        "text": f"Scan complete — {len(confirmed)} confirmed vulnerability(ies)."})
        _STATUS = "done"
        _broadcast({"type": "status", "status": "done", "ts": _now()})

    except Exception as e:
        _broadcast({"type": "log", "ts": _now(), "node": "monitor",
                    "text": f"ERROR: {e}"})
        _STATUS = "error"
        _broadcast({"type": "status", "status": "error", "ts": _now()})


async def _scan_handler(request: web.Request) -> web.Response:
    global _SCAN_TASK, _STATUS
    if _SCAN_TASK is not None and not _SCAN_TASK.done():
        return web.json_response({"error": "A scan is already running"}, status=409)

    data = await request.json()
    target = data.get("target", "").strip()
    mode = data.get("mode", "fix")
    model = (data.get("model", "") or "").strip()

    # Legacy clients may still send `backend`.
    if not model:
        legacy = (data.get("backend", "") or "").strip()
        if legacy == "zen":
            return web.json_response(
                {"error": "the 'zen' backend was removed — send a LiteLLM `model` string instead, or run `rouge setup`"},
                status=400,
            )
        model = current_model()

    if not target:
        return web.json_response({"error": "target is required"}, status=400)
    if not os.path.exists(target):
        return web.json_response({"error": f"path not found: {target}"}, status=404)
    if mode not in ("fix", "report"):
        return web.json_response({"error": "mode must be fix or report"}, status=400)
    if not model:
        return web.json_response({"error": "model must be a non-empty LiteLLM model string"}, status=400)

    _HISTORY.clear()
    _LAST_SUMMARY = None
    _LAST_LOG_PATH = ""
    _LAST_REPORT_PATH = ""
    _STATUS = "running"

    _SCAN_TASK = asyncio.create_task(_run_scan(target, mode, model))
    return web.json_response({"ok": True, "target": target, "mode": mode, "model": model})


async def _status_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "status": _STATUS,
        "history_len": len(_HISTORY),
        "summary": _LAST_SUMMARY,
        "log_path": _LAST_LOG_PATH,
        "report_path": _LAST_REPORT_PATH,
    })


async def _stream_handler(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
    await resp.prepare(request)

    for event in _HISTORY:
        await resp.write(f"data: {json.dumps(event)}\n\n".encode())

    q: asyncio.Queue = asyncio.Queue(maxsize=10000)
    _SUBSCRIBERS.add(q)
    try:
        while True:
            event = await q.get()
            await resp.write(f"data: {json.dumps(event)}\n\n".encode())
            if event.get("type") == "status" and event.get("status") == "done":
                pass
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    finally:
        _SUBSCRIBERS.discard(q)
        return resp


async def _index_handler(request: web.Request) -> web.Response:
    return web.Response(text=_DASHBOARD_HTML, content_type="text/html")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", _index_handler)
    app.router.add_get("/stream", _stream_handler)
    app.router.add_get("/api/status", _status_handler)
    app.router.add_post("/api/scan", _scan_handler)
    app.router.add_static("/logs", os.getcwd(), show_index=False)
    return app


def serve(port: int = DEFAULT_PORT) -> None:
    app = build_app()
    web.run_app(app, host="0.0.0.0", port=port, print=None)


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROUGE — Monitoring Station</title>
<style>
  :root {
    --bg: #0d0d12; --panel: #161620; --border: #2a2a3a;
    --red: #ff4d4d; --green: #4dff88; --yellow: #ffcc4d;
    --cyan: #4dccff; --dim: #6a6a80; --text: #e0e0ee; --mono: ui-monospace, "SF Mono", "Cascadia Mono", "JetBrains Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--mono); }
  .header { display: flex; align-items: baseline; gap: 14px; padding: 18px 24px; border-bottom: 1px solid var(--border); background: linear-gradient(90deg, #1a0a0a, var(--panel)); }
  .logo { color: var(--red); font-weight: bold; font-size: 20px; letter-spacing: 2px; }
  .subtitle { color: var(--dim); font-size: 13px; }
  .status-pill { margin-left: auto; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; border: 1px solid var(--border); }
  .status-idle { color: var(--dim); }
  .status-running { color: var(--yellow); background: rgba(255,204,77,.1); border-color: var(--yellow); animation: pulse 1.5s infinite; }
  .status-done { color: var(--green); }
  .status-error { color: var(--red); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
  .main { display: grid; grid-template-columns: 340px 1fr; gap: 0; height: calc(100vh - 60px); }
  .sidebar { border-right: 1px solid var(--border); padding: 20px; overflow-y: auto; background: var(--panel); }
  .log-area { display: flex; flex-direction: column; overflow: hidden; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: var(--dim); margin: 0 0 12px; }
  form { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
  label { font-size: 12px; color: var(--dim); }
  input, select { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 8px 10px; border-radius: 4px; font-family: var(--mono); font-size: 13px; width: 100%; }
  input:focus, select:focus { outline: none; border-color: var(--red); }
  button { background: var(--red); color: #fff; border: none; padding: 10px; border-radius: 4px; font-family: var(--mono); font-weight: bold; cursor: pointer; font-size: 13px; letter-spacing: 1px; }
  button:disabled { background: var(--border); color: var(--dim); cursor: not-allowed; }
  button:hover:enabled { background: #ff3333; }
  .summary { font-size: 12px; line-height: 1.8; }
  .summary .row { display: flex; justify-content: space-between; padding: 2px 0; }
  .summary .val { color: var(--cyan); font-weight: bold; }
  .vert-badge { display: block; margin-top: 12px; padding: 10px; text-align: center; background: rgba(77,255,136,.1); border: 1px solid var(--green); border-radius: 6px; color: var(--green); font-weight: bold; letter-spacing: 1px; }
  .log-header { padding: 12px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--panel); }
  .log-count { color: var(--dim); font-size: 12px; }
  #log { flex: 1; overflow-y: auto; padding: 16px 20px; font-size: 13px; line-height: 1.7; }
  .line { white-space: pre-wrap; word-break: break-all; }
  .ts { color: var(--dim); }
  .node { color: var(--cyan); }
  .node-recon { color: var(--cyan); }
  .node-exploit { color: var(--yellow); }
  .node-triage { color: #cc88ff; }
  .node-patch { color: var(--green); }
  .node-report { color: #88ccff; }
  .node-monitor { color: var(--red); font-weight: bold; }
  .event-log .text { color: var(--text); }
  .event-summary { padding: 10px 12px; margin: 8px 0; border: 1px solid var(--border); border-radius: 4px; background: rgba(77,204,255,.05); }
  .event-status { padding: 6px 0; border-top: 1px dashed var(--border); margin-top: 6px; }
  .link { color: var(--cyan); text-decoration: none; word-break: break-all; }
  .link:hover { text-decoration: underline; }
  .clear-btn { background: transparent; border: 1px solid var(--border); color: var(--dim); padding: 4px 10px; font-size: 11px; border-radius: 4px; }
  .clear-btn:hover { border-color: var(--red); color: var(--red); }
</style>
</head>
<body>
<div class="header">
  <span class="logo">▄▄▄ ROGUE</span>
  <span class="subtitle">Autonomous AI Red Team — Monitoring Station</span>
  <span id="pill" class="status-pill status-idle">IDLE</span>
</div>
<div class="main">
  <div class="sidebar">
    <h2>Launch Scan</h2>
    <form id="scanForm">
      <div><label for="target">Target Path</label>
        <input id="target" name="target" placeholder="/path/to/codebase" required>
      </div>
      <div><label for="mode">Mode</label>
        <select id="mode" name="mode">
          <option value="fix">fix (generate patch)</option>
          <option value="report">report (write report)</option>
        </select>
      </div>
      <div><label for="model">Model (LiteLLM format — blank = saved default)</label>
        <input id="model" name="model" list="modelPresets" placeholder="openai/qwen-max">
        <datalist id="modelPresets">
          <option value="openai/qwen-max">openai/qwen-max — Qwen Cloud (default)</option>
          <option value="gpt-4o">gpt-4o — OpenAI</option>
          <option value="claude-sonnet-4-5">claude-sonnet-4-5 — Anthropic</option>
          <option value="gemini/gemini-2.0-flash">gemini/gemini-2.0-flash — Google</option>
          <option value="groq/llama-3.3-70b-versatile">groq/llama-3.3-70b-versatile — Groq</option>
          <option value="ollama/llama3.1">ollama/llama3.1 — local Ollama</option>
        </datalist>
      </div>
      <button id="runBtn" type="submit">▶ RUN SCAN</button>
    </form>

    <h2>Summary</h2>
    <div id="summary" class="summary">
      <div class="row"><span>Status</span><span class="val" id="sumStatus">idle</span></div>
      <div class="row"><span>Findings</span><span class="val" id="sumFindings">—</span></div>
      <div class="row"><span>Confirmed</span><span class="val" id="sumConfirmed">—</span></div>
      <div class="row"><span>False Positives</span><span class="val" id="sumFP">—</span></div>
      <div class="row"><span>Unverified</span><span class="val" id="sumInc">—</span></div>
    </div>
    <div id="vertArea"></div>
    <div id="linksArea" style="margin-top:16px;font-size:12px;line-height:1.8;"></div>
  </div>

  <div class="log-area">
    <div class="log-header">
      <h2 style="margin:0">Live Agent Log</h2>
      <div>
        <span class="log-count" id="count">0 lines</span>
        <button class="clear-btn" onclick="document.getElementById('log').innerHTML='';">clear</button>
      </div>
    </div>
    <div id="log"></div>
  </div>
</div>

<script>
const pill = document.getElementById('pill');
const logEl = document.getElementById('log');
const countEl = document.getElementById('count');
const runBtn = document.getElementById('runBtn');
const form = document.getElementById('scanForm');
let lineCount = 0;
let autoScroll = true;

logEl.addEventListener('scroll', () => {
  autoScroll = (logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight) < 60;
});

function setPill(status) {
  pill.className = 'status-pill status-' + status;
  pill.textContent = status.toUpperCase();
  document.getElementById('sumStatus').textContent = status;
  runBtn.disabled = (status === 'running');
}

function appendLog(e) {
  if (e.type === 'log') {
    const div = document.createElement('div');
    div.className = 'line event-log';
    const nodeCls = 'node node-' + (e.node || 'monitor');
    div.innerHTML = '<span class="ts">[' + e.ts + ']</span> <span class="' + nodeCls + '">[' + (e.node||'monitor') + ']</span> <span class="text">' + escapeHtml(e.text) + '</span>';
    logEl.appendChild(div);
    lineCount++;
  } else if (e.type === 'status') {
    setPill(e.status);
    const div = document.createElement('div');
    div.className = 'line event-status';
    div.innerHTML = '<span class="ts">[' + e.ts + ']</span> <span class="node">— status: ' + e.status + '</span>';
    logEl.appendChild(div);
    lineCount++;
  } else if (e.type === 'summary') {
    renderSummary(e.summary);
  }
  countEl.textContent = lineCount + ' lines';
  if (autoScroll) logEl.scrollTop = logEl.scrollHeight;
}

function renderSummary(s) {
  document.getElementById('sumFindings').textContent = s.findings;
  document.getElementById('sumConfirmed').textContent = s.confirmed;
  document.getElementById('sumFP').textContent = s.false_positives;
  document.getElementById('sumInc').textContent = (s.inconclusive !== undefined) ? s.inconclusive : '—';
  const vert = document.getElementById('vertArea');
  if (s.vert) {
    vert.innerHTML = '<span class="vert-badge">✓ VERT — Clean Bill of Health</span>';
  } else if (s.inconclusive > 0 && s.confirmed === 0) {
    vert.innerHTML = '<span class="vert-badge" style="background:rgba(255,204,77,.1);border-color:var(--yellow);color:var(--yellow);">⚠ INCOMPLETE — findings unverified</span>';
  } else {
    vert.innerHTML = '';
  }
  const links = document.getElementById('linksArea');
  let html = '';
  if (s.log_path) {
    const safe = s.log_path.replace(/^.*?\/logs\//, '/logs/');
    html += '<div><a class="link" href="' + safe + '" target="_blank">📄 ' + basename(s.log_path) + '</a></div>';
  }
  if (s.report_path) {
    html += '<div><a class="link" href="' + s.report_path + '" target="_blank">📋 ' + basename(s.report_path) + '</a></div>';
  }
  links.innerHTML = html;
}

function basename(p) { return p.split('/').pop(); }
function escapeHtml(s) { return s.replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = {
    target: document.getElementById('target').value,
    mode: document.getElementById('mode').value,
    model: document.getElementById('model').value,
  };
  runBtn.disabled = true;
  logEl.innerHTML = '';
  lineCount = 0;
  countEl.textContent = '0 lines';
  document.getElementById('vertArea').innerHTML = '';
  document.getElementById('linksArea').innerHTML = '';
  setPill('running');
  try {
    const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const j = await r.json();
    if (!r.ok) {
      appendLog({type:'log', ts:new Date().toTimeString().slice(0,8), node:'monitor', text:'ERROR: ' + (j.error || 'scan failed')});
      setPill('error');
    }
  } catch (err) {
    appendLog({type:'log', ts:new Date().toTimeString().slice(0,8), node:'monitor', text:'ERROR: ' + err.message});
    setPill('error');
  }
});

fetch('/api/status').then(r => r.json()).then(s => {
  setPill(s.status);
  if (s.summary) renderSummary(s.summary);
});

const es = new EventSource('/stream');
es.onmessage = (ev) => {
  try { appendLog(JSON.parse(ev.data)); } catch(e) {}
};
es.onerror = () => { setTimeout(() => { if (es.readyState === EventSource.CLOSED) es = new EventSource('/stream'); }, 2000); };
</script>
</body>
</html>"""
