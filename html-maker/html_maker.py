"""
HTML Maker
Watches /output for AI analysis JSON files from the parser,
renders them into clean tabbed HTML pentest reports in /reports.
"""

import os
import json
import time
from pathlib import Path
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

OUTPUT_DIR = "/output"
REPORTS_DIR = "/reports"

processed = set()

SEVERITY_COLOR = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2980b9",
    "Info":     "#95a5a6",
}

SEVERITY_TEXT_COLOR = {
    "Critical": "#fff",
    "High":     "#fff",
    "Medium":   "#333",
    "Low":      "#fff",
    "Info":     "#fff",
}


def render_html(target, data):
    counts = data.get("counts", {})
    score = data.get("score", 0)
    raw_findings = data.get("raw_findings", [])
    ai_data = data.get("ai_analysis", {})
    summary = ai_data.get("executive_summary", "No summary provided.")
    ai_findings = ai_data.get("findings", [])
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Raw findings tab ---
    if raw_findings:
        raw_rows = ""
        for f in raw_findings:
            sev = f.get("severity", "Info")
            bg = SEVERITY_COLOR.get(sev, "#95a5a6")
            tc = SEVERITY_TEXT_COLOR.get(sev, "#fff")
            raw_rows += (
                "<tr>"
                "<td><span class='badge' style='background:" + bg + ";color:" + tc + ";'>" + sev + "</span></td>"
                "<td>" + f.get("template", "-") + "</td>"
                "<td>" + f.get("tool", "-") + "</td>"
                "<td class='url-cell'>" + f.get("url", "-") + "</td>"
                "</tr>"
            )
        raw_tab_html = (
            "<table class='findings-table'>"
            "<thead><tr><th>Severity</th><th>Finding</th><th>Tool</th><th>URL</th></tr></thead>"
            "<tbody>" + raw_rows + "</tbody>"
            "</table>"
        )
    else:
        raw_tab_html = "<p class='empty-msg'>No raw findings recorded.</p>"

    # --- AI analysis tab ---
    if ai_findings:
        ai_cards = ""
        for f in ai_findings:
            sev = f.get("severity", "Info")
            bg = SEVERITY_COLOR.get(sev, "#95a5a6")
            tc = SEVERITY_TEXT_COLOR.get(sev, "#fff")
            ai_cards += (
                "<div class='card'>"
                "<div class='card-header'>"
                "<span class='badge' style='background:" + bg + ";color:" + tc + ";'>" + sev + "</span>"
                "<strong>" + f.get("title", "Untitled") + "</strong>"
                "</div>"
                "<div class='card-body'>"
                "<p><span class='label'>Description</span>" + f.get("description", "-") + "</p>"
                "<p><span class='label'>Risk</span>" + f.get("risk", "-") + "</p>"
                "<p><span class='label'>Remediation</span>" + f.get("remediation", "-") + "</p>"
                "</div>"
                "</div>"
            )
    else:
        ai_cards = "<p class='empty-msg'>No AI analysis available.</p>"

    # --- Summary chips ---
    chips = ""
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        n = counts.get(level, 0)
        bg = SEVERITY_COLOR.get(level, "#95a5a6")
        tc = SEVERITY_TEXT_COLOR.get(level, "#fff")
        chips += "<span class='chip' style='background:" + bg + ";color:" + tc + ";'>" + level + " <strong>" + str(n) + "</strong></span>"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report - """ + target + """</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f8; color: #2c3e50; }

  .topbar { background: #2c3e50; color: #fff; padding: 18px 40px; display: flex; align-items: center; justify-content: space-between; }
  .topbar h1 { font-size: 1.3rem; letter-spacing: 1px; }
  .topbar h1 span { color: #e74c3c; }
  .topbar .meta { font-size: 0.8rem; color: #bdc3c7; }

  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }

  .summary-box { background: #fff; border-radius: 10px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
  .summary-box h2 { font-size: 0.95rem; text-transform: uppercase; letter-spacing: 1px; color: #7f8c8d; margin-bottom: 12px; }
  .summary-box p { line-height: 1.7; color: #34495e; }

  .chips { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 24px; }
  .chip { padding: 6px 16px; border-radius: 20px; font-size: 0.85rem; }

  .tabs { display: flex; gap: 0; margin-bottom: 0; border-bottom: 2px solid #dde1e7; }
  .tab-btn { padding: 12px 28px; border: none; background: none; cursor: pointer; font-size: 0.95rem; color: #7f8c8d; border-bottom: 3px solid transparent; margin-bottom: -2px; transition: all 0.2s; font-weight: 500; }
  .tab-btn.active { color: #2c3e50; border-bottom-color: #e74c3c; }
  .tab-btn:hover { color: #2c3e50; }

  .tab-panel { display: none; background: #fff; border-radius: 0 0 10px 10px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
  .tab-panel.active { display: block; }

  /* Raw findings table */
  .findings-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  .findings-table th { background: #f4f6f8; padding: 10px 14px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; color: #7f8c8d; border-bottom: 2px solid #dde1e7; }
  .findings-table td { padding: 10px 14px; border-bottom: 1px solid #eef0f3; vertical-align: top; }
  .findings-table tr:last-child td { border-bottom: none; }
  .url-cell { font-family: monospace; font-size: 0.8rem; word-break: break-all; color: #2980b9; }

  /* AI analysis cards */
  .card { border: 1px solid #e8eaed; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .card-header { display: flex; align-items: center; gap: 12px; padding: 14px 18px; background: #f9fafb; border-bottom: 1px solid #e8eaed; }
  .card-header strong { font-size: 0.95rem; }
  .card-body { padding: 18px; }
  .card-body p { margin-bottom: 12px; line-height: 1.7; color: #34495e; }
  .card-body p:last-child { margin-bottom: 0; }
  .label { display: inline-block; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #7f8c8d; margin-right: 8px; min-width: 90px; }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
  .empty-msg { color: #95a5a6; font-style: italic; padding: 20px 0; }

  .score-bar { display: inline-block; background: #e74c3c; color: #fff; padding: 4px 14px; border-radius: 20px; font-size: 0.85rem; font-weight: 700; }

  footer { text-align: center; color: #bdc3c7; font-size: 0.8rem; margin: 40px 0 20px; }
</style>
</head>
<body>

<div class="topbar">
  <h1>Sn1per<span>Dash</span> &mdash; Pentest Report</h1>
  <div class="meta">Target: <strong style="color:#fff">""" + target + """</strong> &nbsp;|&nbsp; """ + generated + """</div>
</div>

<div class="container">

  <div class="summary-box">
    <h2>Executive Summary</h2>
    <p>""" + summary + """</p>
  </div>

  <div class="chips">
    """ + chips + """
    <span class="chip score-bar">Risk Score: """ + str(score) + """</span>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('raw', this)">Raw Findings</button>
    <button class="tab-btn" onclick="switchTab('ai', this)">AI Analysis</button>
  </div>

  <div id="tab-raw" class="tab-panel active">
    """ + raw_tab_html + """
  </div>

  <div id="tab-ai" class="tab-panel">
    """ + ai_cards + """
  </div>

</div>

<footer>Generated by Sn1perDash &nbsp;|&nbsp; Powered by Qwen 2.5 via Ollama</footer>

<script>
function switchTab(name, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}
</script>

</body>
</html>"""


def process_json(json_path):
    print("[*] Rendering: " + json_path.name)
    try:
        data = json.loads(json_path.read_text(errors="replace"))
    except json.JSONDecodeError as e:
        print("[ERROR] Invalid JSON in " + json_path.name + ": " + str(e))
        return

    target = data.get("target") or json_path.stem.replace("-analysis", "")
    html = render_html(target, data)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    out = Path(REPORTS_DIR) / (target + "-report.html")
    out.write_text(html, encoding="utf-8")
    print("[OK] Report saved: " + str(out))


class JsonHandler(FileSystemEventHandler):
    def on_created(self, event):
        self._handle(event.src_path)

    def on_modified(self, event):
        self._handle(event.src_path)

    def _handle(self, path):
        p = Path(path)
        if p.suffix == ".json" and str(p) not in processed:
            processed.add(str(p))
            time.sleep(3)
            process_json(p)


def scan_existing(output_dir):
    for f in output_dir.glob("*.json"):
        if str(f) not in processed:
            processed.add(str(f))
            process_json(f)


def main():
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[*] HTML Maker started")
    print("[*] Watching: " + OUTPUT_DIR)
    print("[*] Reports:  " + REPORTS_DIR)

    scan_existing(output_dir)

    observer = Observer()
    observer.schedule(JsonHandler(), str(output_dir), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
