"""
Sn1per Report Parser
Watches Sn1per's loot folder for new/changed reports,
parses findings, and sends a prompt to Ollama (Qwen 7b).
"""

import os
import time
import json
import re
import requests
from pathlib import Path
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

# Config
LOOT_DIR = "/loot"
OLLAMA_URL = "http://ollama:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:7b"
OUTPUT_DIR = "/output"
WATCH_INTERVAL = 2

SEVERITY_MAP = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
    "P5": "Info",
}

processed = set()


def parse_vuln_report(report_path):
    findings = []
    target = report_path.parent.parent.name
    text = report_path.read_text(errors="replace")

    pattern = re.compile(
        r"(P[1-5])\s*-\s*\w+,\s*(.+?),\s*\[(.+?)\],\s*(\S+)"
    )

    for match in pattern.finditer(text):
        severity_code, tool, template, url = match.groups()
        findings.append({
            "severity": SEVERITY_MAP.get(severity_code, severity_code),
            "severity_code": severity_code,
            "tool": tool.strip(),
            "template": template.strip(),
            "url": url.strip(),
        })

    counts = {}
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        m = re.search(rf"{level}:\s*(\d+)", text)
        counts[level] = int(m.group(1)) if m else 0

    score_m = re.search(r"Score:\s*(\d+)", text)
    score = int(score_m.group(1)) if score_m else 0

    return {
        "target": target,
        "counts": counts,
        "score": score,
        "findings": findings,
    }


def build_prompt(parsed):
    target = parsed["target"]
    counts = parsed["counts"]
    findings = parsed["findings"]

    findings_text = "\n".join(
        "  - [" + f["severity"] + "] " + f["template"] + " via " + f["tool"] + " at " + f["url"]
        for f in findings
    ) or "  - No vulnerabilities detected."

    prompt = (
        "You are a professional penetration tester writing a vulnerability analysis report.\n\n"
        "Target: " + target + "\n"
        "Scan Summary:\n"
        "  Critical: " + str(counts.get("Critical", 0)) + "\n"
        "  High:     " + str(counts.get("High", 0)) + "\n"
        "  Medium:   " + str(counts.get("Medium", 0)) + "\n"
        "  Low:      " + str(counts.get("Low", 0)) + "\n"
        "  Info:     " + str(counts.get("Info", 0)) + "\n"
        "  Risk Score: " + str(parsed["score"]) + "\n\n"
        "Findings:\n" + findings_text + "\n\n"
        "For each finding above, provide:\n"
        "1. What the vulnerability is\n"
        "2. Why it is a risk\n"
        "3. How to fix it\n\n"
        "Write in clear, professional English suitable for a client report.\n"
        'Format your response as JSON with this structure:\n'
        '{"executive_summary": "...", "findings": [{"title": "...", "severity": "...", "description": "...", "risk": "...", "remediation": "..."}]}'
    )
    return prompt


def send_to_ollama(prompt):
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to Ollama. Is it running?")
        return ""
    except Exception as e:
        print("[ERROR] Ollama request failed: " + str(e))
        return ""


def save_output(parsed, ai_response):
    """Save combined raw findings + AI analysis for html-maker."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    target = parsed["target"]

    # Parse AI response JSON (strip markdown fences if needed)
    raw = ai_response.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        ai_data = json.loads(raw)
    except Exception:
        ai_data = {"executive_summary": ai_response, "findings": []}

    combined = {
        "target": target,
        "counts": parsed["counts"],
        "score": parsed["score"],
        "raw_findings": parsed["findings"],
        "ai_analysis": ai_data,
    }

    out_file = Path(OUTPUT_DIR) / (target + "-analysis.json")
    out_file.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print("[OK] Saved analysis to " + str(out_file))


def process_report(report_path):
    print("[*] Processing: " + str(report_path))
    parsed = parse_vuln_report(report_path)

    if not parsed["findings"] and parsed["score"] == 0:
        print("[SKIP] No findings in " + report_path.name)
        return

    prompt = build_prompt(parsed)
    print("[*] Sending to Ollama (" + OLLAMA_MODEL + ")...")

    ai_response = send_to_ollama(prompt)
    if ai_response:
        save_output(parsed, ai_response)
    else:
        print("[WARN] Empty response from Ollama, skipping save.")


class ReportHandler(FileSystemEventHandler):
    def on_created(self, event):
        self._handle(event.src_path)

    def on_modified(self, event):
        self._handle(event.src_path)

    def _handle(self, path):
        p = Path(path)
        if p.name.startswith("vulnerability-report-"):
            if str(p) not in processed:
                processed.add(str(p))
                time.sleep(1)
                process_report(p)


def scan_existing(loot_dir):
    for report in loot_dir.rglob("vulnerability-report-*.txt"):
        if str(report) not in processed:
            processed.add(str(report))
            process_report(report)


def main():
    loot_dir = Path(LOOT_DIR)
    loot_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Sn1per Parser started")
    print("[*] Watching: " + LOOT_DIR)
    print("[*] Ollama:   " + OLLAMA_URL + " (" + OLLAMA_MODEL + ")")
    print("[*] Output:   " + OUTPUT_DIR)

    scan_existing(loot_dir)

    observer = Observer()
    observer.schedule(ReportHandler(), str(loot_dir), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(WATCH_INTERVAL)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
