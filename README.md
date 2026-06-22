# Sn1perDash

Automated penetration testing report pipeline. Runs Sn1per scans, parses findings, analyzes them with a local AI model, and renders clean HTML reports — all in Docker.

---

## How it works

```
loot/               →   python-parser   →   output/              →   html-maker   →   reports/
(Sn1per scan data)      (parse + AI)        (JSON analysis)          (render)         (HTML reports)
```

1. **Sn1per** scans a target and writes results to `loot/<workspace>/vulnerabilities/`
2. **python-parser** watches `loot/` for new reports, parses findings (P1–P5 severity), sends them to Ollama for AI analysis, and saves a combined JSON to `output/`
3. **Ollama** runs Qwen 2.5:7b locally — no data leaves your machine
4. **html-maker** watches `output/` for new JSON files and renders a tabbed HTML report into `reports/`

---

## Services

| Service | Description |
|---|---|
| `sn1per` | Sn1per community edition (xer0dayz/sn1per) |
| `python-parser` | Parses Sn1per reports and queries Ollama |
| `ollama` | Local LLM server running Qwen 2.5:7b |
| `html-maker` | Renders JSON analysis into HTML reports |

---

## Requirements

- Docker + Docker Compose
- NVIDIA GPU (RTX 3050 6GB or better) with NVIDIA Container Toolkit
- ~5GB disk space for the Qwen 2.5:7b model

---

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/sn1perDash.git
cd sn1perDash

# Create required folders
mkdir loot output reports

# Start all services
docker compose up -d

# Pull the AI model (first time only)
docker exec -it ollama ollama pull qwen2.5:7b
```

---

## Usage

Drop a Sn1per workspace folder into `loot/`:

```
loot/
└── my-target/
    └── vulnerabilities/
        └── vulnerability-report-*.txt
```

The pipeline picks it up automatically. Reports appear in `reports/` as `<target>-report.html`.

---

## Report layout

Each HTML report has two tabs:

- **Raw Findings** — table of everything Sn1per found (severity, finding, tool, URL)
- **AI Analysis** — Qwen's structured breakdown with description, risk, and remediation per finding

---

## Shutdown / Startup

```bash
# Safe shutdown
docker compose down

# Start again
docker compose up -d
```

Scan data in `loot/`, `output/`, and `reports/` persists between restarts.
