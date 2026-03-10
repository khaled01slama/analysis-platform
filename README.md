# Security Analysis Platform

A security analysis workbench that ties together vulnerability scanning, dead-code detection, SBOM parsing, and an AI assistant behind a single FastAPI backend and browser UI.

I built this because I kept switching between half a dozen CLI tools every time I needed to audit a codebase. Now everything lives in one place: upload an SBOM, run a Vanir scan, point Joern at your source tree, and the correlation engine figures out which vulnerabilities actually matter by checking whether the affected code is even reachable.

---

## What's inside

| Component | What it does |
|---|---|
| **SBOM Analyzer** | Parses SPDX and CycloneDX files, extracts packages and known vulnerabilities |
| **Vanir** (Google) | Source-level static analysis that detects missing security patches in C/C++ and Java — mainly targeting Android & Linux kernel code |
| **Joern** | Builds a Code Property Graph from your source and finds unused/dead functions |
| **Correlation Engine** | Cross-references Vanir vulnerability hits with Joern's dead-code results so you can deprioritize vulns in code that's never called |
| **Security Assistant** | LangGraph agent backed by Groq (Llama 3.1) that can answer questions, query the local DB, and search the web for CVE details |
| **Dashboard** | Single-page frontend that shows scan results, history, and lets you chat with the assistant |

## Project layout

```
├── api/                  FastAPI app + route handlers
│   └── routes/           /api/sbom, /api/correlation, /api/security, /api/dashboard
├── correlation_engine/   Correlator logic + SQLite integration
├── sbom_analyzer/        SPDX/CycloneDX parser and converter
├── security_assistant/   LangGraph agent, tools, web search, prompts
├── vanir/                Wrapper + Google Vanir (git submodule)
├── detection_script/     Joern shell scripts (find_non_called_methods.sh)
├── frontend/             Static SPA (vanilla JS, no build step)
├── docker-entrypoint.sh  Entrypoint that validates components and starts uvicorn
├── Dockerfile            Multi-stage build (Vanir Bazel build → runtime image)
└── docker-compose.yml    One-command deployment
```

## Requirements

- **Python 3.10+** (tested on 3.11)
- **Java 11+** (needed by both Joern and Vanir's Bazel build — JDK 21 works fine)
- **Bazel 8.x** — only if you're building Vanir from source
- **Linux** (Ubuntu 22.04 recommended). macOS should work for the API/SBOM parts, but Joern and Vanir are Linux-focused.
- ~4 GB RAM minimum, 8 GB recommended (Joern's CPG generation can be hungry)

## Getting started

### 1. Clone

```bash
git clone --recurse-submodules https://github.com/khaled01slama/analysis-platform.git
cd analysis-platform
```

If you already cloned without `--recurse-submodules`:
```bash
git submodule update --init --recursive
```

### 2. Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Set up your `.env`

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

The only required key is `GROQ_API_KEY` (get one free at https://console.groq.com/keys). Everything else has sensible defaults.

```dotenv
GROQ_API_KEY=gsk_your_key_here
GROQ_MODEL=llama-3.1-8b-instant
```

### 4. Run

**Quick start (no Docker):**
```bash
./start.sh
```

**Or with the full entrypoint (validates all components):**
```bash
./docker-entrypoint.sh
```

**With Docker:**
```bash
docker compose up --build
```

The app will be at:
- **Frontend:** http://localhost:8000/
- **API docs:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/api/health

## Installing the external tools

### Joern

Joern does dead-code analysis by building a Code Property Graph from your source.

```bash
mkdir -p tools/joern && cd tools/joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
chmod +x joern-install.sh
./joern-install.sh --install-dir=$(pwd)/joern-cli
```

Then either add it to your PATH or set `JOERN_HOME`:
```bash
export PATH="$(pwd)/joern-cli/bin:$PATH"
```

Test it:
```bash
joern --version
```

### Vanir

Vanir is Google's tool for detecting missing security patches. The source is included as a git submodule under `vanir/vanir/`.

**Build from source (requires Bazel):**
```bash
cd vanir/vanir
bazel build //:detector_runner --build_python_zip -c opt
```

The binary ends up at `bazel-bin/detector_runner`. Copy it somewhere handy:
```bash
mkdir -p ../../tools/vanir
cp bazel-bin/detector_runner bazel-bin/detector_runner.zip ../../tools/vanir/
export VANIR_PATH="$(pwd)/../../tools/vanir"
```

Test it:
```bash
$VANIR_PATH/detector_runner --help
```

## How to use it

### SBOM analysis

Upload an SPDX or CycloneDX file through the UI (SBOM tab) or via the API:

```bash
curl -X POST http://localhost:8000/api/sbom/upload \
  -F "file=@my-sbom.spdx.json"
```

### Joern dead-code scan

```bash
./docker-entrypoint.sh joern-analyze /path/to/source MyProject output.json
```

Or use the script directly:
```bash
bash detection_script/find_non_called_methods.sh /path/to/source MyProject results.json
```

### Vanir patch detection

```bash
./docker-entrypoint.sh vanir-scan offline_directory_scanner /path/to/source
```

### Correlation

Upload both Vanir and Joern results through the Correlation tab. The engine matches CVE-affected files with Joern's dead-function list and flags which vulnerabilities are in actively-used code versus dead code.

### Security Assistant

Open the Security tab and ask questions in natural language. The agent can:
- Query your local scan results ("which CVEs affect my project?")
- Search the web for vulnerability details
- Explain remediation steps

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | API key for Groq LLM (required for the security assistant) |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | Which Groq model to use |
| `VANIR_PATH` | `/opt/vanir` | Path to Vanir detector_runner binary |
| `JOERN_HOME` | `/opt/joern` | Path to Joern installation |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `WORKERS` | `1` | Uvicorn worker count |

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn
- **AI:** LangGraph, LangChain, Groq (Llama 3.1)
- **Analysis:** Google Vanir, Joern, spdx-tools
- **Frontend:** Vanilla JavaScript SPA (no framework, no build step)
- **Storage:** SQLite (via the correlation engine's DB layer)
- **Deployment:** Docker, Docker Compose

## License

This project is provided as-is for educational and research purposes. Google Vanir (in `vanir/vanir/`) is licensed under the BSD license — see its own LICENSE file.

