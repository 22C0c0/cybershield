# CyberShield — High-Performance Cybersecurity Suite

<p align="center">
  <strong>6-in-1 cybersecurity platform for network monitoring, threat detection, vulnerability assessment, and security operations.</strong>
</p>

---

## Modules

| Module | Port | Description |
|--------|------|-------------|
| **NIDS** | 8001 | Network Intrusion Detection System — real-time packet analysis & threat detection |
| **Malware Sandbox** | 8002 | Static & dynamic analysis of suspicious files with YARA rules |
| **Vulnerability Scanner** | 8003 | High-speed port scanning & CVE detection across networks |
| **SIEM** | 8004 | Log ingestion, correlation engine, and alert management |
| **Zero Trust Proxy** | 8005 | Authentication, authorization, MFA, and audit logging |
| **Secrets Detector** | 8006 | Scan repositories for leaked credentials, API keys, and secrets |

## Quick Start

### Prerequisites
- Docker & Docker Compose v2+
- Python 3.11+ (for local development)
- Linux recommended (full functionality for NIDS requires `NET_RAW` capability)

### 1. Clone & Start

```bash
git clone https://github.com/22C0c0/cybershield.git
cd cybershield
cp .env.example .env
# Edit .env with your configuration

docker compose up -d
```

### 2. Verify All Services

```bash
# Check health of all modules
for port in 8001 8002 8003 8004 8005 8006; do
  echo "Port $port:" && curl -s http://localhost:$port/health
done
```

### 3. Access APIs

| Service | URL | Docs |
|---------|-----|------|
| NIDS | http://localhost:8001 | http://localhost:8001/docs |
| Malware Sandbox | http://localhost:8002 | http://localhost:8002/docs |
| Vuln Scanner | http://localhost:8003 | http://localhost:8003/docs |
| SIEM | http://localhost:8004 | http://localhost:8004/docs |
| Zero Trust Proxy | http://localhost:8005 | http://localhost:8005/docs |
| Secrets Detector | http://localhost:8006 | http://localhost:8006/docs |

## Local Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run a specific module (example: SIEM)
python -m modules.siem.src.api

# Run tests
pytest -v

# Lint & format
ruff check .
ruff format .
```

> **Note:** Python 3.12+ is required for the GUI (PySide6).

## Desktop GUI

A PySide6 desktop application wraps every module in one window — no Docker or
running services required; it imports the module engines directly in-process.

Tabs:
1. **Dashboard** — living status of all modules + aggregated global alerts
2. **NIDS** — live packet capture (start/stop), stats, signatures, alerts
3. **Malware Sandbox** — pick a file, run static/dynamic analysis, view risk
   score, verdict and hashes
4. **Vuln Scanner** — scan a host or CIDR network, review open ports and CVEs
5. **SIEM** — ingest pasted log lines or a log file, view generated alerts
6. **Zero Trust** — register/login/logout, role-based access checks, audit trail
7. **Secrets Detector** — scan files, folders, git repos or raw content

```bash
# Install (PySide6 + base requirements)
pip install -r requirements-gui.txt

# Launch the GUI
python -m gui.app
# or, after `pip install -e .`
cybershield-gui
```

Run the windowed app from a graphical session (needs a display server).

### Cross-platform — Windows / macOS / Linux

The GUI and all module engines are platform-agnostic. Build a standalone
executable for any OS from CI or locally:

| Platform | Build                     | Output                  |
|----------|---------------------------|-------------------------|
| Windows  | `build\gui.bat` (cmd)     | `dist\cybershield-gui.exe` |
| macOS    | `bash build/gui.sh`       | `dist/cybershield-gui`  |
| Linux    | `bash build/gui.sh`       | `dist/cybershield-gui`  |

```bash
# One-time venv + deps (adds PyInstaller on top of requirements-gui.txt)
bash build/gui.sh --install        # Linux / macOS
build\gui.bat --install            # Windows

# Build the bundle
bash build/gui.sh                  # Linux / macOS
build\gui.bat                      # Windows
```

Notes:
- Bundling uses `packaging/cybershield-gui.spec` (single-file app, no Python
  required on the target machine).
- **NIDS capture** needs elevated privileges: root/`CAP_NET_RAW` on Linux
  (`sudo setcap cap_net_raw+ep ./dist/cybershield-gui`), Administrator on
  Windows, or root/sudo on macOS. Other modules work without privileges.
- **NIDS interface** is auto-detected per platform (`eth0`/`en0`/Windows
  adapter) and can be overridden in the GUI.
- The malware sandbox executes the analyzed file in an isolated temp dir;
  enable the checkbox with caution (it actually runs the target).

## CI/CD

The repository uses GitHub Actions (`.github/workflows/ci.yml`) with three stages:

1. **Lint** — `ruff check .` and `ruff format --check .`
2. **Test** — `pytest -v` (52 unit tests across all modules and shared libraries)
3. **Docker** (on `main` only) — builds all images with `docker compose build`, starts the stack, and verifies the `/health` endpoint on every module port (8001–8006)

## API Examples

### NIDS — Start packet capture
```bash
curl -X POST http://localhost:8001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "packet_count": 1000}'
```

### Malware Sandbox — Analyze a file
```bash
curl -X POST http://localhost:8002/api/v1/analyze \
  -F "file=@suspicious_file.exe"
```

### Vulnerability Scanner — Scan a host
```bash
curl -X POST http://localhost:8003/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "ports": [22, 80, 443]}'
```

### SIEM — Ingest logs
```bash
curl -X POST http://localhost:8004/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{"logs": ["Failed password for root from 192.168.1.100 port 22 ssh2"], "source": "auth-log"}'
```

### Zero Trust Proxy — Register & Login
```bash
# Register
curl -X POST http://localhost:8005/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "securepass123"}'

# Login
curl -X POST http://localhost:8005/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "securepass123"}'
```

### Secrets Detector — Scan a directory
```bash
curl -X POST http://localhost:8006/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/scan", "max_depth": 5}'
```

## Architecture

```
cybershield/
├── shared/                 # Shared libraries (config, logging, models, crypto)
├── modules/
│   ├── nids/              # Network Intrusion Detection System
│   ├── malware_sandbox/   # Malware Analysis Sandbox
│   ├── vuln_scanner/      # Vulnerability Scanner
│   ├── siem/              # Security Information & Event Management
│   ├── zero_trust_proxy/  # Zero Trust Authentication Proxy
│   └── secrets_detector/  # Secrets & Credential Leak Detector
├── docker-compose.yml     # Full orchestration (docker compose v2+)
├── requirements.txt       # Python dependencies
├── pyproject.toml         # Project configuration (incl. ruff, pytest)
└── .github/workflows/     # GitHub Actions CI/CD pipeline
```

## Security Notes

- **Default admin password** in Zero Trust Proxy is `admin123` — change immediately in production
- **NIDS** requires `NET_RAW` capability (runs in `--network=host` mode)
- **Malware Sandbox** executes files in isolated containers — do NOT expose to untrusted networks
- Never commit `.env` files with real credentials
- All modules write structured JSON logs for easy integration with log aggregators

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.
