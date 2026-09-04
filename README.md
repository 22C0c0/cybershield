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
