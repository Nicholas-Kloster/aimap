# aimap

**nmap for AI infrastructure.** Finds every exposed LLM, vector database, and AI model server on a network and tells you exactly what's running, what's unprotected, and what data is inside.

Single binary, zero external dependencies (Go stdlib only).

## Features

- **16 service fingerprints**: Weaviate, ChromaDB, Qdrant, Ollama, vLLM, LocalAI, text-generation-webui, MLflow, TensorFlow Serving, Triton Inference Server, Ray Serve, LangServe, Flowise, Open WebUI, LiteLLM, Jupyter Notebook
- **3-phase pipeline**: Port scan → Service fingerprint → Deep enumeration
- **Deep enumerators** for Weaviate, Ollama, ChromaDB, Qdrant, Flowise, Jupyter, MLflow
- **Generic checks**: CORS misconfig, API key leaks, header disclosure
- **PII field detection** in vector database schemas
- **CIDR support** for scanning ranges
- **JSON reporting** for pipeline integration
- Colored terminal output with risk scoring

## Install

```
go install github.com/Nicholas-Kloster/aimap@latest
```

Or build from source:

```
git clone https://github.com/Nicholas-Kloster/aimap.git
cd aimap
go build -o aimap .
```

## Usage

```
aimap -target <ip|host|cidr> [flags]
aimap -list targets.txt [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Single target (IP, hostname, or CIDR) |
| `-list` | | File of targets, one per line |
| `-ports` | `8080,8443,11434,8000,3000,6333,19530,8888,8501,9090,5000,4000,7860,3001` | Ports to scan |
| `-timeout` | `5s` | Connection timeout |
| `-threads` | `20` | Concurrent scan threads |
| `-o` | | JSON report output file |
| `-v` | | Verbose output |

### Examples

```bash
# Single target
aimap -target 192.168.1.100

# Scan a subnet for AI services
aimap -target 10.0.0.0/24 -threads 50

# Specific ports with JSON output
aimap -target ml-server.internal -ports 8080,11434,5000 -o report.json

# From a target list
aimap -list targets.txt -o results.json -v
```

## Architecture

| File | Purpose |
|------|---------|
| `main.go` | CLI entry point, 3-phase orchestration |
| `scanner.go` | Parallel TCP connect + HTTP probe |
| `fingerprints.go` | 16-service fingerprint database + match engine |
| `enumerators.go` | Service-specific deep enumeration |
| `reporter.go` | Colored terminal output + JSON export |
| `utils.go` | HTTP client, JSON helpers, CIDR parsing, worker pool |

## Risk Scoring

| Level | Criteria |
|-------|----------|
| **Critical** | No auth + data accessible, exposed credentials/secrets |
| **High** | No auth on data-bearing service, schema/model exposure |
| **Medium** | Version/info leak, CORS misconfiguration |
| **Low** | Service detected, header disclosure |

## Legal

This tool is intended for authorized security testing and research only. Only scan systems you own or have explicit written permission to test. All requests are read-only HTTP GETs.

## License

MIT
