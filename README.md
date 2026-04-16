# aimap

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/Nicholas-Kloster/aimap)](https://github.com/Nicholas-Kloster/aimap/releases)
[![Stars](https://img.shields.io/github/stars/Nicholas-Kloster/aimap)](https://github.com/Nicholas-Kloster/aimap/stargazers)

**nmap for AI infrastructure.** A purpose-built scanner for LLMs, vector databases, and ML model servers. Defenders run it against their own networks to find exposed AI services before attackers do.

Single Go binary. Zero external dependencies. Read-only HTTP probes. Safe for production.

## Why aimap exists

Security teams can't secure what they can't see, and AI adoption moves faster than inventory does. Every organization running modern ML has shadow deployments the security team doesn't know about:

- A data scientist stands up Ollama on a dev VM "just to test" — and never takes it down.
- An ML engineer deploys MLflow with `--host 0.0.0.0` because the docs said to — and it ends up on the internet when the security group gets relaxed.
- A team installs Jupyter for a workshop and forgets to set a token.
- A RAG prototype with a ChromaDB instance ships to production with no auth because "we'll add it later."
- Someone spins up Flowise to experiment with agent workflows and puts OpenAI keys in the credentials panel, which turns out to be world-readable.

Generic scanners (`nmap`, `nuclei`) don't identify these as AI services, so they don't show up in the security team's inventory. aimap does.

## What it detects (23 services)

| Category | Services |
|---|---|
| Vector databases | Weaviate, ChromaDB, Qdrant, Milvus |
| LLM runtimes | Ollama, vLLM, LocalAI, text-generation-webui |
| ML platforms | MLflow, TensorFlow Serving, Triton Inference Server, Ray Serve, Ray Dashboard, Kubeflow |
| Orchestration / UI | LangServe, Flowise, Dify, Open WebUI, LiteLLM, BentoML |
| Observability | Langfuse |
| Notebooks / adjacent | Jupyter Notebook, Docker Registry |

Each service has a dedicated fingerprint; several also have deep enumerators that surface PII fields, unauthenticated RCE, exposed credentials, and other actionable findings.

## Install

### Go install (recommended for developers)

```bash
go install github.com/Nicholas-Kloster/aimap@latest
```

### Download a binary (recommended for security teams)

Pre-built Linux amd64 and arm64 binaries are on the [Releases page](https://github.com/Nicholas-Kloster/aimap/releases). Download, chmod, move to PATH:

```bash
curl -LO https://github.com/Nicholas-Kloster/aimap/releases/latest/download/aimap-linux-amd64
chmod +x aimap-linux-amd64
sudo mv aimap-linux-amd64 /usr/local/bin/aimap
```

### Build from source

```bash
git clone https://github.com/Nicholas-Kloster/aimap.git
cd aimap
go build -o aimap .
```

## Quick start

```bash
# Scan a single host
aimap -target 192.168.1.100

# Audit an internal subnet for shadow AI
aimap -target 10.0.0.0/24 -threads 50 -o audit.json

# Investigate one host with wide port coverage
aimap -target 10.5.5.5 -v -ports 8000,8080,8443,8888,9091,11434,6333,19530,5000,3000,7860,4000,51000,55000

# CI/CD deployment gate — fail build on critical findings
aimap -target $DEPLOY_URL -o check.json
jq '.enum_results[] | select(.risk_level == "critical")' check.json
```

### Common use cases

**Shadow-AI audit** — scan your internal CIDR ranges on a schedule, diff against last run, investigate new AI services appearing.

**External-exposure check** — scan your own public IPs to catch AI services that leaked onto the internet through misconfigured cloud security groups.

**CI/CD deployment gate** — run aimap against newly-deployed services as a smoke test, fail the build if critical findings surface.

**Incident response** — single-target deep dive when you have a tip that one specific host may be exposed.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | — | Single target (IP, hostname, or CIDR) |
| `-list` | — | File of targets, one per line (`#` comments supported) |
| `-ports` | 19-port default set | Comma-separated ports to scan |
| `-timeout` | `5s` | Connection timeout |
| `-threads` | `20` | Concurrent scan threads |
| `-o` | — | JSON report output file |
| `-v` | false | Verbose output |

Default port list: `8080,8443,11434,8000,3000,6333,19530,9091,8888,8501,9090,5000,5001,4000,7860,3001,8265,51000,55000`

See `man aimap` (if installed system-wide) for the full reference.

## Output

Terminal output is colorized, human-readable, and includes per-service risk scoring. JSON output (`-o file.json`) is machine-readable and stable across releases — suitable for pipeline integration, SIEM ingest, or diffing across scans.

### Risk levels

| Level | Criteria | Examples |
|-------|----------|----------|
| **critical** | Exploitable now, no auth | Unauthenticated Jupyter RCE, exposed Flowise credentials, Dify with unclaimed admin |
| **high** | Sensitive data accessible, no auth | Vector DB with PII, Langfuse traces readable, MLflow experiments accessible |
| **medium** | Information disclosure | Version leaks, CORS misconfig |
| **low** | Service detected, minor leak | Header disclosure |
| **info** | Service identified, auth in place | Nothing actionable |

**Escalation rule:** `auth == none` + `high` finding = `critical`. Data accessible without authentication is always critical regardless of other factors.

## Architecture

| File | Purpose |
|------|---------|
| `main.go` | CLI entry point, 3-phase orchestration |
| `scanner.go` | Parallel TCP connect + HTTP probe |
| `fingerprints.go` | Fingerprint database + match engine |
| `enumerators.go` | Service-specific deep enumeration |
| `reporter.go` | Colored terminal output + JSON export |
| `utils.go` | HTTP client, JSON helpers, CIDR parsing, worker pool |

Adding a new service is two steps:

1. Add a `Fingerprint` struct to `fingerprints.go`
2. (Optional) Add an `enum<Service>` function to `enumerators.go` and wire it in `runEnumerators`

PRs welcome.

## Safety and authorization

aimap is active — it performs TCP connections and HTTP GETs. **Only scan systems you own or have explicit written authorization to test.** Unauthorized scanning of third-party infrastructure may violate local computer-misuse laws.

For passive reconnaissance of external targets, use dedicated OSINT tools instead (Shodan, Censys, Certificate Transparency logs).

aimap does not:

- Authenticate to services (even if credentials are provided)
- Submit forms or POST data
- Execute exploits or payloads
- Modify, delete, or create anything on target systems

All probes are HTTP GETs. All findings are derived from public-endpoint responses.

## Integration examples

### GitHub Actions (CI gate)

```yaml
- name: AI exposure check
  run: |
    aimap -target ${{ env.DEPLOY_URL }} -o aimap.json
    CRITICAL=$(jq '[.enum_results[] | select(.risk_level == "critical")] | length' aimap.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::Deployment blocked: $CRITICAL critical AI exposures found"
      exit 1
    fi
```

### Cron-based continuous monitoring

```bash
# /etc/cron.monthly/aimap-audit
#!/bin/bash
OUT=/var/log/aimap/$(date +%Y-%m).json
aimap -target 10.0.0.0/16 -threads 50 -o "$OUT"

# Diff against last month
PREV=$(ls /var/log/aimap/*.json | tail -n 2 | head -n 1)
diff <(jq -S '.services' "$PREV") <(jq -S '.services' "$OUT") && \
  mail -s "aimap audit clean" security@example.com || \
  mail -s "aimap audit: NEW SERVICES DETECTED" security@example.com < "$OUT"
```

### Ingest into SIEM

The JSON schema is stable; findings have consistent `category`, `severity`, and `service` fields. Ingest `enum_results[].findings[]` into Splunk/Elastic/Loki as-is.

## Contributing

Bug reports and fingerprint additions welcome via GitHub issues and PRs. When submitting a new fingerprint:

- Include the service's default port(s)
- Include a reliable distinguishing probe (path + body match)
- Note any known auth patterns
- Deep enumerators are nice-to-have, not required

## License

MIT. See [LICENSE](LICENSE).

## Author

Nicholas Kloster ([NuClide](https://github.com/Nicholas-Kloster))

## Acknowledgments

Built on methodology from investigations into exposed AI infrastructure during 2025-2026 — including engagements where vector databases, LLM inference servers, and MLflow instances were found unauthenticated on public IPs. aimap is the tool that would have caught them earlier if defenders had been running it.

## See also

- [nmap](https://nmap.org) — general-purpose network scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) — template-based vulnerability scanner
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — risk framework for AI applications
