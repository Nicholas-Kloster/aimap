# Changelog

All notable changes to aimap are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [v1.3.0] — 2026-04-23

Coverage release. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Default port list (`-ports`)** — 7 new ports added to the default scan list:

- `80`, `443` — Dify and Coolify defaults; OpenHands installer; many AI services behind reverse proxies
- `2379` — etcd client port
- `5678` — n8n
- `9000` — MinIO API
- `30000` — SGLang, OpenHands NodePort default
- `18789` — Clawdbot

**Fingerprints** — 13 new entries (23 → 36 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| SGLang | 30000, 8889 | `/get_model_info` + body match | High severity — exposes model_path, runtime args |
| AI TTS Server | 10087, 8080 | `/v1/audio/voices` | Medium — voice/model enumeration |
| SillyTavern | 8000, 8001 | `Www-Authenticate: SillyTavern` header | Medium — character roleplay UI; often co-deployed with local LLMs |
| Grafana | 3000 | `/api/health` | Medium — DB status disclosure |
| Prometheus | 9090 | `/-/healthy` + `/api/v1/status/runtimeinfo` | Medium — metrics exposure |
| etcd | 2379 | `/health` + `/version` | Critical — Kubernetes/orchestration secret store |
| MinIO | 9000 | `/` AccessDenied XML + `/minio/health/live` | High — S3-compatible object store, often unauthenticated |
| n8n | 5678 | `/rest/active-workflows` | Critical — workflow orchestration with embedded credentials |
| OpenHands | 3000, 30000 | `<title>OpenHands</title>` + admin console body | Critical — autonomous agent platform |
| Mem0 | 8888 | `/docs` "Mem0 REST APIs" | High — agent memory store with PII |
| Coolify | 8000, 443 | `coolify_session` Set-Cookie | Low — self-hosted PaaS |
| Clawdbot | 18789, 443, 80 | `clawdbot-app` body | Medium |
| Open Directory | 9090, 8080, 8000, 4000 | "Directory listing for" / "Index of /" | High — Python http.server / nginx autoindex exposure |

**Deep enumerators** — 15 new dedicated enumerators (11 → 26 total):

- **`enumSGLang`** — model path, runtime args, served-model name, fingerprint extraction
- **`enumTTS`** — voice catalog and model enumeration via `/v1/audio/voices`
- **`enumVLLM`** — model list via `/v1/models` (previously fingerprint-only)
- **`enumOpenWebUI`** — auth posture, signup-open detection, environment leak via `/api/config`
- **`enumSillyTavern`** — basic-auth realm fingerprint, version probe
- **`enumGrafana`** — anonymous-access detection, version disclosure, snapshot enumeration
- **`enumPrometheus`** — anonymous query API, target enumeration, runtime info
- **`enumEtcd`** — anonymous v2/v3 access detection, member list, key enumeration without auth
- **`enumMinIO`** — bucket enumeration, anonymous access, server-info disclosure
- **`enumN8n`** — workflow enumeration, credential count, executions list
- **`enumOpenDirectory`** — directory walk + sensitive-filename heuristic (id_rsa, .env, *.pem, backup archives)
- **`enumOpenHands`** — admin console claim state, conversation history readability, agent runtime info
- **`enumMem0`** — memory enumeration, user/agent isolation check, PII detection in memory contents
- **`enumCoolify`** — installer claim state, server registration check
- **`enumClawdbot`** — version + auth fingerprint

**New category — AI agent platforms**: OpenHands, Mem0, Coolify, Clawdbot.

**New category — Observability / infra co-deployed with AI stacks**: Grafana, Prometheus, etcd, MinIO, n8n alongside Langfuse.

### Verified

- `go build -o aimap .` — clean
- `go vet ./...` — clean
- Banner reports `Fingerprints: 36 AI/ML services`

### Notes

The v1.3.0 commit message says "add Clawdbot fingerprint + enumerator, expand default ports" — that's the visible tip. The full delta also folds in a backlog of partially-staged fingerprints (SGLang, AI TTS, SillyTavern, the observability quintet, the agent-platform quartet, Open Directory) and their enumerators that had accumulated since v1.2.0.

---

## [v1.2.0] — 2026-04-17

Companion-tool release. No changes to the aimap Go binary, its fingerprint database, CLI flags, or JSON schema.

### Added

**`aimap-profile/` — target profiling + classification + disclosure-routing companion tool.**

Where aimap *fingerprints services* on a target (what's running?), `aimap-profile` *profiles the target itself* (what IS it? how should I approach it? where do I disclose?). The two tools are designed to be used together — profile first, then scan.

- Single-file Python (~500 LoC), read-only, passive-first.
- Reads Shodan historical data + live DNS/WHOIS/TLS cert + security.txt probes + RFC 9116 disclosure channels. Emits structured JSON designed for LLM/pipeline consumption.
- Eight analysis modules: identity, surface_passive (Shodan), surface_active (nmap, opt-in), discrepancy + honeypot scoring, classification + ethics flags, adjacency (PTR /29 + CT namespaces), web_surface (Nuxt/Next.js config extraction, token regex), disclosure (security.txt, MX, bounty hints).

Verified **100% primary-category accuracy across 17 real-world targets** spanning honeypot / clinical_hipaa / personal_device / commercial_staging / commercial_saas / research_lab / education classifications.

Honeypot detection example:

```json
"discrepancy": {
  "honeypot_score": 6,
  "verdict": "likely honeypot / deception asset",
  "signals": ["honeypot combo: [GlobalProtect, Ivanti] (+3)",
              "honeypot combo: [Asus, FortiGate] (+3)"]
}
```

HIPAA-boundary detection example:

```json
"classification": {
  "primary_category": "clinical_hipaa",
  "ethics_flags": [
    "HIPAA-adjacent network — no active probing of clinical systems",
    "Educational institution — CFAA exposure; prefer institutional CSIRT disclosure"
  ]
}
```

Run with `./aimap-profile/aimap_profile.py --target <ip|host> --mode fast`. See `aimap-profile/README.md` for heuristics reference and roadmap.

### Unchanged

- aimap Go binary (still v1.1.1)
- Fingerprint database (23 services)
- Default `-ports` list
- PKGBUILD / man page / CLI flags / JSON output schema

The aimap-profile companion is a separate script with its own versioning (v0.1.0); upgrading or skipping it does not affect `aimap` itself.

---

## [v1.1.0] — 2026-04-16

Additive release. No CLI, JSON schema, or existing fingerprint output changes.

### Added

**Default port list (`-ports`)** — 5 new ports added to the default scan list:

- `9091` — Milvus REST gateway
- `5001` — Dify (docker-compose's non-default web port)
- `8265` — Ray Dashboard
- `51000`, `55000` — Docker Registry (common non-default ports seen in the wild)

**Fingerprints** — 7 new entries (16 → 23 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Milvus | 9091, 19530 | `/api/v1/health` | Closes gap where 19530 was scanned but unfingerprinted |
| Langfuse | 3000 | `/api/public/health` | High severity — stores full prompt/response traces |
| Dify | 80, 5001, 3000 | `/console/api/setup` | Catches critical "setup not completed → admin claimable" state |
| BentoML | 3000 | `/healthz` + `/docs.json` | |
| Ray Dashboard | 8265 | `/api/version` | Distinct from Ray Serve (already covered on 8000) |
| Kubeflow | 8080 | `/pipeline/apis/v1beta1/healthz` | |
| Docker Registry | 5000, 51000, 55000 | `/v2/` header | Severity: low — flagged for handoff to registry triage |

**Deep enumerators** — 4 new dedicated enumerators:

- **`enumMilvus`** — version, health, Prometheus metrics, collection enumeration via REST gateway, PII detection in collection names.
- **`enumLangfuse`** — auth status, open-signup detection, project count via `/api/public/projects`. Always emits an informational finding noting Langfuse contains LLM conversation data, so defenders know what they're dealing with even when auth is correctly configured.
- **`enumDify`** — primary signal is `/console/api/setup` returning a non-finished state, meaning anyone can claim the admin account. Critical-severity finding for fresh deployments.
- **`enumDockerRegistry`** — detects `/v2/_catalog` anonymous access, reports repo count, and flags adjacency. Does not perform full triage — points defender at dedicated registry tooling for that.

BentoML, Ray Dashboard, and Kubeflow are detected and risk-scored via the generic path; dedicated enumerators are queued for v1.2.

### Verified

- `go build -o aimap .` — clean
- `go vet ./...` — clean
- Banner reports `Fingerprints: 23 AI/ML services`

### Known limitations / queued for v1.2

- Autonomous agent frameworks (SuperAGI, AgentGPT, MetaGPT, OpenDevin) — intentionally skipped; category churns too fast for stable fingerprints.
- Dedicated deep enumerators for BentoML, Ray Dashboard, Kubeflow.
- Tier 2 adds from the Shodan AI/ML reference: Typesense, Label Studio, Argilla, ArangoDB.
- NVIDIA DCGM — GPU metrics exporter; useful for asset inventory but low severity standalone.

## [v1.0.0]

Initial release. 16 fingerprinted AI/ML services, ASCII banner UI, JSON report output, severity icons, progress bars.
