# Changelog

All notable changes to aimap are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [v1.7.0] — 2026-05-09

Embedding Services tier (3 platforms). Backward-compatible. Fingerprint count: 66 → 69. Enumerator count: 33 → 36.

### Added

**Fingerprints** — 3 new entries:

| Service | Ports | Probe (conjunctive) | Severity | Notes |
|---------|-------|---------------------|----------|-------|
| HuggingFace TEI | 80, 8080, 3000 | `GET /info` → status 200 + `json_field:model_pipeline_tag` + `body_contains:feature-extraction` | medium | `model_pipeline_tag:"feature-extraction"` is TEI-unique — not present in any LLM inference server; disambiguates from Ollama/llama.cpp |
| infinity-embedding | 7997, 8080, 8000 | `GET /openapi.json` → status 200 + `body_contains:Infinity Emb`; alt: `GET /v1/models` → `json_field:data` + `body_contains:infinity_emb` | medium | OpenAI-compat embedding server; OpenAPI title is the discriminating signal |
| Embedding API | 8000, 8001, 8080, 8002, 8100, 5000 | `GET /` → status 200 + `json_field:embedding_dimension`; OR `json_field:embed`; OR `GET /health` → `json_field:embedding_dimension` | medium | Custom FastAPI catch-all — `embedding_dimension` / `embed` JSON keys are embedding-specific; not present in LLM or general API roots |

**Enumerators** — 3 new deep enumerators:

| Enumerator | Probes | Extracted fields |
|-----------|--------|-----------------|
| `enumTEI` | `/info`, `/metrics` | model_id, version, max_input_length, max_batch_total_tokens, max_concurrent_requests; Prometheus te_request_count / te_embed_count |
| `enumInfinity` | `/v1/models`, `/openapi.json` | model list, OpenAPI title, version |
| `enumEmbeddingAPI` | `/`, `/health`, `/openapi.json` | embed model, embedding_dimension, reranker, llm backend, index_dir, docs_dir (filesystem path leak) |

### Methodology notes

Embedding services are **Shodan-dark** — TEI, infinity, and custom FastAPI embedding servers all return API JSON at `GET /`, which Shodan's crawler treats as non-HTML and indexes minimally. Shodan `http.html:"BAAI/bge"` (41 hits), `http.html:"nomic-embed"` (22 hits) and similar model-name queries are the only Shodan-viable approach; they work because model names appear in HTML dashboards, not because Shodan indexes the API roots.

**Docker Registry FP:** `"text-embeddings-inference"` in banner (6 hits) matches Docker Registry `/v2/_catalog` responses listing the TEI image. Not live TEI servers. The TEI fingerprint probes `/info` specifically to avoid this.

**Reposify contamination:** `http.html:"all-MiniLM"` at 404 hits is dominated by `Server: Reposify` honeypots at `Content-Length: 3151`. Filter: `server:"Reposify"` exclusion.

**Threat class:** Compute theft (GPU/CPU at operator's expense) + embedding oracle (attacker pre-computes query vectors to probe downstream vector DBs without the embedding key). Severity elevated to high when paired with exposed vector DB on same host.

Companion survey catalog: [`AI-LLM-Infrastructure-OSINT/shodan/queries/27-embedding-services.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/shodan/queries/27-embedding-services.md)

## [v1.6.0] — 2026-05-08

BI/Dashboard tier (3 platforms) + Voice/Audio AI tier (10 platforms). Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes. Fingerprint count: 53 → 66.

### Added

**BI / Dashboard fingerprints** (already shipped in `b9136a9` — formalized in this release):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Metabase | 3000, 80, 443, 8080, 8443 | `GET /api/session/properties` (status 200 + `json_field:has-user-setup`) | High — CVE-2023-38646 pre-auth RCE via setup wizard if `has-user-setup:false` |
| Apache Superset | 8088, 80, 443, 8080 | `GET /api/v1/` (status 200 + `json_field:message` + `body_contains:Superset`) | High — CVE-2023-27524 predictable SECRET_KEY auth bypass; default-creds `admin/general` and `admin/admin` checks |
| Redash | 5000, 80, 443, 8080 | `GET /api/status` (status 200 + `json_field:workers` + `json_field:version`) | High — `/api/data_sources` unauth = CRITICAL when present |

**Voice / Audio AI fingerprints** — 10 new entries:

| Service | Ports | Probe (conjunctive) | Severity | Why |
|---------|-------|---------------------|---------:|-----|
| Whisper ASR | 9000, 8080, 7860, 8000 | `body_contains:openai-whisper-asr-webservice` OR `/inference + body:whisper.cpp` OR `/docs + body:Whisper + body:/asr` | medium | Compute theft + PHI/PII risk in healthcare deployments |
| Coqui XTTS | 8020, 5002, 8000 | `/api/tts/speakers + body:speaker` OR `/ + body:XTTS + body:coqui` | medium | Voice-cloning compute theft |
| Piper TTS | 5000, 8080, 10200 | `body:piper + body:tts` | low | Edge / RPi deployments |
| RVC Voice Cloning WebUI | 7865, 7860, 7897 | `body:Retrieval-based-Voice-Conversion` / `body:GPT-SoVITS` / `body:Applio` | **high** | **Fraud-relevant — celebrity voice clones, deepfake-call enablement** |
| OpenVoice | 7860, 8000 | `body:OpenVoice + body:myshell` | **high** | Multi-language voice cloning |
| ChatTTS | 7860, 8000, 9966 | `body:ChatTTS + body:2noise` | medium | Conversational TTS |
| F5-TTS | 7860, 8000 | `body:F5-TTS` OR `body:swivid/f5-tts` | medium | Flow-matching voice clone |
| Pipecat Voice Agent | 7860, 8000, 8080 | `body:pipecat` (root or /health) | **high** | **Real-time outbound-call abuse — Twilio/Daily integration** |
| Vocode Voice Agent | 8000, 3000, 7860 | `body:vocode + body:transcriber` | **high** | Same — voice-agent framework abuse |
| LiveKit Agents | 7880, 8080, 3000 | `body:livekit-agents` OR `body:livekit-server` | medium | Real-time AV pipeline |

### Severity rationale (Voice / Audio)

Voice-cloning (RVC / OpenVoice) and real-time voice-agent (Pipecat / Vocode) fingerprints get `severity:high` because the abuse class differs qualitatively from typical compute-theft. RVC servers loaded with celebrity speaker embeddings are deepfake-fraud infrastructure; Pipecat / Vocode servers integrated with Twilio can make outbound scam calls. Other voice/audio fingerprints (transcription, simple TTS) stay at `medium` / `low`.

### Methodology context

Closes the Speech & Audio AI tier in [`FUTURE-SURVEYS.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/FUTURE-SURVEYS.md). Companion query catalog at `shodan/queries/17-voice-audio-ai.md` and discovery runbook at `data/voice-audio-ai-discovery-runbook.sh` in the OSINT repo.

**Wake Forest "WHISPER" FP class** documented in the survey-17 catalog. `whisper.phs.wakehealth.edu` is a federally-funded clinical research portal (ColdFusion-on-IIS) that surfaces in `http.title:"Whisper"` Shodan dorks via keyword collision — pure FP for voice/audio AI. Same lesson class as the Garak / Garakuta-no-Kamisama collision Session 9 caught: single-keyword title/html match is unsound at population scale. The aimap fingerprints here all use conjunctive `body_contains` anchored to the actual project name (`openai-whisper-asr-webservice`, `whisper.cpp`, `Retrieval-based-Voice-Conversion`, `pipecat`, etc.) to avoid this class of FP.

### Notes for fingerprint authors

- Port 7860 (Gradio default) is heavily collision-prone across image generation, TTS, ASR, and voice cloning. Voice/audio fingerprints disambiguate via project-specific body strings; the catalog's `port:7860 http.html:"voice"` / `"speech"` / `"clone"` cross-cuts apply at Shodan-dork level, not at fingerprint level.
- Port 8000 / 8080 collisions (uvicorn, FastAPI generic) are handled by the same conjunctive pattern — voice-AI fingerprints require the project name appear in body.

## [v1.5.0] — 2026-05-05

Specialty data layers — analytic / OLAP / NoSQL tier. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Fingerprints** — 3 new entries (50 → 53 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| ClickHouse | 8123, 8443, 9091 | `GET /ping` (status 200 + body `Ok.` + `X-Clickhouse-Server-Display-Name` header present) AND `GET /?query=SELECT+1` (status 200 + `X-Clickhouse-Format` header) | High — OLAP query access; sometimes including AI training datasets, model registries, or feature stores |
| Apache Pinot Controller | 9000 | `GET /cluster/info` (status 200 + json fields `clusterName` + `controllerHost`) AND `GET /tables` (status 200 + json field `tables`) | High — real-time analytics; tables/schema/segments/instance enumeration |
| ScyllaDB REST | 10000 | `GET /api-doc/` (status 200 + json field `apis` + body contains `storage_service`) | High — distributed NoSQL admin API; cluster topology, keyspaces, tables, sometimes AI feature stores |

### Methodology context

This release closes the Specialty data layers tier in [`FUTURE-SURVEYS.md`](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/FUTURE-SURVEYS.md). Cassandra CQL native protocol on port 9042 is **not** added to aimap — the CQL handshake is binary, not HTTP, and a proper protocol-strict OPTIONS-frame banner check belongs in the survey runbook (`data/specialty-data-layers-discovery-runbook.sh` in the OSINT repo). Adding tcp_send / binary_frame match types to aimap is a separate hardening pass, not blocking for this survey.

Port 9000 is collision-prone (ClickHouse native TCP, MinIO API, Pinot broker default, Whisper, etc.). The Apache Pinot Controller fingerprint discriminates via the conjunctive `clusterName` + `controllerHost` JSON field requirement — neither field appears on collision-class services.

Port 10000 collides with Webmin and miscellaneous management UIs; the ScyllaDB REST fingerprint discriminates via the `/api-doc/` Swagger-1.2 shape with `apis` array + the distinctive `storage_service` resource path.

### Notes for fingerprint authors

- Go's `net/http` canonicalizes `x-clickhouse-server-display-name` → `X-Clickhouse-Server-Display-Name`. Use canonical case for any new `header_contains` matchers.
- `header_contains` with `Value: ""` matches "header is present at all" (Go's `strings.Contains(s, "")` is always true). This is the idiomatic "header exists" check.

## [v1.4.0] — 2026-05-05

Specialty data layers — DuckDB-backed APIs. Backward-compatible: no CLI, JSON schema, or existing-fingerprint output changes.

### Added

**Fingerprints** — 2 new entries (48 → 50 total):

| Service | Ports | Probe | Notes |
|---------|-------|-------|-------|
| Amulet Scan DuckDB API | 3001, 3000, 8000 | `GET /` JSON banner: `name`, `endpoints`, body contains `amulet scan` | High — Canton Network (Daml DLT) ledger-explorer backend; banner-declared admin endpoints (`POST /refresh-views`, `GET /health/config`, `/backfill/*`) |
| Definite.app DuckDB | 80, 443, 3000, 8000 | `GET /` operational headers: `X-Backend-Hostname` contains `duckdb-`, `X-Server-Version` contains `(git ` | High — YC-backed "DuckDB as a Service"; pod-name leak in header (`duckdb-deployment-*` prod / `duckdb-staging-deployment-*` staging) |

### Methodology context

Both fingerprints were derived during NuClide's `DuckDB-HTTP` Shodan-facet bucketing exercise (2026-05-05). The facet itself is substring-noisy at population scale — 38% of global facet hits are a single SaaS operator's K8s ingress fleet whose CSP `script-src` whitelists a `@duckdb/duckdb-wasm` CDN URL (browser-side WASM, not server-side DuckDB). Conjunctive matching anchors on **structured product banners** (JSON `name` field, operational headers in canonical case), not the keyword. Same lesson class as session-9's Garak/DeepEval substring-FP correction, with Shodan as the matcher.

### Notes for fingerprint authors

- Go's `net/http` canonicalizes header names (`x-backend-hostname` on the wire → `X-Backend-Hostname` in `resp.Header`). Existing fingerprints (`Server`, `Docker-Distribution-Api-Version`) already use canonical case; new `header_contains` matchers should follow the same convention. Case-insensitive header lookup is a separate hardening pass not done in this release.

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
