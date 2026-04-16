# Changelog

All notable changes to aimap are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

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
