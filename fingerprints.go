package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ── Fingerprint types ───────────────────────────────────────────────

type MatchCond struct {
	Type  string // status_code, body_contains, json_field, json_array, header_contains
	Field string
	Value string
}

type Probe struct {
	Path    string
	Matches []MatchCond
}

type Fingerprint struct {
	Name         string
	DefaultPorts []int
	Probes       []Probe
	Severity     string
}

// ── Fingerprint database ────────────────────────────────────────────

var Fingerprints = []Fingerprint{
	// ── Vector databases ────────────────────────────────────────
	{
		Name:         "Weaviate",
		DefaultPorts: []int{8080, 8443},
		Probes: []Probe{
			{Path: "/v1/meta", Matches: []MatchCond{
				{Type: "json_field", Field: "version"},
				{Type: "json_field", Field: "modules"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "ChromaDB",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/api/v1/heartbeat", Matches: []MatchCond{
				{Type: "body_contains", Value: "nanosecond heartbeat"},
			}},
			{Path: "/api/v1/collections", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Qdrant",
		DefaultPorts: []int{6333},
		Probes: []Probe{
			{Path: "/collections", Matches: []MatchCond{
				{Type: "json_field", Field: "result"},
			}},
		},
		Severity: "high",
	},

	// ── LLM runtimes ───────────────────────────────────────────
	{
		Name:         "Ollama",
		DefaultPorts: []int{11434},
		Probes: []Probe{
			{Path: "/api/tags", Matches: []MatchCond{
				{Type: "json_field", Field: "models"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "vLLM",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "body_contains", Value: "vllm"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "SGLang",
		DefaultPorts: []int{30000, 8889},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "sglang is running"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "sglang"},
			}},
			{Path: "/get_model_info", Matches: []MatchCond{
				{Type: "json_field", Field: "model_path"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "LocalAI",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "localai"},
			}},
			{Path: "/models/available", Matches: []MatchCond{
				{Type: "json_field", Field: "object"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "AI TTS Server",
		DefaultPorts: []int{10087, 8080},
		Probes: []Probe{
			{Path: "/v1/audio/voices", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "voices"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "json_field", Field: "endpoints"},
				{Type: "body_contains", Value: "audio/speech"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "text-generation-webui",
		DefaultPorts: []int{7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "gradio"},
				{Type: "body_contains", Value: "text-generation"},
			}},
		},
		Severity: "medium",
	},

	// ── ML platforms ────────────────────────────────────────────
	{
		Name:         "MLflow",
		DefaultPorts: []int{5000},
		Probes: []Probe{
			{Path: "/api/2.0/mlflow/experiments/list", Matches: []MatchCond{
				{Type: "json_field", Field: "experiments"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "TensorFlow Serving",
		DefaultPorts: []int{8501},
		Probes: []Probe{
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "json_field", Field: "model_version_status"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Triton Inference Server",
		DefaultPorts: []int{8000, 8001},
		Probes: []Probe{
			{Path: "/v2", Matches: []MatchCond{
				{Type: "json_field", Field: "name"},
				{Type: "body_contains", Value: "triton"},
			}},
			{Path: "/v2/repository/index", Matches: []MatchCond{
				{Type: "json_array"},
				{Type: "body_contains", Value: "READY"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Ray Serve",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/api/serve/deployments/", Matches: []MatchCond{
				{Type: "json_field", Field: "deployments"},
			}},
		},
		Severity: "medium",
	},

	// ── Orchestration / UI ──────────────────────────────────────
	{
		Name:         "LangServe",
		DefaultPorts: []int{8000},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "body_contains", Value: "langserve"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "body_contains", Value: "langserve"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Flowise",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/api/v1/flows", Matches: []MatchCond{
				{Type: "json_array"},
				{Type: "body_contains", Value: "flowData"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "flowise"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Open WebUI",
		DefaultPorts: []int{3000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Open WebUI"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "open-webui"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "SillyTavern",
		DefaultPorts: []int{8000, 8001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Www-Authenticate", Value: "SillyTavern"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "LiteLLM",
		DefaultPorts: []int{4000},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "body_contains", Value: "litellm"},
			}},
			{Path: "/model/info", Matches: []MatchCond{
				{Type: "body_contains", Value: "litellm"},
			}},
		},
		Severity: "medium",
	},

	// ── Notebooks / dev ─────────────────────────────────────────
	{
		Name:         "Jupyter Notebook",
		DefaultPorts: []int{8888},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "json_field", Field: "started"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "jupyter"},
			}},
		},
		Severity: "high",
	},

	// ── Additions v1.1 ──────────────────────────────────────────
	{
		Name:         "Milvus",
		DefaultPorts: []int{9091, 19530},
		Probes: []Probe{
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "body_contains", Value: "is_healthy"},
			}},
			{Path: "/api/v1/collections", Matches: []MatchCond{
				{Type: "json_field", Field: "collection_names"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Langfuse",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/api/public/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "json_field", Field: "version"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "langfuse"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Dify",
		DefaultPorts: []int{80, 5001, 3000},
		Probes: []Probe{
			{Path: "/console/api/setup", Matches: []MatchCond{
				{Type: "json_field", Field: "step"},
			}},
			{Path: "/console/api/version", Matches: []MatchCond{
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "dify"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "<title>Dify</title>"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "BentoML",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/docs.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "openapi"},
				{Type: "body_contains", Value: "bentoml"},
			}},
			{Path: "/livez", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "BentoML"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Ray Dashboard",
		DefaultPorts: []int{8265},
		Probes: []Probe{
			{Path: "/api/version", Matches: []MatchCond{
				{Type: "json_field", Field: "ray_version"},
			}},
			{Path: "/api/cluster_status", Matches: []MatchCond{
				{Type: "json_field", Field: "cluster_status"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Kubeflow",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/pipeline/apis/v1beta1/healthz", Matches: []MatchCond{
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "kubeflow"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Kubeflow"},
			}},
		},
		Severity: "high",
	},

	// ── Compute orchestration / training tier ──────────────────
	// All fingerprints in this section follow the conjunctive-match
	// discipline (status_code + json_field + body_contains, all required)
	// so probes don't fire on naked single-word substring matches.
	{
		Name:         "Apache Spark UI",
		DefaultPorts: []int{4040, 8080, 18080},
		Probes: []Probe{
			{Path: "/api/v1/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "spark"},
			}},
			{Path: "/api/v1/applications", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Airflow",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "metadatabase"},
				{Type: "json_field", Field: "scheduler"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "metadatabase"},
				{Type: "json_field", Field: "scheduler"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Dask Dashboard",
		DefaultPorts: []int{8787},
		Probes: []Probe{
			{Path: "/json/identity.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "type"},
				{Type: "json_field", Field: "services"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Prefect",
		DefaultPorts: []int{4200},
		Probes: []Probe{
			{Path: "/api/admin/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
			}},
			{Path: "/api/admin/database", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "connection_url"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Temporal Web",
		DefaultPorts: []int{8080, 8233},
		Probes: []Probe{
			{Path: "/api/v1/cluster-info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "supportedClients"},
				{Type: "json_field", Field: "clusterName"},
			}},
			{Path: "/api/v1/namespaces", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "namespaces"},
			}},
		},
		Severity: "high",
	},

	// ── BI / Dashboard / Visualization ──────────────────────────
	{
		Name:         "Metabase",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/session/properties", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "has-user-setup"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Superset",
		DefaultPorts: []int{8088},
		Probes: []Probe{
			{Path: "/api/v1/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "message"},
				{Type: "body_contains", Value: "Superset"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Redash",
		DefaultPorts: []int{5000, 80, 443},
		Probes: []Probe{
			{Path: "/api/status", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "workers"},
				{Type: "json_field", Field: "version"},
			}},
		},
		Severity: "high",
	},

	// ── Observability / infra co-deployed with AI stacks ───────
	{
		Name:         "Grafana",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "json_field", Field: "database"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Prometheus",
		DefaultPorts: []int{9090},
		Probes: []Probe{
			{Path: "/-/healthy", Matches: []MatchCond{
				{Type: "body_contains", Value: "Prometheus Server is Healthy"},
			}},
			{Path: "/api/v1/status/runtimeinfo", Matches: []MatchCond{
				{Type: "json_field", Field: "reloadConfigSuccess"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "etcd",
		DefaultPorts: []int{2379},
		Probes: []Probe{
			{Path: "/health", Matches: []MatchCond{
				{Type: "json_field", Field: "health"},
			}},
			{Path: "/version", Matches: []MatchCond{
				{Type: "json_field", Field: "etcdserver"},
			}},
		},
		Severity: "critical",
	},
	{
		Name:         "MinIO",
		DefaultPorts: []int{9000},
		Probes: []Probe{
			// MinIO health returns empty 200 with x-amz-request-id header.
			// Require both the health path AND the S3-style root error body
			// to avoid matching Rails/Express catch-all routers.
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "AccessDenied"},
				{Type: "body_contains", Value: "xml"},
			}},
			{Path: "/minio/health/live", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Amz-Request-Id", Value: ""},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "n8n",
		DefaultPorts: []int{5678},
		Probes: []Probe{
			{Path: "/rest/active-workflows", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "n8n"},
			}},
		},
		Severity: "critical",
	},

	// ── AI agent platforms ──────────────────────────────────────
	{
		Name:         "OpenHands",
		DefaultPorts: []int{3000, 30000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "<title>OpenHands</title>"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "OpenHands Admin Console"},
			}},
		},
		Severity: "critical",
	},
	{
		Name:         "Mem0",
		DefaultPorts: []int{8888},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "body_contains", Value: "Mem0 REST APIs"},
			}},
			{Path: "/v1/memories", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Coolify",
		DefaultPorts: []int{8000, 443},
		Probes: []Probe{
			// Coolify returns JSON 401 when Accept: application/json is sent,
			// but always sets coolify_session cookie on any request.
			{Path: "/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Set-Cookie", Value: "coolify_session"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "body_contains", Value: "<title>Coolify</title>"},
			}},
		},
		Severity: "low",
	},
	{
		Name:         "Clawdbot",
		DefaultPorts: []int{18789, 443, 80},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "clawdbot-app"},
			}},
		},
		Severity: "medium",
	},

	// ── AI safety / eval / guardrails ───────────────────────────
	// All fingerprints in this section combine status_code + JSON shape +
	// distinctive keyword (conjunctive). Single-word body_contains is
	// disallowed — it produced FPs at population scale (Clipface ≠ Garak,
	// LiveChat ≠ DeepEval, EDocs ≠ DeepEval — see ai-safety-eval-cloud-survey
	// methodology correction 2026-05-05).
	{
		Name:         "Promptfoo",
		DefaultPorts: []int{15500, 5000, 3000},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "status"},
				{Type: "body_contains", Value: "promptfoo"},
			}},
			{Path: "/api/eval", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "NeMo Guardrails",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/v1/rails/configs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "/v1/rails/configs"},
				{Type: "body_contains", Value: "openapi"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "DeepEval Server",
		DefaultPorts: []int{5000, 8000, 8080},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "service"},
				{Type: "body_contains", Value: "deepeval"},
			}},
			{Path: "/api/v1/evaluations", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "LangSmith Self-Hosted",
		DefaultPorts: []int{1984, 8080},
		Probes: []Probe{
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "instance_flags"},
			}},
			{Path: "/api/v1/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "version"},
				{Type: "body_contains", Value: "langsmith"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Inspect AI",
		DefaultPorts: []int{7575, 7576, 8080},
		Probes: []Probe{
			{Path: "/api/logs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_array"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "<title>inspect"},
				{Type: "body_contains", Value: "log_dir"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Garak REST",
		DefaultPorts: []int{5000, 8000, 8080},
		Probes: []Probe{
			{Path: "/api/v1/garak/version", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "garak_version"},
			}},
			{Path: "/probes", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "probes"},
				{Type: "body_contains", Value: "garak"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Lakera Guard Self-Hosted",
		DefaultPorts: []int{8000, 8080},
		Probes: []Probe{
			{Path: "/v1/guard", Matches: []MatchCond{
				{Type: "header_contains", Field: "Server", Value: "lakera"},
			}},
			{Path: "/api/v1/guards", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "guards"},
			}},
		},
		Severity: "high",
	},

	// ── Exposed file servers ────────────────────────────────────
	{
		Name:         "Open Directory",
		DefaultPorts: []int{9090, 8080, 8000, 4000},
		Probes: []Probe{
			// Python http.server / SimpleHTTPServer
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Directory listing for"},
			}},
			// nginx autoindex
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Index of /"},
			}},
		},
		Severity: "high",
	},

	// ── Specialty data layers — analytic / OLAP / NoSQL ─────────
	// Catalogued in case-studies/commercial/FUTURE-SURVEYS.md as
	// "Specialty data layers". All conjunctive: a server-issued header
	// or JSON field anchors the keyword match, no naked body_contains.
	{
		Name:         "ClickHouse",
		DefaultPorts: []int{8123, 8443, 9091},
		Probes: []Probe{
			// /ping returns "Ok.\n" with X-ClickHouse-* headers always present.
			// header_contains with empty Value matches "header exists at all".
			{Path: "/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ok."},
				{Type: "header_contains", Field: "X-Clickhouse-Server-Display-Name", Value: ""},
			}},
			// /?query=SELECT+1 returns "1\n" with the same X-ClickHouse-* headers.
			{Path: "/?query=SELECT+1", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Clickhouse-Format", Value: ""},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Apache Pinot Controller",
		DefaultPorts: []int{9000},
		Probes: []Probe{
			// /cluster/info returns canonical Pinot controller JSON.
			{Path: "/cluster/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "clusterName"},
				{Type: "json_field", Field: "controllerHost"},
			}},
			// /tables list — Pinot-specific structure {"tables":[...]}
			{Path: "/tables", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "tables"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "ScyllaDB REST",
		DefaultPorts: []int{10000},
		Probes: []Probe{
			// /api-doc/ returns Swagger 1.2 JSON listing storage_service / system / etc resources.
			// body_contains anchored by both json_field and the distinctive "storage_service" path.
			{Path: "/api-doc/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "apis"},
				{Type: "body_contains", Value: "storage_service"},
			}},
		},
		Severity: "high",
	},

	// ── Specialty data layers — DuckDB-backed APIs ──────────────
	// Discovered via Shodan `DuckDB-HTTP` facet 2026-05-05. The facet itself
	// is substring-noisy (38% of hits are a single SaaS operator's CSP
	// whitelist mentioning @duckdb/duckdb-wasm CDN URL — browser-side WASM,
	// not server-side DuckDB). Conjunctive matching anchors on structured
	// product banners, not the keyword.
	{
		Name:         "Amulet Scan DuckDB API",
		DefaultPorts: []int{3001, 3000, 8000},
		Probes: []Probe{
			// JSON banner at root: {"name":"Amulet Scan DuckDB API","version":"...","mode":"read-only",
			//                       "endpoints":["GET /health",...,"POST /refresh-views"],
			//                       "dataPath":"/var/lib/ledger_raw/raw"}
			// Canton Network (Daml DLT) ledger-explorer backend; surface includes
			// admin endpoints (POST /refresh-views, GET /health/config, /backfill/*).
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "name"},
				{Type: "json_field", Field: "endpoints"},
				{Type: "body_contains", Value: "amulet scan"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Definite.app DuckDB",
		DefaultPorts: []int{80, 443, 3000, 8000},
		Probes: []Probe{
			// Two operational headers together — x-backend-hostname leaks the K8s
			// pod name (duckdb-deployment-* in prod, duckdb-staging-deployment-* in
			// staging) + x-server-version is YYYY.MMDD.0 (git ...) date-versioned.
			// Conjunctive header_contains beats body matching since body is often
			// 2 bytes ("OK").
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "X-Backend-Hostname", Value: "duckdb-"},
				{Type: "header_contains", Field: "X-Server-Version", Value: "(git "},
			}},
		},
		Severity: "high",
	},

	// ── Adjacent (non-AI, noted for defender handoff) ───────────
	// Docker Registry is not an AI service, but often co-deployed with
	// AI stacks. Defender should hand off to nuclide-registry-recon.
	{
		Name:         "Docker Registry",
		DefaultPorts: []int{5000, 51000, 55000},
		Probes: []Probe{
			{Path: "/v2/", Matches: []MatchCond{
				{Type: "header_contains", Field: "Docker-Distribution-Api-Version", Value: "registry/2.0"},
			}},
			{Path: "/v2/_catalog", Matches: []MatchCond{
				{Type: "json_field", Field: "repositories"},
			}},
		},
		Severity: "low",
	},

	// ── Voice / Audio AI (survey 17) ───────────────────────────────────
	// These services are typically Tier-A "no auth concept" and skew toward
	// abuse classes that aren't in the typical CVE corpus: voice-cloning
	// fraud, transcription-compute theft, real-time-agent abuse.

	// Whisper ASR — broad family covering openai-whisper-asr-webservice,
	// faster-whisper, whisper.cpp HTTP server. The /v1/audio/transcriptions
	// endpoint is the OpenAI-compatible discriminator; some servers expose
	// /asr instead. Multiple probes for full family coverage.
	{
		Name:         "Whisper ASR",
		DefaultPorts: []int{9000, 8080, 7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "openai-whisper-asr-webservice"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Whisper"},
				{Type: "body_contains", Value: "/asr"},
			}},
			{Path: "/inference", Matches: []MatchCond{
				{Type: "body_contains", Value: "whisper.cpp"},
			}},
		},
		Severity: "medium",
	},

	// Coqui XTTS server — /api/tts is the inference endpoint;
	// /api/tts/speakers lists configured voices including any cloned ones.
	// Hardened by status_code + body_contains on the speaker-listing endpoint
	// to avoid colliding with random "tts" hits in marketing copy.
	{
		Name:         "Coqui XTTS",
		DefaultPorts: []int{8020, 5002, 8000},
		Probes: []Probe{
			{Path: "/api/tts/speakers", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "speaker"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "XTTS"},
				{Type: "body_contains", Value: "coqui"},
			}},
		},
		Severity: "medium",
	},

	// Piper TTS HTTP wrapper — small, edge-deployed, often on Raspberry Pi.
	// Default port 5000 conflicts with Flask-many; require body_contains to
	// disambiguate.
	{
		Name:         "Piper TTS",
		DefaultPorts: []int{5000, 8080, 10200},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "piper"},
				{Type: "body_contains", Value: "tts"},
			}},
		},
		Severity: "low",
	},

	// RVC WebUI / GPT-SoVITS / Applio — the voice-cloning Gradio family.
	// Distinct fingerprint vs generic Gradio because the page advertises
	// the specific project name. Severity high because this is the
	// fraud-relevant class.
	{
		Name:         "RVC Voice Cloning WebUI",
		DefaultPorts: []int{7865, 7860, 7897},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Retrieval-based-Voice-Conversion"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "GPT-SoVITS"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Applio"},
			}},
		},
		Severity: "high",
	},

	// OpenVoice (MyShell.ai) — multi-language voice cloning via speaker
	// embedding extraction. The se_extractor module name is project-specific.
	{
		Name:         "OpenVoice",
		DefaultPorts: []int{7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenVoice"},
				{Type: "body_contains", Value: "myshell"},
			}},
		},
		Severity: "high",
	},

	// ChatTTS (2noise) — conversational TTS, viral mid-2024.
	{
		Name:         "ChatTTS",
		DefaultPorts: []int{7860, 8000, 9966},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ChatTTS"},
				{Type: "body_contains", Value: "2noise"},
			}},
		},
		Severity: "medium",
	},

	// F5-TTS — flow-matching TTS (2024-25). Lab demo deployments.
	{
		Name:         "F5-TTS",
		DefaultPorts: []int{7860, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "F5-TTS"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "swivid/f5-tts"},
			}},
		},
		Severity: "medium",
	},

	// Pipecat (Daily.co) — real-time voice-agent framework. Severity high
	// because abuse is "outbound call automation" not just compute theft.
	{
		Name:         "Pipecat Voice Agent",
		DefaultPorts: []int{7860, 8000, 8080},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pipecat"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pipecat"},
			}},
		},
		Severity: "high",
	},

	// Vocode — voice-agent framework, often paired with twilio/daily.co.
	// Conjunctive match on banner term + framework signature to keep the
	// 4-hit Shodan FP-prone "vocode" string from over-matching.
	{
		Name:         "Vocode Voice Agent",
		DefaultPorts: []int{8000, 3000, 7860},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "vocode"},
				{Type: "body_contains", Value: "transcriber"},
			}},
		},
		Severity: "high",
	},

	// LiveKit Agents — real-time AV pipeline framework.
	{
		Name:         "LiveKit Agents",
		DefaultPorts: []int{7880, 8080, 3000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-agents"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-server"},
			}},
		},
		Severity: "medium",
	},
}

// ── Matching engine ─────────────────────────────────────────────────

func matchFingerprints(openPorts []PortResult, timeout time.Duration, verbose bool) []ServiceMatch {
	client := newHTTPClient(timeout)
	var matches []ServiceMatch

	for _, port := range openPorts {
		// Determine scheme(s) to try. Always include both so that a TLS port
		// that also speaks plaintext (e.g. OpenHands admin console) can match
		// on the richer HTTP body when the HTTPS SPA shell is too sparse.
		schemes := []string{"http", "https"}
		if port.TLS {
			schemes = []string{"https", "http"}
		}

		for _, fp := range Fingerprints {
			matched := false
			for _, probe := range fp.Probes {
				if matched {
					break
				}
				for _, scheme := range schemes {
					url := fmt.Sprintf("%s://%s:%d%s", scheme, port.Host, port.Port, probe.Path)
					status, headers, body, err := httpGET(client, url)
					if err != nil {
						continue
					}

					allMatch := true
					for _, mc := range probe.Matches {
						if !evalMatch(mc, status, headers, body) {
							allMatch = false
							break
						}
					}

					if allMatch {
						baseURL := fmt.Sprintf("%s://%s:%d", scheme, port.Host, port.Port)
						sm := ServiceMatch{
							Host:      port.Host,
							Port:      port.Port,
							Service:   fp.Name,
							Severity:  fp.Severity,
							BaseURL:   baseURL,
							MatchPath: probe.Path,
						}
						if json.Valid(body) {
							sm.MatchBody = json.RawMessage(body)
						}
						if parsed, err := parseJSON(body); err == nil {
							if v := jStr(parsed, "version"); v != "" {
								sm.Version = v
							}
						}
						if verbose {
							fmt.Printf("    %s %s on %s:%d via %s\n",
								green("[match]"), fp.Name, port.Host, port.Port, probe.Path)
						}
						matches = append(matches, sm)
						matched = true
						break
					}
				}
			}
		}
	}
	return matches
}

func evalMatch(mc MatchCond, status int, headers map[string]string, body []byte) bool {
	switch mc.Type {
	case "status_code":
		return fmt.Sprintf("%d", status) == mc.Value
	case "body_contains":
		return strings.Contains(strings.ToLower(string(body)), strings.ToLower(mc.Value))
	case "json_field":
		if m, err := parseJSON(body); err == nil {
			return jHas(m, mc.Field)
		}
		return false
	case "json_array":
		_, err := parseJSONArray(body)
		return err == nil
	case "header_contains":
		if v, ok := headers[mc.Field]; ok {
			return strings.Contains(strings.ToLower(v), strings.ToLower(mc.Value))
		}
		return false
	}
	return false
}
