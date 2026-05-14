package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Fingerprint types ───────────────────────────────────────────────

type MatchCond struct {
	// Type: status_code, body_contains, body_not_contains, json_field,
	// json_array, header_contains.
	//
	// body_not_contains is an anti-match: the probe FAILS if the substring
	// appears in the body. Used to exclude false-positive shapes (e.g.,
	// a marketing-site reflection that contains the brand name but isn't a
	// self-hosted instance).
	Type  string
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
		DefaultPorts: []int{8000, 80, 443},
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
		// MLflow's tracking server. The /api/2.0/mlflow/experiments/list
		// endpoint that earlier versions exposed has been removed upstream;
		// /experiments/search (POST) replaced it. We fingerprint via the GET /
		// index, which serves a known HTML skeleton with <title>MLflow</title>
		// and a /static-files/manifest.json link. Two conjunctive conditions
		// keep this from matching arbitrary gunicorn apps.
		Name:         "MLflow",
		DefaultPorts: []int{5000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>mlflow</title>"},
				{Type: "body_contains", Value: "static-files/manifest.json"},
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
		Name: "Ray Serve",
		// Verified live 2026-05-13 against 16.52.175.212:80. Operators
		// often expose Ray Serve as a custom REST endpoint at / rather
		// than the upstream /api/serve/deployments/ admin path. The
		// distinctive body signal is "Ray Serve" in the root JSON, anchored
		// with json_field "message" to avoid matching random JSON with
		// the word "ray" or "serve".
		DefaultPorts: []int{8000, 80, 443},
		Probes: []Probe{
			{Path: "/api/serve/deployments/", Matches: []MatchCond{
				{Type: "json_field", Field: "deployments"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "header_contains", Field: "Content-Type", Value: "application/json"},
				{Type: "body_contains", Value: "Ray Serve"},
				{Type: "body_contains", Value: "message"},
			}},
		},
		Severity: "medium",
	},

	// ── Orchestration / UI ──────────────────────────────────────
	{
		Name: "LangServe",
		// Default upstream is :8000 (FastAPI), but production hosts often
		// front via nginx/Traefik on 80/443. Field-validated 2026-05-13:
		// 3.234.68.99:443 served the genai-langserve FastAPI/Swagger UI
		// and the FP was filtered out by over-narrow DefaultPorts.
		DefaultPorts: []int{8000, 80, 443, 8080},
		Probes: []Probe{
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "langserve"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "langserve"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "Flowise",
		DefaultPorts: []int{3000, 80, 443},
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
			// Conjunctive probe: title plus a unique-to-Open-WebUI asset path.
			// Single-word brand mentions ("open-webui" or "Open WebUI"
			// anywhere in the body) used to fire alone, which over-matched
			// blog posts, tutorials, and marketing reflections that referenced
			// the project. The /static/loader.js path is specific to the
			// Open WebUI deployment, not the brand.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>open webui</title>"},
				{Type: "body_contains", Value: "/static/loader.js"},
			}},
		},
		Severity: "medium",
	},
	{
		Name: "SillyTavern",
		// Pre-1.12 SillyTavern returned 401 with WWW-Authenticate:
		// SillyTavern. The modern build (verified 2026-05-13 against
		// 115.120.242.5:8000) serves an HTML login page directly. The
		// /css/st-tailwind.css path is the project-specific asset
		// signature; the title alone over-matches tutorial/blog content.
		DefaultPorts: []int{8000, 8001},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>sillytavern</title>"},
				{Type: "body_contains", Value: "css/st-tailwind.css"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>sillytavern</title>"},
				{Type: "body_contains", Value: "css/st-tailwind.css"},
			}},
		},
		Severity: "medium",
	},
	{
		Name:         "LiteLLM",
		DefaultPorts: []int{4000, 80, 443},
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
		DefaultPorts: []int{3000, 80, 443},
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
		DefaultPorts: []int{3000, 80, 443},
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
		DefaultPorts: []int{8080, 80, 443},
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
		DefaultPorts: []int{8088, 80, 443, 8080},
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
		Name: "Grafana",
		// Grafana's upstream default is :3000, but production deployments
		// almost always front it via nginx/Traefik on 80/443. Field-validated
		// 2026-05-13 against 141.147.71.47:443 which exposes the standard
		// /api/health JSON.
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/health", Matches: []MatchCond{
				{Type: "json_field", Field: "database"},
				{Type: "json_field", Field: "version"},
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
		Name: "n8n",
		// Verified live 2026-05-13 against 217.77.5.226:5678 and
		// 89.207.169.68:10243. Single-word body_contains "n8n" over-matched
		// any page that mentioned the project; replaced with conjunctive
		// <title>n8n.io - Workflow Automation</title> + REST_ENDPOINT
		// JavaScript constant.
		DefaultPorts: []int{5678, 80, 443},
		Probes: []Probe{
			{Path: "/rest/active-workflows", Matches: []MatchCond{
				{Type: "json_field", Field: "data"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>n8n.io"},
				{Type: "body_contains", Value: "REST_ENDPOINT"},
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
		Name: "Mem0",
		// Default is 8888 in upstream docs, but field-validated 2026-05-13
		// against 45.77.183.19:8000 and other Shodan hits that run Mem0
		// behind uvicorn on the standard FastAPI port.
		DefaultPorts: []int{8888, 8000, 8080},
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
		Name: "Promptfoo",
		// Verified live 2026-05-13 against 38.105.232.166:3000.
		// Some Promptfoo deployments ship only the SPA front-end without
		// a mounted /api/* — the canonical HTML has <title>promptfoo</title>
		// + a /promptfoo/favicon.png unique asset path.
		DefaultPorts: []int{15500, 5000, 3000, 80, 443},
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
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>promptfoo</title>"},
				{Type: "body_contains", Value: "/promptfoo/favicon"},
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
		Name: "Whisper ASR",
		// Verified live 2026-05-13 against 37.75.9.88:9000.
		// GET / returns 307 → /docs (FastAPI default). /docs HTML has the
		// title but not the /asr path (that's only in /openapi.json). Added
		// an explicit /openapi.json probe with the canonical title string
		// from the upstream webservice.
		DefaultPorts: []int{9000, 8080, 7860, 8000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "openai-whisper-asr-webservice"},
			}},
			{Path: "/docs", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "whisper asr webservice"},
			}},
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "whisper asr webservice"},
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
		Name: "Coqui XTTS",
		// Coqui XTTS deployments split into two shapes:
		//   1. Upstream-style API exposing /api/tts/speakers (Flask)
		//   2. Custom HTML UI fork ("XTTS - Generate Speech from Text" /
		//      similar localized title + tts-form / tts-generator-card markup)
		// Verified live 2026-05-13 against 195.87.80.179:8040 (Turkish
		// custom UI). The "coqui" brand string is sometimes absent in
		// custom forks. The HTML probe anchors on the title pattern +
		// a tts-form class.
		DefaultPorts: []int{8020, 5002, 8000, 8040, 80, 443},
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
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>xtts"},
				{Type: "body_contains", Value: "tts-form"},
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
		Name: "RVC Voice Cloning WebUI",
		// Verified live 2026-05-13 against 180.184.96.130:8055.
		// Modern Gradio builds of RVC don't ship the full upstream
		// "Retrieval-based-Voice-Conversion" string; the og:title
		// and gradio_config markdown header carry "RVC WebUI" instead.
		// Two conjuncts (og:title RVC WebUI + gradio_config) keep this
		// from matching arbitrary Gradio apps that mention RVC.
		DefaultPorts: []int{7865, 7860, 7897, 8055, 80, 443},
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
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `content="RVC WebUI"`},
				{Type: "body_contains", Value: "gradio_config"},
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
		Name: "Pipecat Voice Agent",
		// Verified live 2026-05-13 against 18.142.164.147:80 (Pipecat UI).
		// Real deployments redirect / → /client/ and serve <title>Pipecat
		// UI</title>. Single-word body_contains "pipecat" was over-matching
		// risk; tighten to require the title plus the Vite client asset
		// path. Port 80 added to DefaultPorts.
		DefaultPorts: []int{7860, 8000, 8080, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>pipecat"},
				{Type: "body_contains", Value: "assets/index-"},
			}},
			{Path: "/client/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>pipecat"},
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

	// LiveKit — real-time AV pipeline framework + Meet demo app.
	{
		Name: "LiveKit Agents",
		// Three deployment shapes:
		//   1. Agent runner serving its own HTML (rare; "livekit-agents")
		//   2. LiveKit Server admin UI ("livekit-server")
		//   3. LiveKit Meet demo app (dominant — 992 Shodan hits 2026-05-13).
		// Verified live 2026-05-13 against 143.20.37.151:3002 (LiveKit Meet).
		// The Meet demo bundles /images/livekit-meet-home.svg as a unique
		// asset path; combined with the Next.js _next/static path this is
		// distinct enough to avoid bare-brand mentions.
		DefaultPorts: []int{7880, 8080, 3000, 3002, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-agents"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-server"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "livekit-meet-home"},
				{Type: "body_contains", Value: "_next/static"},
			}},
		},
		Severity: "medium",
	},

	// ── Embedding Services ──────────────────────────────────────────────

	// HuggingFace Text Embeddings Inference (TEI) — canonical standalone
	// embedding server from HuggingFace. Exposes /info with model_pipeline_tag
	// = "feature-extraction" (never present in LLM inference servers).
	// Ships auth-off; compute theft + embedding oracle against downstream RAG.
	{
		Name:         "HuggingFace TEI",
		DefaultPorts: []int{80, 8080, 3000},
		Probes: []Probe{
			{Path: "/info", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "model_pipeline_tag"},
				{Type: "body_contains", Value: "feature-extraction"},
			}},
		},
		Severity: "medium",
	},

	// infinity-embedding (michaelfeil/infinity) — OpenAI-compat embedding
	// server. Default port 7997. /openapi.json title is "Infinity Emb".
	{
		Name:         "infinity-embedding",
		DefaultPorts: []int{7997, 8080, 8000},
		Probes: []Probe{
			{Path: "/openapi.json", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "Infinity Emb"},
			}},
			{Path: "/v1/models", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "data"},
				{Type: "body_contains", Value: "infinity_emb"},
			}},
		},
		Severity: "medium",
	},

	// Custom Embedding API — FastAPI/uvicorn embedding servers (the dominant
	// shape in the wild). Root GET / returns JSON with "embed" key referencing
	// a model name, or "embedding_dimension" (OpenVINO pattern). Covers
	// BAAI/bge, nomic-embed, multilingual-e5, and other model families
	// served via custom FastAPI wrappers. Auth-off by default on every
	// observed instance; leaks model name, embedding dimension, vector DB
	// collection names, and internal filesystem paths.
	{
		Name:         "Embedding API",
		DefaultPorts: []int{8000, 8001, 8080, 8002, 8100, 5000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embedding_dimension"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embed"},
			}},
			{Path: "/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "json_field", Field: "embedding_dimension"},
			}},
		},
		Severity: "medium",
	},
	// === AI observability tier (Phase 3 of the 2026-05 sweep) ===
	//
	// Phoenix is the load-bearing one: 25% unauth rate at population scale
	// (94 of 377 hosts on 2026-05-10) driven by PHOENIX_ENABLE_AUTH=False
	// shipping default. The other four ship auth-on-by-default; we fingerprint
	// them to surface latent primitives (default secrets, weak ADMIN keys).
	{
		Name:         "Arize Phoenix",
		DefaultPorts: []int{6006, 80, 443, 8000},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Phoenix</title>"},
				{Type: "body_contains", Value: "Arize Phoenix"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "platformVersion"},
				{Type: "body_contains", Value: "Phoenix"},
			}},
		},
		Severity: "critical",
	},
	{
		Name:         "Helicone Self-Hosted",
		DefaultPorts: []int{3000, 80, 443, 8585},
		Probes: []Probe{
			// Direct /signin probe - returns 200 with BetterAuth login page.
			// The body_not_contains anti-match rejects the marketing-site
			// reflection observed live 2026-05-13 — helicone.ai's static
			// pages ship a hardcoded <link rel="canonical" href="https://
			// www.helicone.ai/">, while a real self-hosted instance does
			// not.
			{Path: "/signin", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "_next/static"},
				{Type: "body_contains", Value: "helicone"},
				{Type: "body_not_contains", Value: `canonical" href="https://www.helicone.ai/"`},
			}},
			// HTTP client follows the / -> /signin 307. After redirect we
			// land on signin and the body still contains helicone branding.
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "_next/static"},
				{Type: "body_contains", Value: "helicone"},
				{Type: "body_not_contains", Value: `canonical" href="https://www.helicone.ai/"`},
			}},
		},
		Severity: "high",
	},
	{
		Name: "Lunary",
		// Iter 21: catastrophic over-match against Elasticsearch fixed.
		// The old `/api/v1/health` + `json_field:status` probe matched any
		// JSON with a "status" field — including Elasticsearch's
		// /_cluster/health response (`status: green`). Observed 283 false
		// positives in the n8n corpus sweep against hosts reverse-proxying
		// Elasticsearch at /api/v1/health.
		//
		// Real Lunary returns the exact body `{"status":"OK"}`. We anchor
		// to that exact substring AND anti-match the ES shape via
		// body_not_contains on a unique-to-Elasticsearch field.
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			{Path: "/api/v1/health", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: `"status":"ok"`},
				{Type: "body_not_contains", Value: "cluster_name"},
				{Type: "body_not_contains", Value: "active_shards"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Dashboard | Lunary</title>"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "OpenLIT",
		DefaultPorts: []int{3000, 80, 443},
		Probes: []Probe{
			// The NextAuth middleware redirects /api/* to /login?callbackUrl=...
			// Our HTTP client follows redirects, so we'll see the login page
			// body. The login page contains the OpenLIT brand string.
			{Path: "/api/ping", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenLIT"},
				{Type: "body_contains", Value: "callbackUrl"},
			}},
			{Path: "/login", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OpenLIT"},
				{Type: "body_contains", Value: "_next/static"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Pezzo",
		DefaultPorts: []int{4200, 3000, 80, 443},
		Probes: []Probe{
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "<title>Pezzo</title>"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "pezzo"},
				{Type: "body_contains", Value: "<title>"},
			}},
		},
		Severity: "high",
	},
}

// ── Matching engine ─────────────────────────────────────────────────

// scanAllFingerprints is set by the -scan-all-fingerprints CLI flag. When
// true, the DefaultPorts filter is bypassed and every fingerprint is
// probed against every open port. Trades ~30x more HTTP requests for the
// ability to catch services running on non-canonical ports.
var scanAllFingerprints = false

func matchFingerprints(openPorts []PortResult, timeout time.Duration, verbose bool, threads int) []ServiceMatch {
	client := newHTTPClient(timeout)
	var (
		mu      sync.Mutex
		matches []ServiceMatch
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, threads)

	for _, port := range openPorts {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Determine scheme(s) to try. Always include both so that a TLS port
			// that also speaks plaintext (e.g. OpenHands admin console) can match
			// on the richer HTTP body when the HTTPS SPA shell is too sparse.
			schemes := []string{"http", "https"}
			if port.TLS {
				schemes = []string{"https", "http"}
			}

			// Filter fingerprints to those that list this port in DefaultPorts,
			// or have no DefaultPorts restriction (empty = try on any port).
			// Avoids probing all 69 fingerprints against every open port.
			// -scan-all-fingerprints bypasses this filter — useful for hosts
			// running services on non-canonical ports.
			candidateFPs := Fingerprints[:0:0]
			if scanAllFingerprints {
				candidateFPs = append(candidateFPs, Fingerprints...)
			} else {
				for _, fp := range Fingerprints {
					if len(fp.DefaultPorts) == 0 {
						candidateFPs = append(candidateFPs, fp)
						continue
					}
					for _, dp := range fp.DefaultPorts {
						if dp == port.Port {
							candidateFPs = append(candidateFPs, fp)
							break
						}
					}
				}
				// Emit a one-line stderr warning if the open port has zero
				// FP candidates — a hint to the user that they may want to
				// re-run with -scan-all-fingerprints.
				if len(candidateFPs) == 0 && !verbose {
					fmt.Fprintf(os.Stderr,
						"\n[!] no FP candidates for %s:%d (port not in any DefaultPorts list); "+
							"re-run with -scan-all-fingerprints to probe exhaustively\n",
						port.Host, port.Port)
				}
			}

			// Parallelize FP candidates within this port. Iter 11.
			//
			// Without this, a port with 21 candidate FPs (e.g. port 80 after
			// the iter 8d/9 catalog-wide DefaultPorts widening) ran each FP
			// sequentially per port-goroutine. The -threads flag's worker
			// pool was idle while the matcher walked the candidate list
			// serially. Wall time per port grew from ~10s to ~80s.
			//
			// We spawn one inner goroutine per FP, gated by the same
			// outer semaphore so total concurrency stays bounded.
			var fpWG sync.WaitGroup
			for _, fp := range candidateFPs {
				fp := fp
				fpWG.Add(1)
				sem <- struct{}{}
				go func() {
					defer fpWG.Done()
					defer func() { <-sem }()
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
								mu.Lock()
								matches = append(matches, sm)
								mu.Unlock()
								matched = true
								break
							}
						}
					}
				}()
			}
			fpWG.Wait()
		}()
	}
	wg.Wait()
	return matches
}

// matchProbe is a test-friendly helper that evaluates a Probe's match
// conditions against a captured PortResult, without making a network call.
// Used by fingerprint unit tests; in production the matcher fetches a fresh
// response per probe path.
//
// The probe's Path is NOT used by this helper — the caller is responsible
// for providing a PortResult whose BodySnippet/Headers represent what the
// path would return. This lets tests synthesize any probe shape (root,
// /api/v1/health, /docs, etc.) without network access.
func matchProbe(probe Probe, pr PortResult) bool {
	body := []byte(pr.BodySnippet)
	headers := pr.Headers
	if headers == nil {
		headers = map[string]string{}
		if pr.Server != "" {
			headers["Server"] = pr.Server
		}
		if pr.ContentType != "" {
			headers["Content-Type"] = pr.ContentType
		}
	}
	for _, mc := range probe.Matches {
		if !evalMatch(mc, pr.StatusCode, headers, body) {
			return false
		}
	}
	return len(probe.Matches) > 0
}

func evalMatch(mc MatchCond, status int, headers map[string]string, body []byte) bool {
	switch mc.Type {
	case "status_code":
		return fmt.Sprintf("%d", status) == mc.Value
	case "body_contains":
		return strings.Contains(strings.ToLower(string(body)), strings.ToLower(mc.Value))
	case "body_not_contains":
		return !strings.Contains(strings.ToLower(string(body)), strings.ToLower(mc.Value))
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
