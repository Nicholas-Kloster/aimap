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
		Name:         "LocalAI",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/readyz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "ok"},
			}},
			{Path: "/models/available", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
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
			{Path: "/v2/health/ready", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
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
				{Type: "status_code", Value: "200"},
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
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
				{Type: "body_contains", Value: "OK"},
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
				{Type: "body_contains", Value: "status"},
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
				{Type: "body_contains", Value: "dify"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Dify"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "BentoML",
		DefaultPorts: []int{3000},
		Probes: []Probe{
			{Path: "/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
			}},
			{Path: "/docs.json", Matches: []MatchCond{
				{Type: "body_contains", Value: "bentoml"},
			}},
			{Path: "/", Matches: []MatchCond{
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
				{Type: "status_code", Value: "200"},
			}},
		},
		Severity: "high",
	},
	{
		Name:         "Kubeflow",
		DefaultPorts: []int{8080},
		Probes: []Probe{
			{Path: "/pipeline/apis/v1beta1/healthz", Matches: []MatchCond{
				{Type: "status_code", Value: "200"},
			}},
			{Path: "/", Matches: []MatchCond{
				{Type: "body_contains", Value: "Kubeflow"},
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
}

// ── Matching engine ─────────────────────────────────────────────────

func matchFingerprints(openPorts []PortResult, timeout time.Duration, verbose bool) []ServiceMatch {
	client := newHTTPClient(timeout)
	var matches []ServiceMatch

	for _, port := range openPorts {
		// Determine scheme(s) to try
		schemes := []string{"http"}
		if port.TLS {
			schemes = []string{"https"}
		} else if port.StatusCode == 0 {
			// Scanner couldn't determine — try both
			schemes = []string{"http", "https"}
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
