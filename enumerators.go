package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ── PII detection ───────────────────────────────────────────────────

var piiPatterns = []string{
	"student", "email", "mail", "phone", "tel", "mobile",
	"counseling", "counselor", "grade", "personal", "private",
	"name", "first_name", "last_name", "firstname", "lastname", "fullname",
	"ssn", "social_security", "national_id", "passport", "identity",
	"address", "street", "city", "zip", "postal",
	"dob", "date_of_birth", "birthday", "birth_date",
	"password", "passwd", "secret", "token", "api_key", "credential",
	"credit_card", "card_number", "cvv", "bank", "account",
	"salary", "income", "gender", "sex", "race", "ethnicity",
	"medical", "health", "diagnosis", "disability",
	"parent", "guardian", "emergency_contact", "family",
	"gpa", "score", "evaluation", "discipline",
	"customer", "employee", "user",
}

func isPII(field string) bool {
	lower := strings.ToLower(field)
	for _, p := range piiPatterns {
		if lower == p || strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ── Secret patterns ─────────────────────────────────────────────────

var secretPatterns = []struct {
	Pattern string
	Name    string
}{
	{"OPENAI_API_KEY", "OpenAI API key in filesystem"},
	{"ANTHROPIC_API_KEY", "Anthropic API key in filesystem"},
	{"AWS_ACCESS_KEY_ID", "AWS credentials exposed"},
	{"AWS_SECRET_ACCESS_KEY", "AWS secret key exposed"},
	{"GOOGLE_API_KEY", "Google API key in filesystem"},
	{"AZURE_OPENAI_KEY", "Azure OpenAI key in filesystem"},
	{"HF_TOKEN", "HuggingFace token in filesystem"},
	{"HUGGING_FACE", "HuggingFace credential in filesystem"},
	{"DATABASE_URL", "Database connection string exposed"},
	{"POSTGRES_PASSWORD", "PostgreSQL password exposed"},
	{"MYSQL_PASSWORD", "MySQL password exposed"},
	{"REDIS_PASSWORD", "Redis password exposed"},
	{"sk-proj-", "OpenAI project key pattern"},
	{"sk-ant-", "Anthropic key pattern"},
	{"AKIA", "AWS access key ID pattern"},
	{"ghp_", "GitHub PAT pattern"},
	{"glpat-", "GitLab PAT pattern"},
	{"xoxb-", "Slack bot token pattern"},
}

func scanSecrets(content string, r *EnumResult) {
	for _, sp := range secretPatterns {
		if strings.Contains(content, sp.Pattern) {
			idx := strings.Index(content, sp.Pattern)
			snippet := content[idx:]
			if nl := strings.IndexByte(snippet, '\n'); nl > 0 {
				snippet = snippet[:nl]
			}
			if len(snippet) > 50 {
				snippet = snippet[:47] + "..."
			}
			r.Findings = append(r.Findings, Finding{
				Category: "credentials",
				Title:    sp.Name,
				Detail:   snippet,
				Severity: "critical",
			})
		}
	}
}

// ── Dispatcher ──────────────────────────────────────────────────────

func runEnumerators(services []ServiceMatch, timeout time.Duration, verbose bool) []EnumResult {
	client := newHTTPClient(timeout)
	var results []EnumResult

	for _, svc := range services {
		if verbose {
			fmt.Printf("    enumerating %s @ %s\n", svc.Service, svc.BaseURL)
		}
		var result EnumResult
		switch svc.Service {
		case "Weaviate":
			result = enumWeaviate(client, svc)
		case "Ollama":
			result = enumOllama(client, svc)
		case "ChromaDB":
			result = enumChromaDB(client, svc)
		case "Qdrant":
			result = enumQdrant(client, svc)
		case "Flowise":
			result = enumFlowise(client, svc)
		case "Jupyter Notebook":
			result = enumJupyter(client, svc)
		case "MLflow":
			result = enumMLflow(client, svc)
		case "Milvus":
			result = enumMilvus(client, svc)
		case "Langfuse":
			result = enumLangfuse(client, svc)
		case "Dify":
			result = enumDify(client, svc)
		case "Docker Registry":
			result = enumDockerRegistry(client, svc)
		default:
			result = mkResult(svc)
		}
		result.Findings = append(result.Findings, checkGeneric(client, svc)...)
		result.RiskLevel = computeRisk(result)
		results = append(results, result)
	}
	return results
}

func mkResult(svc ServiceMatch) EnumResult {
	return EnumResult{
		Service:    svc.Service,
		Host:       svc.Host,
		Port:       svc.Port,
		BaseURL:    svc.BaseURL,
		Version:    svc.Version,
		AuthStatus: "unknown",
		RawData:    make(map[string]interface{}),
	}
}

// ── Weaviate ────────────────────────────────────────────────────────

func enumWeaviate(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/v1/meta"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["meta"] = m
			if mods := jMap(m, "modules"); mods != nil {
				names := make([]string, 0, len(mods))
				for k := range mods {
					names = append(names, k)
				}
				r.RawData["modules"] = names
			}
		}
	}

	r.AuthStatus = "none"
	if st, _, _, err := httpGET(c, b+"/.well-known/openid-configuration"); err == nil && st == 200 {
		r.AuthStatus = "OIDC"
	}

	if st, _, body, err := httpGET(c, b+"/v1/schema"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			classes := jArray(m, "classes")
			type colInfo struct {
				Name       string   `json:"name"`
				Vectorizer string   `json:"vectorizer"`
				Props      int      `json:"properties"`
				Objects    int      `json:"objects"`
				PII        []string `json:"pii_fields,omitempty"`
			}
			var cols []colInfo
			var allPII []string
			totalObjects := 0

			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(classes)))
			for _, cls := range classes {
				cm, ok := cls.(map[string]interface{})
				if !ok {
					continue
				}
				ci := colInfo{
					Name:       jStr(cm, "class"),
					Vectorizer: jStr(cm, "vectorizer"),
				}
				props := jArray(cm, "properties")
				ci.Props = len(props)
				for _, p := range props {
					pm, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					if pName := jStr(pm, "name"); isPII(pName) {
						ci.PII = append(ci.PII, pName)
						allPII = append(allPII, pName)
					}
				}
				url := fmt.Sprintf("%s/v1/objects?class=%s&limit=1", b, ci.Name)
				if s, _, ob, e := httpGET(c, url); e == nil && s == 200 {
					if om, e := parseJSON(ob); e == nil {
						ci.Objects = int(jFloat(om, "totalResults"))
					}
				}
				totalObjects += ci.Objects
				r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s objects)", ci.Name, fmtNum(ci.Objects)))
				cols = append(cols, ci)
			}
			r.RawData["collections"] = cols

			if len(allPII) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII fields: " + strings.Join(allPII, ", "),
					Severity: "critical", Data: allPII,
				})
			}
			if totalObjects > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%s total objects — full read access", fmtNum(totalObjects)),
					Severity: "high",
				})
			} else {
				r.Findings = append(r.Findings, Finding{
					Category: "schema", Title: "Full schema readable (collections empty)",
					Severity: "high",
				})
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/v1/nodes"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			nodes := jArray(m, "nodes")
			r.RawData["node_count"] = len(nodes)
		}
	}

	return r
}

// ── Ollama ──────────────────────────────────────────────────────────

func enumOllama(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/tags"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "models")
			type modelInfo struct {
				Name string `json:"name"`
				Size string `json:"size"`
			}
			var mlist []modelInfo
			var parts []string
			for _, mdl := range models {
				mm, ok := mdl.(map[string]interface{})
				if !ok {
					continue
				}
				mi := modelInfo{Name: jStr(mm, "name")}
				if sz := jFloat(mm, "size"); sz > 0 {
					mi.Size = fmt.Sprintf("%.1fGB", sz/1e9)
				}
				mlist = append(mlist, mi)
				parts = append(parts, fmt.Sprintf("%s (%s)", mi.Name, mi.Size))
			}
			r.RawData["models"] = mlist
			if len(parts) > 0 {
				r.Details = append(r.Details, "Models: "+strings.Join(parts, ", "))
			}
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: fmt.Sprintf("%d models loaded", len(mlist)),
				Severity: "high",
			})
		}
	}

	if st, _, _, err := httpGET(c, b+"/api/generate"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "/api/generate open — anyone can run inference",
			Detail:   fmt.Sprintf("HTTP %d", st),
			Severity: "critical",
		})
	}

	if st, _, _, err := httpGET(c, b+"/api/pull"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "/api/pull open — anyone can download new models",
			Detail:   fmt.Sprintf("HTTP %d", st),
			Severity: "critical",
		})
	}

	return r
}

// ── ChromaDB ────────────────────────────────────────────────────────

func enumChromaDB(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		r.Version = strings.Trim(string(body), "\" \n\r")
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/collections"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			type colInfo struct {
				Name  string `json:"name"`
				ID    string `json:"id"`
				Count int    `json:"count"`
			}
			var cols []colInfo
			totalObjects := 0
			var piiNames []string

			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(arr)))
			for _, item := range arr {
				if cm, ok := item.(map[string]interface{}); ok {
					ci := colInfo{Name: jStr(cm, "name"), ID: jStr(cm, "id")}
					if ci.ID != "" {
						cURL := fmt.Sprintf("%s/api/v1/collections/%s/count", b, ci.ID)
						if s, _, cb, e := httpGET(c, cURL); e == nil && s == 200 {
							var cnt int
							if json.Unmarshal(cb, &cnt) == nil {
								ci.Count = cnt
							}
						}
					}
					totalObjects += ci.Count
					if isPII(ci.Name) {
						piiNames = append(piiNames, ci.Name)
					}
					r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s objects)", ci.Name, fmtNum(ci.Count)))
					cols = append(cols, ci)
				}
			}
			r.RawData["collections"] = cols

			if len(piiNames) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII-indicating collection names: " + strings.Join(piiNames, ", "),
					Severity: "high",
				})
			}
			if totalObjects > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%s total objects — full read access", fmtNum(totalObjects)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── Qdrant ──────────────────────────────────────────────────────────

func enumQdrant(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/collections"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			result := jMap(m, "result")
			if result != nil {
				cols := jArray(result, "collections")
				type colDetail struct {
					Name   string `json:"name"`
					Points int    `json:"points"`
					Status string `json:"status"`
				}
				var details []colDetail
				r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(cols)))
				for _, col := range cols {
					cm, ok := col.(map[string]interface{})
					if !ok {
						continue
					}
					cd := colDetail{Name: jStr(cm, "name")}
					cURL := fmt.Sprintf("%s/collections/%s", b, cd.Name)
					if s, _, cb, e := httpGET(c, cURL); e == nil && s == 200 {
						if dm, err := parseJSON(cb); err == nil {
							if res := jMap(dm, "result"); res != nil {
								cd.Points = int(jFloat(res, "points_count"))
								cd.Status = jStr(res, "status")
							}
						}
					}
					r.Details = append(r.Details, fmt.Sprintf("  %-30s (%s points)", cd.Name, fmtNum(cd.Points)))
					details = append(details, cd)
				}
				r.RawData["collections"] = details
				r.Findings = append(r.Findings, Finding{
					Category: "schema", Title: "Collections enumerated",
					Detail:   fmt.Sprintf("%d collections accessible", len(details)),
					Severity: "high",
				})
			}
		}
	}

	if st, _, body, err := httpGET(c, b+"/cluster"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["cluster"] = m
		}
	}

	return r
}

// ── Flowise ─────────────────────────────────────────────────────────

func enumFlowise(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/flows"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Flows: %d", len(arr)))
			r.Findings = append(r.Findings, Finding{
				Category: "flows", Title: fmt.Sprintf("%d flows readable", len(arr)),
				Severity: "high",
			})
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/chatflows"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Chatflows: %d", len(arr)))
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/credentials"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Findings = append(r.Findings, Finding{
				Category: "credentials", Title: fmt.Sprintf("Credentials endpoint accessible — %d entries", len(arr)),
				Severity: "critical",
			})
		}
	}

	return r
}

// ── Jupyter ─────────────────────────────────────────────────────────

func enumJupyter(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Kernels
	if st, _, body, err := httpGET(c, b+"/api/kernels"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["kernels"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "rce", Title: "Unauthenticated code execution",
				Detail:   fmt.Sprintf("Anyone on the network gets a full shell. No token required. %d active kernel(s).", len(arr)),
				Severity: "critical",
			})
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = "token/password required"
	}

	// Sessions
	if st, _, body, err := httpGET(c, b+"/api/sessions"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["sessions"] = len(arr)
		}
	}

	// File listing + secret scanning
	if st, _, body, err := httpGET(c, b+"/api/contents"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			contents := jArray(m, "content")
			r.RawData["files"] = len(contents)

			// Look for sensitive files
			sensitiveFiles := []string{".env", ".env.local", ".env.production", "config.py", "settings.py", "credentials.json"}
			for _, item := range contents {
				im, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				fname := jStr(im, "name")
				for _, sf := range sensitiveFiles {
					if strings.EqualFold(fname, sf) || strings.HasSuffix(strings.ToLower(fname), ".env") {
						// Try to read the file
						fURL := fmt.Sprintf("%s/api/contents/%s", b, fname)
						if fs, _, fb, fe := httpGET(c, fURL); fe == nil && fs == 200 {
							if fm, fe := parseJSON(fb); fe == nil {
								content := jStr(fm, "content")
								if content != "" {
									scanSecrets(content, &r)
								}
							}
						}
						break
					}
				}
			}

			if len(contents) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "files", Title: fmt.Sprintf("File listing accessible — %d files/dirs in root", len(contents)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── MLflow ──────────────────────────────────────────────────────────

func enumMLflow(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/2.0/mlflow/experiments/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			exps := jArray(m, "experiments")
			r.Details = append(r.Details, fmt.Sprintf("Experiments: %d", len(exps)))
			r.Findings = append(r.Findings, Finding{
				Category: "experiments", Title: fmt.Sprintf("%d experiments accessible", len(exps)),
				Severity: "high",
			})
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/2.0/mlflow/registered-models/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "registered_models")
			r.Details = append(r.Details, fmt.Sprintf("Registered models: %d", len(models)))
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: fmt.Sprintf("%d registered models accessible", len(models)),
				Severity: "high",
			})
		}
	}

	return r
}

// ── Milvus ──────────────────────────────────────────────────────────

func enumMilvus(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Version / build info
	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["version_info"] = m
		}
	}

	// Health
	if st, _, body, err := httpGET(c, b+"/api/v1/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
		}
	}

	// Prometheus metrics (often exposes internal cluster info)
	if st, _, body, err := httpGET(c, b+"/metrics"); err == nil && st == 200 {
		if strings.Contains(string(body), "milvus_") {
			r.Findings = append(r.Findings, Finding{
				Category: "metrics", Title: "Prometheus metrics endpoint accessible",
				Detail:   "/metrics exposes internal cluster telemetry and deployment topology",
				Severity: "medium",
			})
		}
	}

	// Collection enumeration via REST gateway
	if st, _, body, err := httpGET(c, b+"/api/v1/collections"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			cols := jArray(m, "collection_names")
			if cols == nil {
				// Alternative response shape
				if data := jMap(m, "data"); data != nil {
					cols = jArray(data, "collection_names")
				}
			}
			var piiNames []string
			r.Details = append(r.Details, fmt.Sprintf("Collections: %d", len(cols)))
			for _, c := range cols {
				if name, ok := c.(string); ok {
					r.Details = append(r.Details, fmt.Sprintf("  %s", name))
					if isPII(name) {
						piiNames = append(piiNames, name)
					}
				}
			}
			r.RawData["collections"] = cols

			if len(cols) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%d collections enumerable without auth", len(cols)),
					Severity: "high",
				})
			}
			if len(piiNames) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII-indicating collection names: " + strings.Join(piiNames, ", "),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── Langfuse ────────────────────────────────────────────────────────

func enumLangfuse(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Health / status
	if st, _, body, err := httpGET(c, b+"/api/public/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	// Langfuse is the LLM observability platform. If it's exposed, the real
	// concern is NOT the UI but the trace/span data which contains full
	// prompt+response history. Even signup-open without auth is a finding
	// because anyone can create an account and read existing org data in
	// misconfigured deployments.

	// Check for open signup (CRITICAL misconfig in self-hosted deployments)
	if st, _, body, err := httpGET(c, b+"/api/auth/providers"); err == nil && st == 200 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "credentials") || strings.Contains(bodyStr, "email") {
			r.Findings = append(r.Findings, Finding{
				Category: "access", Title: "Authentication endpoint enumerable",
				Detail:   "Sign-in providers readable; if signup is open, attackers can self-register and access org data",
				Severity: "medium",
			})
		}
	}

	// Langfuse exposes /api/public/projects etc. Without auth these return
	// 401 when properly configured.
	if st, _, body, err := httpGET(c, b+"/api/public/projects"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "data", Title: "LLM trace data accessible without authentication",
				Detail:   "Langfuse stores full prompt/response history, system prompts, user inputs, and tool-call outputs. Unauthenticated access likely exposes production conversation data.",
				Severity: "critical",
			})
			if arr, err := parseJSONArray(body); err == nil {
				r.RawData["project_count"] = len(arr)
				r.Details = append(r.Details, fmt.Sprintf("Projects: %d", len(arr)))
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
			r.Findings = append(r.Findings, Finding{
				Category: "info", Title: "Authentication enforced on trace API",
				Severity: "info",
			})
		}
	}

	// Always flag the severity of what Langfuse contains, even when auth is on
	r.Findings = append(r.Findings, Finding{
		Category: "context", Title: "Langfuse stores LLM conversation data",
		Detail:   "This service contains full prompt/response history. Misconfigurations here leak production conversation data and potentially PII, credentials in tool-call outputs, or system prompts.",
		Severity: "info",
	})

	return r
}

// ── Dify ────────────────────────────────────────────────────────────

func enumDify(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Dify exposes /console/api/setup — returns a JSON response indicating
	// whether initial admin setup has been completed. A fresh Dify instance
	// where setup has NOT been completed is a critical finding: anyone can
	// claim the admin account.
	if st, _, body, err := httpGET(c, b+"/console/api/setup"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			setupDone := false
			if v, ok := m["step"]; ok {
				if s, ok := v.(string); ok && s == "finished" {
					setupDone = true
				}
			}
			r.RawData["setup"] = m
			if !setupDone {
				r.Findings = append(r.Findings, Finding{
					Category: "access", Title: "Dify initial setup NOT completed — admin claimable",
					Detail:   "Anyone reaching /install can register the first admin account. Claim immediately or firewall.",
					Severity: "critical",
				})
				r.AuthStatus = "none (admin claimable)"
			} else {
				r.AuthStatus = "setup completed"
			}
		}
	}

	// Version / info endpoints
	if st, _, body, err := httpGET(c, b+"/console/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	// App enumeration (usually requires auth, but some older Dify versions
	// exposed these endpoints without)
	if st, _, body, err := httpGET(c, b+"/console/api/apps"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jArray(m, "data"); data != nil {
				r.Findings = append(r.Findings, Finding{
					Category: "data", Title: fmt.Sprintf("%d Dify apps enumerable", len(data)),
					Severity: "high",
				})
			}
		}
	}

	return r
}

// ── Docker Registry (handoff only — not an AI service) ─────────────

func enumDockerRegistry(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// This is a non-AI adjacent service. aimap does not triage Docker
	// Registries in depth; that is nuclide-registry-recon's scope.
	// We note presence and key posture only.

	if st, hdrs, _, err := httpGET(c, b+"/v2/"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
		} else if st == 401 {
			if wa, ok := hdrs["Www-Authenticate"]; ok {
				r.AuthStatus = "required: " + wa
			} else {
				r.AuthStatus = "required (HTTP 401)"
			}
		}
	}

	// Catalog access check (read-only)
	if st, _, body, err := httpGET(c, b+"/v2/_catalog"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			repos := jArray(m, "repositories")
			r.RawData["repo_count"] = len(repos)
			r.Details = append(r.Details, fmt.Sprintf("Anonymous /v2/_catalog accessible — %d repositories", len(repos)))
			if len(repos) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "adjacent", Title: fmt.Sprintf("Docker Registry — %d repos anonymously enumerable", len(repos)),
					Detail:   "Adjacent to AI services. Use nuclide-registry-recon or scripts/registry_triage.py for full triage.",
					Severity: "medium",
				})
			}
		}
	} else {
		r.Findings = append(r.Findings, Finding{
			Category: "adjacent", Title: "Docker Registry detected",
			Detail:   "Adjacent to AI services. Not fully triaged by aimap. Use nuclide-registry-recon for depth.",
			Severity: "low",
		})
	}

	return r
}

// ── Generic checks ──────────────────────────────────────────────────

func checkGeneric(c *http.Client, svc ServiceMatch) []Finding {
	var findings []Finding
	b := svc.BaseURL

	if _, hdrs, _, err := httpGET(c, b+"/"); err == nil {
		if cors, ok := hdrs["Access-Control-Allow-Origin"]; ok && cors == "*" {
			findings = append(findings, Finding{
				Category: "cors", Title: "CORS: Access-Control-Allow-Origin: *",
				Severity: "medium",
			})
		}
		for _, h := range []string{"X-Powered-By", "X-AspNet-Version"} {
			if v, ok := hdrs[h]; ok && v != "" {
				findings = append(findings, Finding{
					Category: "headers", Title: fmt.Sprintf("%s header disclosed", h),
					Detail: v, Severity: "low",
				})
			}
		}
	}

	if svc.MatchBody != nil {
		bodyStr := string(svc.MatchBody)
		for _, sp := range secretPatterns {
			if strings.Contains(bodyStr, sp.Pattern) {
				findings = append(findings, Finding{
					Category: "secrets", Title: fmt.Sprintf("Possible %s in response", sp.Name),
					Detail:   fmt.Sprintf("Pattern '%s' found in probe response", sp.Pattern),
					Severity: "critical",
				})
			}
		}
	}

	return findings
}

func computeRisk(r EnumResult) string {
	ranks := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	best := "info"
	for _, f := range r.Findings {
		if ranks[f.Severity] > ranks[best] {
			best = f.Severity
		}
	}
	if r.AuthStatus == "none" && best == "high" {
		return "critical"
	}
	return best
}
