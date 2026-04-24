package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// langfuseNextDataRe extracts the Next.js __NEXT_DATA__ JSON blob from a
// server-rendered Langfuse page. The blob embeds `props.pageProps` which on
// /auth/sign-in includes `signUpDisabled`, `authProviders`, and
// `runningOnHuggingFaceSpaces` — the fastest way to audit a Langfuse
// deployment's posture without logging in.
var langfuseNextDataRe = regexp.MustCompile(`<script id="__NEXT_DATA__" type="application/json">(.+?)</script>`)

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
		case "SillyTavern":
			result = enumSillyTavern(client, svc)
		case "Open WebUI":
			result = enumOpenWebUI(client, svc)
		case "OpenHands":
			result = enumOpenHands(client, svc)
		case "Mem0":
			result = enumMem0(client, svc)
		case "Coolify":
			result = enumCoolify(client, svc)
		case "Clawdbot":
			result = enumClawdbot(client, svc)
		case "Open Directory":
			result = enumOpenDirectory(client, svc)
		case "Dify":
			result = enumDify(client, svc)
		case "Docker Registry":
			result = enumDockerRegistry(client, svc)
		case "Grafana":
			result = enumGrafana(client, svc)
		case "Prometheus":
			result = enumPrometheus(client, svc)
		case "etcd":
			result = enumEtcd(client, svc)
		case "MinIO":
			result = enumMinIO(client, svc)
		case "n8n":
			result = enumN8n(client, svc)
		case "SGLang":
			result = enumSGLang(client, svc)
		case "vLLM":
			result = enumVLLM(client, svc)
		case "AI TTS Server":
			result = enumTTS(client, svc)
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
		r.Findings = append(r.Findings, Finding{
			Category: "cve",
			Title:    "CVE-2024-36420 — Auth bypass via path traversal (< 1.8.2)",
			Detail:   "Path traversal grants unauth access to chatflow config and embedded API keys. Verify version.",
			Severity: "high",
		})
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

	r.Findings = append(r.Findings, Finding{
		Category: "cve",
		Title:    "CVE-2024-37052…37060 — RCE via model deserialization",
		Detail:   "Any exposed MLflow with write access to the model registry is RCE. Chain: upload malicious pickle model → trigger load → code execution.",
		Severity: "critical",
	})

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

	// Deep posture audit via /auth/sign-in — Langfuse SSR-embeds the auth
	// config in a __NEXT_DATA__ JSON blob. This is the fastest way to see
	// whether signup is open and which SSO providers (if any) are configured,
	// without having to create an account.
	if st, _, body, err := httpGET(c, b+"/auth/sign-in"); err == nil && st == 200 {
		if m := langfuseNextDataRe.FindSubmatch(body); len(m) == 2 {
			var wrap struct {
				Props struct {
					PageProps map[string]interface{} `json:"pageProps"`
				} `json:"props"`
			}
			if err := json.Unmarshal(m[1], &wrap); err == nil {
				pp := wrap.Props.PageProps
				r.RawData["sign_in_config"] = pp

				// signUpDisabled: false → anyone on the internet can register.
				// For a self-hosted Langfuse on corporate infra, this is almost
				// always unintended.
				if v, ok := pp["signUpDisabled"].(bool); ok && !v {
					r.Findings = append(r.Findings, Finding{
						Category: "access", Title: "Langfuse signup is open to the public",
						Detail:   "signUpDisabled=false. Any internet visitor can register an account, persisting a user record in the operator's Postgres and enabling authenticated API probing. Set LANGFUSE_AUTH_DISABLE_SIGNUP=true or restrict via LANGFUSE_AUTH_DOMAINS_*.",
						Severity: "medium",
					})
				}

				// authProviders: inventory configured SSO and flag the common
				// misconfig of password-only auth on a production deployment.
				if ap, ok := pp["authProviders"].(map[string]interface{}); ok {
					var enabled []string
					credsOnly := false
					for name, val := range ap {
						if b, ok := val.(bool); ok && b {
							enabled = append(enabled, name)
						}
					}
					if len(enabled) == 1 && enabled[0] == "credentials" {
						credsOnly = true
					}
					if len(enabled) > 0 {
						r.Details = append(r.Details, "Auth providers: "+strings.Join(enabled, ", "))
					}
					if credsOnly {
						r.Findings = append(r.Findings, Finding{
							Category: "access", Title: "Credentials-only auth (no SSO configured)",
							Detail:   "Only password-based authentication is enabled. No OIDC/SAML provider configured, which removes the identity-provider brute-force ceiling and centralized MFA. Configure LANGFUSE_AUTH_*_CLIENT_* for Google/GitHub/Okta/Azure AD.",
							Severity: "low",
						})
					}
				}

				// runningOnHuggingFaceSpaces flag — informational. This alters
				// default auth semantics and sometimes exposes SPACE_HOST.
				if v, ok := pp["runningOnHuggingFaceSpaces"].(bool); ok && v {
					r.Findings = append(r.Findings, Finding{
						Category: "info", Title: "Running as HuggingFace Space",
						Detail:   "runningOnHuggingFaceSpaces=true — HF Spaces deployments use different default auth semantics.",
						Severity: "info",
					})
				}
			}
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

// ── SillyTavern ─────────────────────────────────────────────────────

func enumSillyTavern(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	r.AuthStatus = "basic"
	if strings.HasPrefix(svc.BaseURL, "http://") {
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "SillyTavern protected by HTTP Basic Auth (cleartext credentials)",
			Detail:   "Basic Auth over plain HTTP transmits base64-encoded credentials without encryption. Upgrade to HTTPS or place behind a TLS reverse proxy.",
			Severity: "medium",
		})
	}
	return r
}

// ── Open WebUI ──────────────────────────────────────────────────────

func enumOpenWebUI(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	authEnabled := true
	signupEnabled := false
	if st, _, body, err := httpGET(c, b+"/api/config"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if feats, ok := m["features"].(map[string]interface{}); ok {
				if v, ok := feats["auth"].(bool); ok {
					authEnabled = v
				}
				if v, ok := feats["enable_signup"].(bool); ok {
					signupEnabled = v
				}
			}
			r.RawData["config"] = m
		}
	}

	if !authEnabled {
		r.AuthStatus = "none"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Open WebUI running without authentication",
			Detail:   "AUTH_ENABLED=false — all API endpoints and chat history accessible without credentials.",
			Severity: "critical",
		})
	} else if signupEnabled {
		r.AuthStatus = "open registration"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Open WebUI allows public self-registration",
			Detail:   "enable_signup=true — anyone can create an account and access connected LLM backends.",
			Severity: "high",
		})
	} else {
		r.AuthStatus = "auth required"
	}

	// Even with auth enabled, check if the OpenAI-compatible API is exposed
	if st, _, body, err := httpGET(c, b+"/api/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jArray(m, "data"); data != nil {
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    fmt.Sprintf("Open WebUI /api/models unauthenticated — %d model(s) listed", len(data)),
					Severity: "critical",
				})
				r.AuthStatus = "none"
			}
		}
	}

	return r
}

// ── Docker Registry ─────────────────────────────────────────────────

var aiRegistryImages = []string{
	"ollama", "vllm", "localai", "llama", "mistral", "deepseek",
	"ragflow", "langflow", "flowise", "dify", "openwebui", "open-webui",
	"sglang", "lmdeploy", "triton", "mlflow", "ray",
	"pytorch", "tensorflow", "transformers", "huggingface",
	"chromadb", "qdrant", "weaviate", "milvus",
	"n8n", "langchain", "autogen", "comfyui", "stable-diffusion",
}

func enumDockerRegistry(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

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

	if st, _, body, err := httpGET(c, b+"/v2/_catalog"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			repos := jArray(m, "repositories")
			r.RawData["repo_count"] = len(repos)
			r.Details = append(r.Details, fmt.Sprintf("Repositories: %d", len(repos)))

			// Score AI-relevant images
			var aiRepos []string
			for _, repo := range repos {
				name, ok := repo.(string)
				if !ok {
					continue
				}
				lower := strings.ToLower(name)
				for _, tag := range aiRegistryImages {
					if strings.Contains(lower, tag) {
						aiRepos = append(aiRepos, name)
						break
					}
				}
			}

			if len(aiRepos) > 0 {
				r.Details = append(r.Details, fmt.Sprintf("AI images: %s", strings.Join(aiRepos, ", ")))
				r.Findings = append(r.Findings, Finding{
					Category: "ai-images",
					Title:    fmt.Sprintf("%d AI/ML images in anonymous registry — pull without auth", len(aiRepos)),
					Detail:   strings.Join(aiRepos, ", "),
					Severity: "high",
				})
			}

			if len(repos) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "access",
					Title:    fmt.Sprintf("%d repos anonymously enumerable via /v2/_catalog", len(repos)),
					Severity: "medium",
				})
			}
		}
	} else {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "Docker Registry detected — catalog access denied",
			Severity: "low",
		})
	}

	return r
}

// ── Grafana ─────────────────────────────────────────────────────────

func enumGrafana(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/api/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["health"] = m
		}
	}

	// Datasources — unauthenticated access = credential exposure (DB URLs, API keys)
	if st, _, body, err := httpGET(c, b+"/api/datasources"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if arr, err := parseJSONArray(body); err == nil {
				r.Details = append(r.Details, fmt.Sprintf("Datasources: %d", len(arr)))
				r.Findings = append(r.Findings, Finding{
					Category: "credentials",
					Title:    fmt.Sprintf("%d datasources exposed — connection strings and keys readable", len(arr)),
					Severity: "critical",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Anonymous access check — Grafana has a grafana.ini anon.enabled option
	if st, _, body, err := httpGET(c, b+"/api/org"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.AuthStatus = "none (anonymous access enabled)"
			r.RawData["org"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "Grafana anonymous access enabled — dashboards readable without login",
				Severity: "medium",
			})
		}
	}

	// Alert rules may contain sensitive metric names and infra topology
	if st, _, body, err := httpGET(c, b+"/api/ruler/grafana/api/v1/rules"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["alert_rules"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "info",
				Title:    "Alert rules readable — internal service topology disclosed",
				Severity: "low",
			})
		}
	}

	return r
}

// ── Prometheus ──────────────────────────────────────────────────────

func enumPrometheus(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/api/v1/status/runtimeinfo"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				r.Version = jStr(data, "version")
				r.RawData["runtimeinfo"] = data
			}
		}
	}

	// Config dump — may contain scrape targets with credentials in URLs
	if st, _, body, err := httpGET(c, b+"/api/v1/status/config"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				cfg := jStr(data, "yaml")
				scanSecrets(cfg, &r)
				r.Findings = append(r.Findings, Finding{
					Category: "config",
					Title:    "Full Prometheus config readable — scrape targets and credentials exposed",
					Detail:   "Check for basic_auth, bearer_token, and tls_config entries in the YAML dump.",
					Severity: "high",
				})
			}
		}
	}

	// Targets — full internal service map
	if st, _, body, err := httpGET(c, b+"/api/v1/targets"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if data := jMap(m, "data"); data != nil {
				active := jArray(data, "activeTargets")
				r.Details = append(r.Details, fmt.Sprintf("Active scrape targets: %d", len(active)))
				r.RawData["target_count"] = len(active)
				if len(active) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "topology",
						Title:    fmt.Sprintf("%d active scrape targets — full internal service map readable", len(active)),
						Severity: "medium",
					})
				}
			}
		}
	}

	// Alert rules
	if st, _, body, err := httpGET(c, b+"/api/v1/rules"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["rules"] = m
		}
	}

	return r
}

// ── etcd ─────────────────────────────────────────────────────────────

func enumEtcd(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, body, err := httpGET(c, b+"/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "etcdserver")
			r.RawData["version"] = m
		}
	}

	if st, _, body, err := httpGET(c, b+"/health"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["health"] = m
			r.AuthStatus = "none"
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "etcd unauthenticated — full cluster secret disclosure",
				Detail:   "All Kubernetes secrets, service account tokens, kubeconfig data, and TLS certs readable via /v3/kv/range. Effectively cluster takeover.",
				Severity: "critical",
			})
		}
	}

	// Key dump via gRPC-gateway (etcd v3 HTTP API)
	// POST /v3/kv/range with empty key range returns all keys
	if st, _, body, err := httpGET(c, b+"/v3/kv/range"); err == nil && st != 404 {
		r.RawData["v3_api_accessible"] = true
		r.Details = append(r.Details, fmt.Sprintf("v3 KV API: HTTP %d", st))
		if st == 200 {
			if m, err := parseJSON(body); err == nil {
				if kvs := jArray(m, "kvs"); kvs != nil {
					r.Details = append(r.Details, fmt.Sprintf("Keys returned: %d", len(kvs)))
					scanSecrets(string(body), &r)
				}
			}
		}
	}

	// Members — cluster topology
	if st, _, body, err := httpGET(c, b+"/v3/cluster/member/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			members := jArray(m, "members")
			r.Details = append(r.Details, fmt.Sprintf("Cluster members: %d", len(members)))
			r.RawData["members"] = members
		}
	}

	return r
}

// ── MinIO ────────────────────────────────────────────────────────────

func enumMinIO(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	if st, _, _, err := httpGET(c, b+"/minio/health/live"); err == nil && st == 200 {
		r.AuthStatus = "S3 API (check bucket policies)"
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "MinIO S3 API reachable",
			Detail:   "Check anonymous bucket policies. Anonymous GET/LIST on buckets exposes stored model artifacts, training data, and MLflow experiment artifacts.",
			Severity: "medium",
		})
	}

	// S3 list-buckets (root /) — requires auth on MinIO by default,
	// but anonymous access is configurable per-bucket
	if st, _, body, err := httpGET(c, b+"/"); err == nil {
		if st == 200 && strings.Contains(strings.ToLower(string(body)), "<listallmybucketsresult") {
			r.AuthStatus = "none — anonymous bucket listing"
			r.Findings = append(r.Findings, Finding{
				Category: "data",
				Title:    "Anonymous bucket listing enabled — all buckets enumerable",
				Severity: "critical",
			})
		} else if strings.Contains(strings.ToLower(string(body)), "accessdenied") {
			r.AuthStatus = "required"
		}
	}

	return r
}

// ── n8n ──────────────────────────────────────────────────────────────

func enumN8n(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "unknown"

	// Unauthenticated workflow enumeration
	if st, _, body, err := httpGET(c, b+"/rest/active-workflows"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				workflows := jArray(m, "data")
				r.Details = append(r.Details, fmt.Sprintf("Active workflows: %d", len(workflows)))
				r.Findings = append(r.Findings, Finding{
					Category: "rce",
					Title:    fmt.Sprintf("n8n unauthenticated — %d active workflows — RCE by design", len(workflows)),
					Detail:   "n8n workflow nodes execute arbitrary JavaScript and shell commands. Write access = unrestricted code execution. No CVE; this is intended behavior.",
					Severity: "critical",
				})
			}
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Credentials endpoint — provider API keys stored in n8n
	if st, _, body, err := httpGET(c, b+"/rest/credentials"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			creds := jArray(m, "data")
			if len(creds) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "credentials",
					Title:    fmt.Sprintf("%d stored credentials accessible — provider API keys exposed", len(creds)),
					Severity: "critical",
				})
			}
		}
	}

	return r
}

func enumTTS(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Service info from root
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if name := jStr(m, "name"); name != "" {
				r.Details = append(r.Details, "Server: "+name)
			}
			if model := jStr(m, "model"); model != "" {
				r.Version = model
				r.Details = append(r.Details, "Model: "+model)
			}
		}
	}

	// Voice list
	if st, _, body, err := httpGET(c, b+"/v1/audio/voices"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Details = append(r.Details, fmt.Sprintf("Voices available: %d", len(arr)))
		} else if m, err := parseJSON(body); err == nil {
			voices := jArray(m, "voices")
			r.Details = append(r.Details, fmt.Sprintf("Voices available: %d", len(voices)))
		}
	}

	r.Findings = append(r.Findings, Finding{
		Category: "exposure",
		Title:    "AI TTS server unauthenticated — /v1/audio/speech open",
		Detail:   "OpenAI-compatible TTS endpoint accessible without credentials. Attacker can generate arbitrary speech, consume compute, potentially abuse voice cloning if enabled.",
		Severity: "medium",
	})
	return r
}

func enumSGLang(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Model info — SGLang-specific endpoint
	if st, _, body, err := httpGET(c, b+"/get_model_info"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if v := jStr(m, "model_path"); v != "" {
				r.Details = append(r.Details, "Model: "+v)
				r.Version = v
			}
			if v := jStr(m, "is_generation"); v != "" {
				r.Details = append(r.Details, "Generation mode: "+v)
			}
		}
	}

	// OpenAI-compat model list
	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "data")
			r.Details = append(r.Details, fmt.Sprintf("Models served: %d", len(models)))
			for _, mdl := range models {
				if mm, ok := mdl.(map[string]interface{}); ok {
					if id, ok := mm["id"].(string); ok {
						r.Details = append(r.Details, "  - "+id)
					}
				}
			}
		}
	}

	// Server info
	if st, _, body, err := httpGET(c, b+"/get_server_info"); err == nil && st == 200 {
		r.RawData["server_info"] = json.RawMessage(body)
	}

	if r.AuthStatus == "none" {
		r.Findings = append(r.Findings, Finding{
			Category: "exposure",
			Title:    "SGLang inference server unauthenticated",
			Detail:   "Full model inference available without credentials. Attacker can enumerate loaded models, run arbitrary prompts, and consume compute.",
			Severity: "high",
		})
	}
	return r
}

func enumVLLM(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	if st, _, body, err := httpGET(c, b+"/v1/models"); err == nil {
		if st == 200 {
			r.AuthStatus = "none"
			if m, err := parseJSON(body); err == nil {
				models := jArray(m, "data")
				r.Details = append(r.Details, fmt.Sprintf("Models served: %d", len(models)))
				for _, mdl := range models {
					if mm, ok := mdl.(map[string]interface{}); ok {
						if id, ok := mm["id"].(string); ok {
							r.Details = append(r.Details, "  - "+id)
						}
					}
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "exposure",
				Title:    "vLLM OpenAI-compatible API unauthenticated",
				Detail:   "Full inference access without credentials. /v1/completions and /v1/chat/completions accessible.",
				Severity: "high",
			})
		} else if st == 401 || st == 403 {
			r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
		}
	}

	// Check completions endpoint directly
	if st, _, _, err := httpGET(c, b+"/v1/completions"); err == nil && st != 404 {
		r.Details = append(r.Details, fmt.Sprintf("/v1/completions → HTTP %d", st))
	}
	return r
}

// ── Open Directory ──────────────────────────────────────────────────

func enumOpenDirectory(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		bodyStr := string(body)

		// Count entries in directory listing
		entries := strings.Count(bodyStr, "<li>") + strings.Count(bodyStr, `href="`)
		if entries > 2 {
			r.Details = append(r.Details, fmt.Sprintf("~%d entries visible", entries/2))
		}

		// Scan for high-value filenames/paths
		highValue := []struct {
			needle   string
			severity string
			title    string
		}{
			{".env", "critical", ".env file exposed — may contain credentials"},
			{"docker-compose", "high", "docker-compose file exposed — reveals service topology"},
			{".ssh/", "critical", "SSH directory exposed"},
			{"id_rsa", "critical", "SSH private key exposed"},
			{"credentials", "critical", "Credentials file exposed"},
			{".claude/", "high", "Claude AI config directory exposed (.claude/)"},
			{".openhands/", "high", "OpenHands AI agent config exposed (.openhands/)"},
			{"CLAUDE.md", "high", "CLAUDE.md instructions file exposed — may contain sensitive directives"},
			{"api_key", "critical", "API key file exposed"},
			{"secret", "high", "Secret file exposed"},
			{"backup", "medium", "Backup file/directory exposed"},
			{".git/", "high", ".git directory exposed — full source history accessible"},
			{"Dockerfile", "medium", "Dockerfile exposed — reveals build environment"},
			{"requirements.txt", "low", "Python requirements file exposed"},
			{"package.json", "low", "Node.js package manifest exposed"},
		}

		for _, hv := range highValue {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(hv.needle)) {
				r.Findings = append(r.Findings, Finding{
					Category: "exposure",
					Title:    hv.title,
					Detail:   fmt.Sprintf("Filename/path '%s' found in directory listing", hv.needle),
					Severity: hv.severity,
				})
			}
		}

		scanSecrets(bodyStr, &r)
	}

	r.Findings = append(r.Findings, Finding{
		Category: "access",
		Title:    "Unauthenticated directory listing — full filesystem tree browsable",
		Detail:   "Server serving files with no authentication; all listed contents are downloadable.",
		Severity: "high",
	})

	return r
}

// ── OpenHands ───────────────────────────────────────────────────────

func enumOpenHands(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Detect admin console vs. regular UI
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		if strings.Contains(strings.ToLower(string(body)), "admin console") {
			r.Details = append(r.Details, "Variant: Admin Console")
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "OpenHands Admin Console — unclaimed setup wizard accessible",
				Detail:   "First visitor can configure the admin account with no prior credentials.",
				Severity: "critical",
			})
			r.AuthStatus = "none"
		}
	}

	// Try settings/config API — unauthenticated on default installs
	if st, _, body, err := httpGET(c, b+"/api/v1/settings"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if m, err := parseJSON(body); err == nil {
			r.RawData["settings"] = m
		}
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "OpenHands /api/v1/settings accessible without authentication",
			Severity: "critical",
		})
	} else if r.AuthStatus == "unknown" {
		if st == 401 || st == 403 {
			r.AuthStatus = "auth required"
		}
	}

	// Pull agent list
	if st, _, body, err := httpGET(c, b+"/api/v1/agents"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if agents := jArray(m, "agents"); agents != nil {
				r.Details = append(r.Details, fmt.Sprintf("Agents available: %d", len(agents)))
			}
		}
	}

	return r
}

// ── Mem0 ────────────────────────────────────────────────────────────

func enumMem0(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Pull OpenAPI spec for version
	if st, _, body, err := httpGET(c, b+"/openapi.json"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if info := jMap(m, "info"); info != nil {
				r.Version = jStr(info, "version")
			}
			r.RawData["openapi"] = m
		}
	}

	// Probe memory endpoint — Mem0 default requires Authorization: Token <key>
	if st, _, body, err := httpGET(c, b+"/v1/memories?user_id=test"); err == nil {
		switch st {
		case 200:
			r.AuthStatus = "none"
			count := 0
			if m, err := parseJSON(body); err == nil {
				if arr := jArray(m, "memories"); arr != nil {
					count = len(arr)
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    fmt.Sprintf("Mem0 /v1/memories unauthenticated — %d entries accessible", count),
				Detail:   "AI agent memory store readable without API key; may contain conversation history, user PII, or agent state.",
				Severity: "critical",
			})
		case 401, 403:
			r.AuthStatus = "auth required"
		default:
			r.AuthStatus = "unknown"
		}
	}

	// Check /v1/users for user enumeration
	if st, _, body, err := httpGET(c, b+"/v1/users"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			if users := jArray(m, "users"); users != nil {
				r.Details = append(r.Details, fmt.Sprintf("Users in memory store: %d", len(users)))
			}
		}
		_ = body
	}

	return r
}

// ── Coolify ─────────────────────────────────────────────────────────

func enumCoolify(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Coolify returns JSON 401 {"message":"Unauthenticated."} for API clients.
	// A 200 at /api/v1/settings would mean auth is disabled (extremely unusual).
	if st, _, body, err := httpGET(c, b+"/api/v1/settings"); err == nil {
		switch st {
		case 200:
			if m, err := parseJSON(body); err == nil {
				r.RawData["settings"] = m
				if jStr(m, "registration_enabled") == "true" {
					r.AuthStatus = "open registration"
					r.Findings = append(r.Findings, Finding{
						Category: "access",
						Title:    "Coolify open registration — anyone can create an admin account",
						Severity: "high",
					})
				} else {
					r.AuthStatus = "auth required"
				}
			}
		case 401, 403:
			r.AuthStatus = "auth required"
		}
	}

	// Check if registration is open on the login page (HTML mode, no JSON Accept)
	if st, _, body, err := httpGET(c, b+"/login"); err == nil && st == 200 {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "register") && !strings.Contains(bodyStr, "disabled") {
			r.AuthStatus = "open registration"
			r.Findings = append(r.Findings, Finding{
				Category: "access",
				Title:    "Coolify self-registration enabled — public account creation allowed",
				Severity: "high",
			})
		} else if r.AuthStatus == "unknown" {
			r.AuthStatus = "auth required"
		}
	}

	return r
}

// ── Clawdbot ─────────────────────────────────────────────────────────

func enumClawdbot(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL

	// Extract assistant name and avatar from the SPA index HTML
	if st, _, body, err := httpGET(c, b+"/"); err == nil && st == 200 {
		bodyStr := string(body)
		if idx := strings.Index(bodyStr, `__CLAWDBOT_ASSISTANT_NAME__="`); idx >= 0 {
			rest := bodyStr[idx+len(`__CLAWDBOT_ASSISTANT_NAME__="`):]
			if end := strings.IndexByte(rest, '"'); end > 0 {
				r.Details = append(r.Details, "Assistant name: "+rest[:end])
			}
		}
		if idx := strings.Index(bodyStr, `__CLAWDBOT_ASSISTANT_AVATAR__="`); idx >= 0 {
			rest := bodyStr[idx+len(`__CLAWDBOT_ASSISTANT_AVATAR__="`):]
			if end := strings.IndexByte(rest, '"'); end > 0 {
				r.Details = append(r.Details, "Avatar: "+rest[:end])
			}
		}
	}

	// Probe the WebSocket gateway — the SPA is a catch-all so HTTP paths are
	// useless for auth detection; the real backend is a WS gateway.
	useTLS := strings.HasPrefix(svc.BaseURL, "https://")
	authStatus, wsDetail := clawdbotWSProbe(svc.Host, svc.Port, useTLS, 6*time.Second)
	r.AuthStatus = authStatus
	if wsDetail != "" {
		r.Details = append(r.Details, wsDetail)
	}

	switch authStatus {
	case "none":
		r.Findings = append(r.Findings, Finding{
			Category: "access",
			Title:    "Clawdbot gateway accessible without authentication",
			Detail:   "WebSocket gateway accepts connections without a valid token.",
			Severity: "critical",
		})
	case "token required":
		// Expected secure state — gateway requires pre-issued token
	}

	r.Findings = append(r.Findings, Finding{
		Category: "exposure",
		Title:    "Clawdbot Control UI exposed to internet",
		Detail:   "OpenClaw management interface accessible publicly; intended for Tailscale/VPN-only access.",
		Severity: "medium",
	})
	r.Findings = append(r.Findings, checkGeneric(c, svc)...)
	return r
}

// clawdbotWSProbe performs a minimal WebSocket handshake and connect probe
// to determine the Clawdbot gateway auth posture without external dependencies.
func clawdbotWSProbe(host string, port int, useTLS bool, timeout time.Duration) (authStatus, detail string) {
	addr := fmt.Sprintf("%s:%d", host, port)

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return "unknown", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Valid 16-byte base64 key for the WS upgrade handshake.
	rawKey := base64.StdEncoding.EncodeToString([]byte("clawdbotprobe123"))

	handshake := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		addr, rawKey,
	)
	if _, err := conn.Write([]byte(handshake)); err != nil {
		return "unknown", ""
	}

	// The 101 response and the first WS frame (challenge) often arrive in the
	// same TCP segment. Read everything available, split on \r\n\r\n.
	initial := make([]byte, 4096)
	n, _ := conn.Read(initial)
	initial = initial[:n]

	sep := []byte("\r\n\r\n")
	idx := strings.Index(string(initial), "\r\n\r\n")
	if idx < 0 || !strings.Contains(string(initial[:idx+4]), "101") {
		return "unknown", ""
	}
	_ = sep

	// Bytes after the HTTP headers are the first WS frame(s).
	buf := newWSBuffer(conn, initial[idx+4:])

	challengeFrame, err := buf.readFrame()
	if err != nil || !strings.Contains(string(challengeFrame), "connect.challenge") {
		return "unknown", ""
	}
	var challengeMsg struct {
		Payload struct {
			Nonce string `json:"nonce"`
			Ts    int64  `json:"ts"`
		} `json:"payload"`
	}
	json.Unmarshal(challengeFrame, &challengeMsg)
	nonce := challengeMsg.Payload.Nonce

	// Generate an ephemeral Ed25519 keypair and sign the challenge.
	// The client-side JS uses Ed25519 (SHA-512 key expansion) matching stdlib.
	// A fresh unregistered keypair lets us reach the token check, not just schema validation.
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubBytes := []byte(pubKey)
	devIDBytes := sha256.Sum256(pubBytes)
	deviceID := fmt.Sprintf("%x", devIDBytes)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubBytes)
	signedAt := challengeMsg.Payload.Ts + 1
	scopes := "operator.admin,operator.approvals,operator.pairing"
	msgToSign := fmt.Sprintf("v2|%s|clawdbot-control-ui|webchat|operator|%s|%d||%s",
		deviceID, scopes, signedAt, nonce)
	sig := ed25519.Sign(privKey, []byte(msgToSign))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	connectPayload := fmt.Sprintf(
		`{"type":"req","id":"00000000-0000-0000-0000-000000000001","method":"connect","params":{`+
			`"minProtocol":3,"maxProtocol":3,`+
			`"client":{"id":"clawdbot-control-ui","version":"dev","platform":"web","mode":"webchat","instanceId":"probe"},`+
			`"role":"operator","scopes":["operator.admin","operator.approvals","operator.pairing"],`+
			`"device":{"id":%q,"publicKey":%q,"signature":%q,"signedAt":%d,"nonce":%q},`+
			`"caps":[],"auth":{},"userAgent":"aimap/1.0","locale":"en-US"}}`,
		deviceID, pubB64, sigB64, signedAt, nonce,
	)
	if err := wsSendTextFrame(conn, []byte(connectPayload)); err != nil {
		return "unknown", ""
	}

	resp, err := buf.readFrame()
	if err != nil {
		return "unknown", ""
	}

	var reply struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp, &reply); err != nil {
		return "unknown", ""
	}

	if reply.OK {
		return "none", "WS gateway: open (no token required)"
	}
	msg := reply.Error.Message
	if strings.Contains(msg, "token missing") || strings.Contains(msg, "unauthorized") {
		return "token required", "WS gateway: " + truncStr(msg, 60)
	}
	return "restricted", "WS gateway: " + truncStr(msg, 60)
}

// wsBuffer wraps a net.Conn with a pre-read buffer for parsing WS frames.
type wsBuffer struct {
	conn net.Conn
	buf  []byte
}

func newWSBuffer(conn net.Conn, initial []byte) *wsBuffer {
	return &wsBuffer{conn: conn, buf: append([]byte(nil), initial...)}
}

func (w *wsBuffer) read(p []byte) (int, error) {
	if len(w.buf) >= len(p) {
		copy(p, w.buf[:len(p)])
		w.buf = w.buf[len(p):]
		return len(p), nil
	}
	// Drain buffer first, then read from conn
	n := copy(p, w.buf)
	w.buf = w.buf[:0]
	if n < len(p) {
		m, err := w.conn.Read(p[n:])
		return n + m, err
	}
	return n, nil
}

func (w *wsBuffer) readN(n int) ([]byte, error) {
	buf := make([]byte, n)
	total := 0
	for total < n {
		got, err := w.read(buf[total:])
		total += got
		if err != nil {
			return buf[:total], err
		}
	}
	return buf, nil
}

func (w *wsBuffer) readFrame() ([]byte, error) {
	hdr, err := w.readN(2)
	if err != nil {
		return nil, err
	}
	plen := int(hdr[1] & 0x7f)
	if plen == 126 {
		ext, err := w.readN(2)
		if err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint16(ext))
	} else if plen == 127 {
		ext, err := w.readN(8)
		if err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint64(ext))
	}
	if plen > 64*1024 {
		plen = 64 * 1024
	}
	return w.readN(plen)
}

// wsSendTextFrame sends a masked WebSocket text frame (client→server must be masked).
func wsSendTextFrame(conn net.Conn, payload []byte) error {
	plen := len(payload)
	var header []byte
	header = append(header, 0x81) // FIN + text opcode
	if plen < 126 {
		header = append(header, byte(0x80|plen))
	} else {
		header = append(header, 0x80|126, byte(plen>>8), byte(plen))
	}
	// masking key (all zeros for simplicity — valid per RFC 6455)
	mask := [4]byte{}
	header = append(header, mask[:]...)
	frame := append(header, payload...) // mask of 0x00 is a no-op XOR
	_, err := conn.Write(frame)
	return err
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
