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
