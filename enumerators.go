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

		// Append generic checks for all services
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

	// Meta
	if st, _, body, err := httpGET(c, b+"/v1/meta"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
			r.RawData["meta"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "info", Title: "Version and metadata disclosed",
				Detail:   fmt.Sprintf("Weaviate %s, hostname: %s", jStr(m, "version"), jStr(m, "hostname")),
				Severity: "medium",
			})
			if mods := jMap(m, "modules"); mods != nil {
				names := make([]string, 0, len(mods))
				for k := range mods {
					names = append(names, k)
				}
				r.RawData["modules"] = names
				if len(names) > 0 {
					r.Findings = append(r.Findings, Finding{
						Category: "info", Title: "Modules exposed",
						Detail:   strings.Join(names, ", "),
						Severity: "low",
					})
				}
			}
		}
	}

	// Auth check
	r.AuthStatus = "none"
	if st, _, _, err := httpGET(c, b+"/.well-known/openid-configuration"); err == nil && st == 200 {
		r.AuthStatus = "OIDC configured"
	}

	// Schema
	if st, _, body, err := httpGET(c, b+"/v1/schema"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			classes := jArray(m, "classes")
			r.RawData["collection_count"] = len(classes)

			type colInfo struct {
				Name       string   `json:"name"`
				Vectorizer string   `json:"vectorizer"`
				Props      int      `json:"properties"`
				Objects    int      `json:"objects"`
				PII        []string `json:"pii_fields,omitempty"`
			}
			var cols []colInfo
			var allPII []string

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
						allPII = append(allPII, ci.Name+"."+pName)
					}
				}

				// Object count
				url := fmt.Sprintf("%s/v1/objects?class=%s&limit=1", b, ci.Name)
				if s, _, ob, e := httpGET(c, url); e == nil && s == 200 {
					if om, e := parseJSON(ob); e == nil {
						ci.Objects = int(jFloat(om, "totalResults"))
					}
				}
				cols = append(cols, ci)
			}
			r.RawData["collections"] = cols

			r.Findings = append(r.Findings, Finding{
				Category: "schema", Title: "Full schema readable",
				Detail:   fmt.Sprintf("%d collections enumerated", len(cols)),
				Severity: "high", Data: cols,
			})
			if len(allPII) > 0 {
				r.Findings = append(r.Findings, Finding{
					Category: "pii", Title: "PII-like field names detected",
					Detail:   strings.Join(allPII, ", "),
					Severity: "high", Data: allPII,
				})
			}
		}
	}

	// Nodes
	if st, _, body, err := httpGET(c, b+"/v1/nodes"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			nodes := jArray(m, "nodes")
			r.RawData["node_count"] = len(nodes)
			r.Findings = append(r.Findings, Finding{
				Category: "cluster", Title: "Cluster topology exposed",
				Detail:   fmt.Sprintf("%d node(s)", len(nodes)),
				Severity: "medium",
			})
		}
	}

	return r
}

// ── Ollama ──────────────────────────────────────────────────────────

func enumOllama(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	b := svc.BaseURL
	r.AuthStatus = "none"

	// Version
	if st, _, body, err := httpGET(c, b+"/api/version"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.Version = jStr(m, "version")
		}
	}

	// Models
	if st, _, body, err := httpGET(c, b+"/api/tags"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "models")
			type modelInfo struct {
				Name string `json:"name"`
				Size string `json:"size"`
			}
			var mlist []modelInfo
			for _, mdl := range models {
				mm, ok := mdl.(map[string]interface{})
				if !ok {
					continue
				}
				mi := modelInfo{Name: jStr(mm, "name")}
				if sz := jFloat(mm, "size"); sz > 0 {
					mi.Size = fmt.Sprintf("%.1f GB", sz/1e9)
				}
				mlist = append(mlist, mi)
			}
			r.RawData["models"] = mlist
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: "Model inventory accessible",
				Detail:   fmt.Sprintf("%d models loaded", len(mlist)),
				Severity: "high", Data: mlist,
			})
		}
	}

	// Generation endpoint
	if st, _, _, err := httpGET(c, b+"/api/generate"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "Generation endpoint reachable",
			Detail:   fmt.Sprintf("GET /api/generate returned HTTP %d — unauthenticated inference likely possible", st),
			Severity: "critical",
		})
	}

	// Pull endpoint
	if st, _, _, err := httpGET(c, b+"/api/pull"); err == nil && st != 404 {
		r.Findings = append(r.Findings, Finding{
			Category: "access", Title: "Model pull endpoint reachable",
			Detail:   fmt.Sprintf("GET /api/pull returned HTTP %d — arbitrary model download may be possible", st),
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

	// Version
	if st, _, body, err := httpGET(c, b+"/api/v1/version"); err == nil && st == 200 {
		r.Version = strings.Trim(string(body), "\" \n\r")
	}

	// Collections
	if st, _, body, err := httpGET(c, b+"/api/v1/collections"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			type colInfo struct {
				Name  string `json:"name"`
				ID    string `json:"id"`
				Count int    `json:"count,omitempty"`
			}
			var cols []colInfo
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
					cols = append(cols, ci)
				}
			}
			r.RawData["collections"] = cols
			r.Findings = append(r.Findings, Finding{
				Category: "schema", Title: "Collections enumerated",
				Detail:   fmt.Sprintf("%d collections accessible", len(cols)),
				Severity: "high", Data: cols,
			})
		}
	}

	// Tenant
	if st, _, _, err := httpGET(c, b+"/api/v1/tenants/default_tenant"); err == nil && st == 200 {
		r.Findings = append(r.Findings, Finding{
			Category: "info", Title: "Tenant info accessible",
			Severity: "medium",
		})
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
					details = append(details, cd)
				}
				r.RawData["collections"] = details
				r.Findings = append(r.Findings, Finding{
					Category: "schema", Title: "Collections enumerated",
					Detail:   fmt.Sprintf("%d collections", len(details)),
					Severity: "high", Data: details,
				})
			}
		}
	}

	// Cluster
	if st, _, body, err := httpGET(c, b+"/cluster"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			r.RawData["cluster"] = m
			r.Findings = append(r.Findings, Finding{
				Category: "cluster", Title: "Cluster topology exposed",
				Severity: "medium",
			})
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
			r.RawData["flow_count"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "flows", Title: "Flows accessible",
				Detail:   fmt.Sprintf("%d flows readable", len(arr)),
				Severity: "high",
			})
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = fmt.Sprintf("required (HTTP %d)", st)
	}

	if st, _, body, err := httpGET(c, b+"/api/v1/chatflows"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["chatflow_count"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "flows", Title: "Chatflows accessible",
				Detail:   fmt.Sprintf("%d chatflows", len(arr)),
				Severity: "high",
			})
		}
	}

	// Credentials — critical
	if st, _, body, err := httpGET(c, b+"/api/v1/credentials"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.Findings = append(r.Findings, Finding{
				Category: "credentials", Title: "Credentials endpoint accessible",
				Detail:   fmt.Sprintf("%d credential entries readable", len(arr)),
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

	if st, _, body, err := httpGET(c, b+"/api/kernels"); err == nil && st == 200 {
		r.AuthStatus = "none"
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["kernels"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "kernels", Title: "Running kernels accessible",
				Detail:   fmt.Sprintf("%d active kernel(s) — code execution possible", len(arr)),
				Severity: "critical",
			})
		}
	} else if st == 401 || st == 403 {
		r.AuthStatus = "token/password required"
	}

	if st, _, body, err := httpGET(c, b+"/api/sessions"); err == nil && st == 200 {
		if arr, err := parseJSONArray(body); err == nil {
			r.RawData["sessions"] = len(arr)
			r.Findings = append(r.Findings, Finding{
				Category: "sessions", Title: "Sessions readable",
				Detail:   fmt.Sprintf("%d active session(s)", len(arr)),
				Severity: "critical",
			})
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/contents"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			contents := jArray(m, "content")
			r.RawData["files"] = len(contents)
			r.Findings = append(r.Findings, Finding{
				Category: "files", Title: "File listing accessible",
				Detail:   fmt.Sprintf("%d files/dirs in root", len(contents)),
				Severity: "critical",
			})
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
			r.RawData["experiments"] = len(exps)
			r.Findings = append(r.Findings, Finding{
				Category: "experiments", Title: "Experiments accessible",
				Detail:   fmt.Sprintf("%d experiments readable", len(exps)),
				Severity: "high",
			})
		}
	}

	if st, _, body, err := httpGET(c, b+"/api/2.0/mlflow/registered-models/list"); err == nil && st == 200 {
		if m, err := parseJSON(body); err == nil {
			models := jArray(m, "registered_models")
			r.RawData["registered_models"] = len(models)
			r.Findings = append(r.Findings, Finding{
				Category: "models", Title: "Registered models accessible",
				Detail:   fmt.Sprintf("%d registered models", len(models)),
				Severity: "high",
			})
		}
	}

	return r
}

// ── Generic checks (runs for every service) ─────────────────────────

func checkGeneric(c *http.Client, svc ServiceMatch) []Finding {
	var findings []Finding
	b := svc.BaseURL

	// CORS
	if _, hdrs, _, err := httpGET(c, b+"/"); err == nil {
		if cors, ok := hdrs["Access-Control-Allow-Origin"]; ok && cors == "*" {
			findings = append(findings, Finding{
				Category: "cors", Title: "Wildcard CORS policy",
				Detail:   "Access-Control-Allow-Origin: *",
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

	// API key patterns in match body
	if svc.MatchBody != nil {
		bodyStr := string(svc.MatchBody)
		keyPatterns := []struct {
			pat  string
			name string
		}{
			{"sk-proj-", "OpenAI API key"},
			{"sk-ant-", "Anthropic API key"},
			{"AKIA", "AWS access key"},
			{"ghp_", "GitHub PAT"},
			{"glpat-", "GitLab PAT"},
			{"xoxb-", "Slack bot token"},
			{"xoxp-", "Slack user token"},
		}
		for _, kp := range keyPatterns {
			if strings.Contains(bodyStr, kp.pat) {
				findings = append(findings, Finding{
					Category: "secrets", Title: fmt.Sprintf("Possible %s in response", kp.name),
					Detail:   fmt.Sprintf("Pattern '%s' found in probe response", kp.pat),
					Severity: "critical",
				})
			}
		}
	}

	return findings
}

// ── Risk computation ────────────────────────────────────────────────

func computeRisk(r EnumResult) string {
	ranks := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	best := "info"
	for _, f := range r.Findings {
		if ranks[f.Severity] > ranks[best] {
			best = f.Severity
		}
	}
	// Unauthenticated + high severity = critical
	if r.AuthStatus == "none" && best == "high" {
		return "critical"
	}
	return best
}
