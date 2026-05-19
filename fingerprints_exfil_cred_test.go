package main

import (
	"strings"
	"testing"
)

// Insight #38: Exposed API Credentials fingerprint + scanCredentials tests.
// Empirical basis: 2026-05-19 Langfuse sk-lf- exposure on 43.156.249.64
// (Jasmine HR-GPT). Specifics redacted; test fixtures use synthetic keys.

// ── Fingerprint detection tests ─────────────────────────────────────

func TestExposedAPICredentials_Langfuse_sk_lf(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.10", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<html><body>sk-lf-12345678-1234-1234-1234-123456789abc found in env</body></html>`,
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/", pr)
}

func TestExposedAPICredentials_Helicone(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.11", Port: 8080, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `window.HELICONE_KEY = "sk-helicone-abcdefghijklmnopqrstuvwx";`,
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/", pr)
}

func TestExposedAPICredentials_Stripe_live(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.12", Port: 443, Open: true,
		StatusCode: 200, ContentType: "text/javascript",
		Headers:     map[string]string{"Content-Type": "text/javascript"},
		BodySnippet: `const stripeKey = "sk_live_` + strings.Repeat("A", 24) + `";`,
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/", pr)
}

func TestExposedAPICredentials_Anthropic(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.13", Port: 8000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `ANTHROPIC_API_KEY=sk-ant-api03-` + strings.Repeat("A", 55),
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/", pr)
}

func TestExposedAPICredentials_LangSmith(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.14", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `LANGCHAIN_API_KEY=lsv2_pt_` + strings.Repeat("a", 36),
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/", pr)
}

func TestExposedAPICredentials_LangfuseEnvPath(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.15", Port: 8080, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"LANGFUSE_SECRET_KEY":"sk-lf-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","PORT":"3000"}`,
	}
	assertFingerprintMatchesPath(t, "Exposed API Credentials", "/env", pr)
}

func TestExposedAPICredentials_NoMatchOnShortPrefix(t *testing.T) {
	// "sk-" alone should NOT match (too broad — not in the fingerprint probes)
	pr := PortResult{
		Host: "203.0.113.16", Port: 8080, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `some sk- mention without a real key format`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Exposed API Credentials" {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if matched {
		t.Fatal("Exposed API Credentials FP matched on bare sk- which is too broad")
	}
}

// ── scanCredentials unit tests ──────────────────────────────────────

func TestScanCredentials_Langfuse_FormatValid(t *testing.T) {
	r := &EnumResult{}
	// Body contains a UUID-format sk-lf- key; the sk-lf- class should detect it
	// and mark format=valid. The LANGFUSE_SECRET_KEY env-var class may also fire
	// but without a Format regex — at least one langfuse finding must be format=valid.
	body := `sk-lf-12345678-1234-1234-1234-123456789abc`
	scanCredentials(body, r)
	if len(r.Findings) == 0 {
		t.Fatal("expected credential finding, got none")
	}
	foundFormatValid := false
	for _, f := range r.Findings {
		if f.Category == "exfil_credential" && strings.Contains(f.Detail, "vendor=langfuse") {
			if strings.Contains(f.Detail, "format=valid") && f.Severity == "critical" {
				foundFormatValid = true
			}
		}
	}
	if !foundFormatValid {
		t.Fatalf("no langfuse format=valid critical finding; findings: %+v", r.Findings)
	}
}

func TestScanCredentials_Langfuse_FormatMismatch_Downgraded(t *testing.T) {
	r := &EnumResult{}
	// Valid prefix but not UUID format — should downgrade to high
	body := `sk-lf-notauuid12345678901234567890`
	scanCredentials(body, r)
	for _, f := range r.Findings {
		if f.Category == "exfil_credential" && strings.Contains(f.Detail, "vendor=langfuse") {
			if !strings.Contains(f.Detail, "format=mismatch") {
				t.Errorf("expected format=mismatch, got: %s", f.Detail)
			}
			if f.Severity != "high" {
				t.Errorf("expected severity downgraded to high, got: %s", f.Severity)
			}
			return
		}
	}
	t.Fatal("langfuse format-mismatch finding not found")
}

func TestScanCredentials_Stripe_Live_Critical(t *testing.T) {
	r := &EnumResult{}
	body := `{"stripe_key":"sk_live_` + strings.Repeat("A", 26) + `"}`
	scanCredentials(body, r)
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, "vendor=stripe") && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("Stripe live key not detected at critical severity")
	}
}

func TestScanCredentials_Redaction(t *testing.T) {
	r := &EnumResult{}
	body := `sk-helicone-abcdefghij1234567890xyzuvw`
	scanCredentials(body, r)
	for _, f := range r.Findings {
		if f.Category == "exfil_credential" {
			if strings.Contains(f.Detail, "abcdefghij1234567890xyzuvw") {
				t.Error("full key is not redacted in finding detail")
			}
			if !strings.Contains(f.Detail, "...") {
				t.Error("expected redacted key with ... suffix")
			}
			return
		}
	}
	t.Fatal("helicone finding not produced")
}

func TestScanCredentials_NoDuplicates(t *testing.T) {
	r := &EnumResult{}
	key := `sk-lf-12345678-1234-1234-1234-123456789abc`
	body := key + "\n" + key + "\n" + key
	scanCredentials(body, r)
	count := 0
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, "vendor=langfuse") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", count)
	}
}

func TestScanCredentials_NoMatch_NoPrefixInBody(t *testing.T) {
	r := &EnumResult{}
	body := `{"status":"ok","version":"1.2.3"}`
	scanCredentials(body, r)
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings on body with no credential prefixes, got %d", len(r.Findings))
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func assertFingerprintMatchesPath(t *testing.T, fpName, path string, pr PortResult) {
	t.Helper()
	for _, fp := range Fingerprints {
		if fp.Name != fpName {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != path {
				continue
			}
			if matchProbe(probe, pr) {
				return
			}
		}
	}
	t.Fatalf("fingerprint %q did not match on path %q", fpName, path)
}
