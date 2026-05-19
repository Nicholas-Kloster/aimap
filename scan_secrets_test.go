package main

import (
	"strings"
	"testing"
)

// scan_secrets_test.go — calibrated severity ladder for scanSecrets, ported
// from scanCredentials in v1.9.19.
//
// Pre-v1.9.19: every match emitted "critical" with no validation.
// Post: severity follows the evidence — anchor-only → BaseSev (medium/high),
// extracted-and-format-validated → critical, extracted-but-format-mismatch
// → BaseSev (no upgrade).

func TestScanSecrets_OpenAIEnvVar_AnchorOnly_Medium(t *testing.T) {
	r := &EnumResult{}
	// Env-var name present, no `=value` — anchor only.
	body := `Available environment variables include OPENAI_API_KEY for the model client.`
	scanSecrets(body, r)
	var openaiFinding *Finding
	for i := range r.Findings {
		if strings.Contains(r.Findings[i].Title, "OpenAI API key") {
			openaiFinding = &r.Findings[i]
		}
	}
	if openaiFinding == nil {
		t.Fatal("OpenAI env-var anchor-only finding not produced")
	}
	if openaiFinding.Severity != "medium" {
		t.Errorf("expected severity=medium for anchor-only, got %q", openaiFinding.Severity)
	}
	if !strings.Contains(openaiFinding.Detail, "anchor_only") {
		t.Errorf("expected anchor_only in detail, got %q", openaiFinding.Detail)
	}
}

func TestScanSecrets_OpenAIEnvVar_FormatValid_Critical(t *testing.T) {
	r := &EnumResult{}
	body := `OPENAI_API_KEY=sk-proj-` + strings.Repeat("A", 40)
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "OpenAI API key") {
			if f.Severity != "critical" {
				t.Errorf("format-validated key should be critical, got %q", f.Severity)
			}
			if !strings.Contains(f.Detail, "format=valid") {
				t.Errorf("expected format=valid in detail, got %q", f.Detail)
			}
			return
		}
	}
	t.Fatal("OpenAI format-validated finding not produced")
}

func TestScanSecrets_OpenAIEnvVar_FormatMismatch_NoUpgrade(t *testing.T) {
	r := &EnumResult{}
	// Value extracted but not matching the sk-(proj-)? prefix pattern.
	body := `OPENAI_API_KEY=placeholder1234567890`
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "OpenAI API key") {
			if f.Severity == "critical" {
				t.Errorf("format-mismatch value should NOT be critical, got critical")
			}
			if !strings.Contains(f.Detail, "format=mismatch") {
				t.Errorf("expected format=mismatch in detail, got %q", f.Detail)
			}
			return
		}
	}
	t.Fatal("OpenAI format-mismatch finding not produced")
}

func TestScanSecrets_AKIA_PrefixOnly_High(t *testing.T) {
	r := &EnumResult{}
	// AKIA appears but not followed by 16 chars of [A-Z0-9] — anchor only.
	body := `Search results: "AKIA" appears in 3 documents.`
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "AWS access key ID") {
			if f.Severity != "high" {
				t.Errorf("AKIA anchor-only should be high (BaseSev), got %q", f.Severity)
			}
			return
		}
	}
	t.Fatal("AKIA anchor-only finding not produced")
}

func TestScanSecrets_AKIA_FormatValid_Critical(t *testing.T) {
	r := &EnumResult{}
	// AKIA + 16 [A-Z0-9] chars = real shape.
	body := `aws_access_key_id = AKIA` + strings.Repeat("A", 16)
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "AWS access key ID") {
			if f.Severity != "critical" {
				t.Errorf("AKIA format-valid should be critical, got %q", f.Severity)
			}
			if !strings.Contains(f.Detail, "format=valid") {
				t.Errorf("expected format=valid, got %q", f.Detail)
			}
			return
		}
	}
	t.Fatal("AKIA format-valid finding not produced")
}

func TestScanSecrets_GitHubPAT_FormatValid_Critical(t *testing.T) {
	r := &EnumResult{}
	body := `gh_token = "ghp_` + strings.Repeat("a", 36) + `"`
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "GitHub PAT") {
			if f.Severity != "critical" {
				t.Errorf("ghp_ format-valid should be critical, got %q", f.Severity)
			}
			return
		}
	}
	t.Fatal("ghp_ format-valid finding not produced")
}

func TestScanSecrets_HuggingFace_GenericAnchor_Low(t *testing.T) {
	r := &EnumResult{}
	// HUGGING_FACE is the broad anchor — could be a doc page mentioning it.
	// Without further evidence, severity is low.
	body := `HUGGING_FACE models include Llama and Mistral.`
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "HuggingFace credential") {
			if f.Severity != "low" {
				t.Errorf("HUGGING_FACE anchor-only should be low, got %q", f.Severity)
			}
			return
		}
	}
	t.Fatal("HUGGING_FACE anchor-only finding not produced")
}

func TestScanSecrets_PreV19Regression_NoFalseCritical(t *testing.T) {
	// Pre-v1.9.19 behavior: ANY anchor → critical. Post: anchor without value
	// gets BaseSev. A doc page that merely mentions "POSTGRES_PASSWORD" must
	// not produce a critical finding.
	r := &EnumResult{}
	body := `Common env vars are POSTGRES_PASSWORD, MYSQL_PASSWORD, REDIS_PASSWORD.`
	scanSecrets(body, r)
	for _, f := range r.Findings {
		if f.Severity == "critical" {
			t.Errorf("pre-v1.9.19 false-critical regression: anchor-only finding emitted at critical: %+v", f)
		}
	}
}

func TestScanSecrets_NoAnchorInBody_NoFindings(t *testing.T) {
	r := &EnumResult{}
	body := `{"status":"ok","version":"1.2.3"}`
	scanSecrets(body, r)
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings on body with no anchors, got %d: %+v", len(r.Findings), r.Findings)
	}
}
