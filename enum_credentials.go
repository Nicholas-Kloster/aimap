package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// enum_credentials.go — credential/secret scanning code, extracted from
// enumerators.go in v1.9.19. Two scanners live here:
//
//   - scanCredentials runs credentialClasses (regex-extracted, format-validated
//     vendor-key catalogue). Source: Insight #38 (2026-05-19).
//   - scanSecrets runs secretPatterns (env-var-name anchors + format-validated
//     credential prefixes). The calibrated severity ladder was added in v1.9.19;
//     previously every match emitted "critical" regardless of evidence.
//
// Both scanners are package-internal helpers called from the deep enumerators
// in enumerators.go. The cross-cutting enumExposedCredentials enumerator that
// chains them lives at the bottom of this file.

// secretPattern is the calibrated scanner used by scanSecrets. Each entry has
// an anchor substring, an optional Value regex to extract the actual secret
// value if it follows the anchor (e.g., `OPENAI_API_KEY=sk-...`), an optional
// Format regex to validate the extracted value against the vendor's documented
// shape, and a BaseSev that applies when only the anchor is present.
//
// Severity ladder (Insight #38 discipline applied 2026-05-19, generalized to
// scanSecrets in v1.9.19):
//   - anchor only (env-var name visible, value not extracted) → BaseSev
//   - anchor + value extracted, Format mismatch                → BaseSev (no downgrade since the value is still suspicious)
//   - anchor + value extracted, Format match                   → "critical"
//   - patterns with no Format defined (sk-proj-, AKIA, ghp_, etc.) → BaseSev
//     when only the prefix is present; "critical" when a sufficient run of
//     post-prefix characters confirms it's a real key shape, not a docs mention.
//
// Memory rule: feedback_100_percent_verified_tier_labels.md — every tier
// label requires 100% verified evidence at that tier; class membership is
// not data membership.
type secretPattern struct {
	Pattern string
	Name    string
	Value   *regexp.Regexp // optional: extracts the value following the anchor
	Format  *regexp.Regexp // optional: validates extracted value shape
	BaseSev string         // severity when anchor matches but value/format absent
}

var secretPatterns = []secretPattern{
	// ── Env-var name disclosure patterns ────────────────────────────
	// Anchor is the env-var name; value extraction looks for `=` or `:` separators
	// followed by ≥10 chars of non-whitespace. Without an extracted value, severity
	// is "medium" — disclosure of the name pattern indicates a misconfigured
	// debug/env endpoint but does not prove the secret value leaked.
	{
		Pattern: "OPENAI_API_KEY",
		Name:    "OpenAI API key env-var",
		Value:   regexp.MustCompile(`OPENAI_API_KEY[=: '"]+([^\s'"<>&]{10,})`),
		Format:  regexp.MustCompile(`^sk-(proj-)?[a-zA-Z0-9_-]{20,}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "ANTHROPIC_API_KEY",
		Name:    "Anthropic API key env-var",
		Value:   regexp.MustCompile(`ANTHROPIC_API_KEY[=: '"]+([^\s'"<>&]{10,})`),
		Format:  regexp.MustCompile(`^sk-ant-(api\d+-)?[a-zA-Z0-9_-]{40,}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "AWS_ACCESS_KEY_ID",
		Name:    "AWS access key env-var",
		Value:   regexp.MustCompile(`AWS_ACCESS_KEY_ID[=: '"]+([^\s'"<>&]{10,})`),
		Format:  regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "AWS_SECRET_ACCESS_KEY",
		Name:    "AWS secret access key env-var",
		Value:   regexp.MustCompile(`AWS_SECRET_ACCESS_KEY[=: '"]+([^\s'"<>&]{20,})`),
		Format:  regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "GOOGLE_API_KEY",
		Name:    "Google API key env-var",
		Value:   regexp.MustCompile(`GOOGLE_API_KEY[=: '"]+([^\s'"<>&]{10,})`),
		Format:  regexp.MustCompile(`^AIza[a-zA-Z0-9_-]{35}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "AZURE_OPENAI_KEY",
		Name:    "Azure OpenAI key env-var",
		Value:   regexp.MustCompile(`AZURE_OPENAI_KEY[=: '"]+([^\s'"<>&]{20,})`),
		BaseSev: "medium",
	},
	{
		Pattern: "HF_TOKEN",
		Name:    "HuggingFace token env-var",
		Value:   regexp.MustCompile(`HF_TOKEN[=: '"]+([^\s'"<>&]{10,})`),
		Format:  regexp.MustCompile(`^hf_[a-zA-Z0-9]{30,}$`),
		BaseSev: "medium",
	},
	{
		Pattern: "HUGGING_FACE",
		Name:    "HuggingFace credential env-var",
		BaseSev: "low", // very generic anchor; could be a doc page
	},
	{
		Pattern: "DATABASE_URL",
		Name:    "Database connection string env-var",
		Value:   regexp.MustCompile(`DATABASE_URL[=: '"]+([^\s'"<>&]{15,})`),
		Format:  regexp.MustCompile(`^[a-z]+://[^@]+@[^/]+/`), // proto://user:pass@host/db
		BaseSev: "medium",
	},
	{
		Pattern: "POSTGRES_PASSWORD",
		Name:    "PostgreSQL password env-var",
		Value:   regexp.MustCompile(`POSTGRES_PASSWORD[=: '"]+([^\s'"<>&]{1,})`),
		BaseSev: "medium",
	},
	{
		Pattern: "MYSQL_PASSWORD",
		Name:    "MySQL password env-var",
		Value:   regexp.MustCompile(`MYSQL_PASSWORD[=: '"]+([^\s'"<>&]{1,})`),
		BaseSev: "medium",
	},
	{
		Pattern: "REDIS_PASSWORD",
		Name:    "Redis password env-var",
		Value:   regexp.MustCompile(`REDIS_PASSWORD[=: '"]+([^\s'"<>&]{1,})`),
		BaseSev: "medium",
	},
	// ── Format-anchored credential prefixes ─────────────────────────
	// These patterns are the credential value's own shape; finding the prefix
	// followed by enough characters of the right charset is the leak. Severity
	// is "high" on prefix-only (could still be a doc-page mention) and "critical"
	// when the trailing characters confirm real-key length.
	{
		Pattern: "sk-proj-",
		Name:    "OpenAI project key",
		Value:   regexp.MustCompile(`sk-proj-[a-zA-Z0-9_-]{20,}`),
		Format:  regexp.MustCompile(`^sk-proj-[a-zA-Z0-9_-]{30,}$`),
		BaseSev: "high",
	},
	{
		Pattern: "sk-ant-",
		Name:    "Anthropic key (legacy/current)",
		Value:   regexp.MustCompile(`sk-ant-(api\d+-)?[a-zA-Z0-9_-]{40,}`),
		Format:  regexp.MustCompile(`^sk-ant-(api\d+-)?[a-zA-Z0-9_-]{50,}$`),
		BaseSev: "high",
	},
	{
		Pattern: "AKIA",
		Name:    "AWS access key ID",
		Value:   regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		Format:  regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`),
		BaseSev: "high",
	},
	{
		Pattern: "ghp_",
		Name:    "GitHub PAT",
		Value:   regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`),
		Format:  regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`),
		BaseSev: "high",
	},
	{
		Pattern: "glpat-",
		Name:    "GitLab PAT",
		Value:   regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20,}`),
		Format:  regexp.MustCompile(`^glpat-[a-zA-Z0-9_-]{20,}$`),
		BaseSev: "high",
	},
	{
		Pattern: "xoxb-",
		Name:    "Slack bot token",
		Value:   regexp.MustCompile(`xoxb-[0-9A-Za-z-]{50,}`),
		Format:  regexp.MustCompile(`^xoxb-[0-9A-Za-z-]{50,}$`),
		BaseSev: "high",
	},
}

// credentialClass is the regex-upgraded credential scanner used by scanCredentials.
// Each entry has a fast prefix pre-filter, a regex to extract the key, an optional
// format-validation regex (UUID check for Langfuse, etc.), and a base severity.
// Source: Insight #38 (exfil-credential hard-proof chain, 2026-05-19).
type credentialClass struct {
	Prefix   string
	Name     string
	Vendor   string
	Extract  *regexp.Regexp
	Format   *regexp.Regexp // nil = no format check beyond Extract
	Severity string
}

var credentialClasses = []credentialClass{
	{
		Prefix: "sk-lf-", Name: "Langfuse secret key", Vendor: "langfuse",
		Extract:  regexp.MustCompile(`sk-lf-[a-zA-Z0-9_-]{20,}`),
		Format:   regexp.MustCompile(`^sk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`),
		Severity: "critical",
	},
	{
		Prefix: "pk-lf-", Name: "Langfuse public key", Vendor: "langfuse",
		Extract:  regexp.MustCompile(`pk-lf-[a-zA-Z0-9_-]{20,}`),
		Format:   regexp.MustCompile(`^pk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`),
		Severity: "high",
	},
	{
		Prefix: "LANGFUSE_SECRET_KEY", Name: "Langfuse secret key (env-var)", Vendor: "langfuse",
		Extract:  regexp.MustCompile(`LANGFUSE_SECRET_KEY[= '"]+([^\s'"<>&]{8,})`),
		Severity: "critical",
	},
	{
		Prefix: "sk-helicone-", Name: "Helicone API key", Vendor: "helicone",
		Extract:  regexp.MustCompile(`sk-helicone-[a-zA-Z0-9_-]{20,}`),
		Severity: "critical",
	},
	{
		Prefix: "sk_live_", Name: "Stripe live secret key", Vendor: "stripe",
		Extract:  regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
		Severity: "critical",
	},
	{
		Prefix: "sk_test_", Name: "Stripe test secret key", Vendor: "stripe",
		Extract:  regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),
		Severity: "high",
	},
	{
		Prefix: "pk_live_", Name: "Stripe live publishable key", Vendor: "stripe",
		Extract:  regexp.MustCompile(`pk_live_[a-zA-Z0-9]{24,}`),
		Severity: "medium",
	},
	{
		Prefix: "sk-ant-api03-", Name: "Anthropic API key", Vendor: "anthropic",
		Extract:  regexp.MustCompile(`sk-ant-api03-[a-zA-Z0-9_-]{50,}`),
		Severity: "critical",
	},
	{
		Prefix: "lsv2_pt_", Name: "LangSmith personal token", Vendor: "langsmith",
		Extract:  regexp.MustCompile(`lsv2_pt_[a-zA-Z0-9]{32,}`),
		Severity: "critical",
	},
	{
		Prefix: "lsv2_sk_", Name: "LangSmith service key", Vendor: "langsmith",
		Extract:  regexp.MustCompile(`lsv2_sk_[a-zA-Z0-9]{32,}`),
		Severity: "critical",
	},
	{
		Prefix: "sk-or-v1-", Name: "OpenRouter API key", Vendor: "openrouter",
		Extract:  regexp.MustCompile(`sk-or-v1-[a-zA-Z0-9_-]{40,}`),
		Severity: "critical",
	},
	{
		Prefix: "xoxp-", Name: "Slack user token", Vendor: "slack",
		Extract:  regexp.MustCompile(`xoxp-[0-9A-Za-z-]{50,}`),
		Severity: "critical",
	},
	{
		Prefix: "xoxe-", Name: "Slack refresh token", Vendor: "slack",
		Extract:  regexp.MustCompile(`xoxe-[0-9A-Za-z-]{50,}`),
		Severity: "critical",
	},
	{
		Prefix: "xapp-", Name: "Slack app token", Vendor: "slack",
		Extract:  regexp.MustCompile(`xapp-[0-9A-Za-z-]{50,}`),
		Severity: "critical",
	},
}

// redactKey returns the first 16 chars of a key + "..." — enough for identification,
// not enough to reconstruct the secret.
func redactKey(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:16] + "..."
}

// scanCredentials runs the Insight-#38 credentialClasses against content.
// Unlike scanSecrets (substring-only), this extracts the key via regex, validates
// format where a Format pattern is defined, and emits a redacted key fragment.
// Severity is downgraded one step when format validation fails (likely substring FP).
func scanCredentials(content string, r *EnumResult) {
	for _, cc := range credentialClasses {
		if !strings.Contains(content, cc.Prefix) {
			continue
		}
		keys := cc.Extract.FindAllString(content, 5)
		seen := map[string]bool{}
		for _, k := range keys {
			rk := redactKey(k)
			if seen[rk] {
				continue
			}
			seen[rk] = true
			sev := cc.Severity
			detail := fmt.Sprintf("vendor=%s key=%s", cc.Vendor, rk)
			if cc.Format != nil {
				if cc.Format.MatchString(k) {
					detail += " format=valid"
				} else {
					detail += " format=mismatch"
					switch sev {
					case "critical":
						sev = "high"
					case "high":
						sev = "medium"
					}
				}
			}
			r.Findings = append(r.Findings, Finding{
				Category: "exfil_credential",
				Title:    cc.Name + " exposed in HTTP response",
				Detail:   detail,
				Severity: sev,
			})
		}
	}
}

// scanSecrets runs the calibrated secretPatterns against content. Severity is
// derived from the evidence ladder, not hardcoded — anchor-only matches emit
// at BaseSev; matches with extracted-and-format-validated values emit
// "critical". An extracted-but-format-mismatch value stays at BaseSev because
// the value is still suspicious but does not satisfy the vendor's documented
// shape (could be a placeholder, redacted output, or unrelated string).
//
// v1.9.18 and earlier: every match emitted "critical" with no validation.
// v1.9.19 ports the Insight #38 validation discipline from scanCredentials.
func scanSecrets(content string, r *EnumResult) {
	for _, sp := range secretPatterns {
		if !strings.Contains(content, sp.Pattern) {
			continue
		}
		sev := sp.BaseSev
		if sev == "" {
			sev = "medium"
		}

		// Try to extract the value following the anchor.
		var extracted string
		if sp.Value != nil {
			if m := sp.Value.FindStringSubmatch(content); m != nil {
				if len(m) > 1 {
					extracted = m[1]
				} else {
					extracted = m[0]
				}
			}
		}

		detail := ""
		if extracted != "" {
			// Format-validate where the vendor's shape is documented.
			if sp.Format != nil && sp.Format.MatchString(extracted) {
				sev = "critical"
				detail = "format=valid value=" + redactKey(extracted)
			} else if sp.Format != nil {
				detail = "format=mismatch value=" + redactKey(extracted)
			} else {
				detail = "value=" + redactKey(extracted)
			}
		} else {
			// Anchor only — pull a short snippet around the anchor for context.
			idx := strings.Index(content, sp.Pattern)
			snippet := content[idx:]
			if nl := strings.IndexByte(snippet, '\n'); nl > 0 {
				snippet = snippet[:nl]
			}
			if len(snippet) > 50 {
				snippet = snippet[:47] + "..."
			}
			detail = "anchor_only snippet=" + snippet
		}

		r.Findings = append(r.Findings, Finding{
			Category: "credentials",
			Title:    sp.Name + " exposed in HTTP response",
			Detail:   detail,
			Severity: sev,
		})
	}
}

// ── Exposed API Credentials (Insight #38) ──────────────────────────

// enumExposedCredentials runs scanCredentials against the matched path body
// plus a set of paths commonly used to expose environment variables. Fires
// when the "Exposed API Credentials" fingerprint matches (body_contains on a
// high-signal vendor key prefix). Emits exfil_credential findings with redacted
// key fragments; format validation runs where a Format regex is defined.
func enumExposedCredentials(c *http.Client, svc ServiceMatch) EnumResult {
	r := mkResult(svc)
	r.AuthStatus = "none"

	probePaths := []string{
		svc.MatchPath,
		"/",
		"/env",
		"/debug/vars",
		"/api/settings",
		"/.env",
		"/config",
		"/health",
	}
	seen := map[string]bool{}
	for _, path := range probePaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if path == "" {
			continue
		}
		sc, _, body, err := httpGET(c, svc.BaseURL+path)
		if err != nil || sc == 0 {
			continue
		}
		if sc >= 200 && sc < 500 {
			scanCredentials(string(body), &r)
			scanSecrets(string(body), &r)
		}
	}

	if len(r.Findings) == 0 {
		r.Details = append(r.Details, "credential prefix in Shodan index but not found on re-fetch (may be stale cache)")
	} else {
		r.Details = append(r.Details, fmt.Sprintf("%d credential finding(s) extracted and redacted", len(r.Findings)))
	}
	r.RiskLevel = computeRisk(r)
	return r
}
