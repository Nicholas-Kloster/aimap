package main

import (
	"testing"
)

// Code-assistant fingerprints (category 09).
//
// Every response body below is a source-of-truth snapshot pulled from a
// live confirmed host during the 2026-05-14 code-assistant survey — not
// a guess. See AI-LLM-Infrastructure-OSINT/shodan/queries/09-code-assistants.md.
//
// Discipline (per aimap CLAUDE.md): no naked single-word body_contains.
// Every keyword is anchored to status_code + json_field / json_array, or
// to a full unique string (e.g. "Refact Server Login", not "Refact").

// helper: does any probe of the named fingerprint match this PortResult?
func caMatches(name string, pr PortResult) bool {
	for _, fp := range Fingerprints {
		if fp.Name != name {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				return true
			}
		}
	}
	return false
}

// ── OpenHands ───────────────────────────────────────────────────────
// GET /api/options/config → {"APP_MODE":"oss","GITHUB_CLIENT_ID":"",
//                            "POSTHOG_CLIENT_KEY":"phc_3ESMmY9..."}
// GET /api/options/models → ["1024-x-1024/dall-e-2", ...]  (JSON array)

func TestOpenHands_MatchesOptionsConfig(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.10", Port: 3000, Open: true, StatusCode: 200,
		ContentType: "application/json",
		BodySnippet: `{"APP_MODE":"oss","GITHUB_CLIENT_ID":"","POSTHOG_CLIENT_KEY":"phc_3ESMmY9SgqEAGBB6sMGK5ayYHkeUuknH2vP6FmWH9RA"}`,
	}
	if !caMatches("OpenHands", pr) {
		t.Fatal("OpenHands FP did not match the /api/options/config response")
	}
}

func TestOpenHands_MatchesOptionsModels(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.11", Port: 3000, Open: true, StatusCode: 200,
		ContentType: "application/json",
		BodySnippet: `["1024-x-1024/dall-e-2","1024-x-1024/gpt-image-1.5","claude-opus-4"]`,
	}
	if !caMatches("OpenHands", pr) {
		t.Fatal("OpenHands FP did not match the /api/options/models JSON array")
	}
}

// ── Sourcegraph ─────────────────────────────────────────────────────
// POST/GET /.api/graphql → "Private mode requires authentication."
// GET /sign-in           → HTML titled "Sign in - Sourcegraph"

func TestSourcegraph_MatchesGraphQLPrivateMode(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.20", Port: 443, Open: true, TLS: true, StatusCode: 401,
		BodySnippet: `Private mode requires authentication.`,
	}
	if !caMatches("Sourcegraph", pr) {
		t.Fatal("Sourcegraph FP did not match the /.api/graphql private-mode string")
	}
}

func TestSourcegraph_MatchesSignInTitle(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.21", Port: 80, Open: true, StatusCode: 200,
		ContentType: "text/html",
		BodySnippet: `<!DOCTYPE html><html><head><title>Sign in - Sourcegraph</title></head><body></body></html>`,
	}
	if !caMatches("Sourcegraph", pr) {
		t.Fatal("Sourcegraph FP did not match the sign-in page title")
	}
}

// ── Sourcebot ───────────────────────────────────────────────────────
// GET /api/repos → {"statusCode":401,"errorCode":"NOT_AUTHENTICATED",
//                   "message":"Not authenticated"}

func TestSourcebot_MatchesReposAuthEnvelope(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.30", Port: 8080, Open: true, StatusCode: 401,
		ContentType: "application/json",
		BodySnippet: `{"statusCode":401,"errorCode":"NOT_AUTHENTICATED","message":"Not authenticated"}`,
	}
	if !caMatches("Sourcebot", pr) {
		t.Fatal("Sourcebot FP did not match the /api/repos auth envelope")
	}
}

// ── Sweep AI ────────────────────────────────────────────────────────
// GET /health → {"status":"UP","autocomplete":"N/A"}

func TestSweepAI_MatchesHealth(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.40", Port: 80, Open: true, StatusCode: 200,
		ContentType: "application/json",
		BodySnippet: `{"status":"UP","autocomplete":"N/A"}`,
	}
	if !caMatches("Sweep AI", pr) {
		t.Fatal("Sweep AI FP did not match the /health response")
	}
}

// ── Tabnine Context Engine ──────────────────────────────────────────
// GET /api/version → {"error":"Unauthorized","message":"API key required.
//                     Use Authorization: Bearer <key> or X-API-Key header."}

func TestTabnine_MatchesAuthRequired(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.50", Port: 443, Open: true, TLS: true, StatusCode: 401,
		ContentType: "application/json",
		BodySnippet: `{"error":"Unauthorized","message":"API key required. Use Authorization: Bearer <key> or X-API-Key header."}`,
	}
	if !caMatches("Tabnine Context Engine", pr) {
		t.Fatal("Tabnine FP did not match the /api/version auth-required message")
	}
}

// ── Dyad ────────────────────────────────────────────────────────────
// GET / → <title>dyad-generated-app</title>

func TestDyad_MatchesGeneratedAppTitle(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.60", Port: 80, Open: true, StatusCode: 200,
		ContentType: "text/html",
		BodySnippet: `<!DOCTYPE html><html><head><title>dyad-generated-app</title></head><body><div id="root"></div></body></html>`,
	}
	if !caMatches("Dyad", pr) {
		t.Fatal("Dyad FP did not match the dyad-generated-app title")
	}
}

// ── bolt.diy ────────────────────────────────────────────────────────
// GET / → Remix app whose body carries the "bolt.diy" string

func TestBoltDiy_MatchesBodyString(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.70", Port: 3001, Open: true, StatusCode: 200,
		ContentType: "text/html",
		BodySnippet: `<!DOCTYPE html><html><head><title>Create Next App</title></head><body><script>window.__bolt="bolt.diy"</script></body></html>`,
	}
	if !caMatches("bolt.diy", pr) {
		t.Fatal("bolt.diy FP did not match the bolt.diy body string")
	}
}

// ── Refact ──────────────────────────────────────────────────────────
// GET / → login page titled "Refact Server Login"

func TestRefact_MatchesServerLogin(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.80", Port: 443, Open: true, TLS: true, StatusCode: 200,
		ContentType: "text/html",
		BodySnippet: `<!DOCTYPE html><html><head><title>Refact Server Login</title></head><body></body></html>`,
	}
	if !caMatches("Refact", pr) {
		t.Fatal("Refact FP did not match the 'Refact Server Login' title")
	}
}

// ── Guard: false-positive rejections ────────────────────────────────
// The signatures that proved to be FP traps in the survey must NOT match.

func TestCodeAssistants_RejectKnownFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		pr   PortResult
		why  string
	}{
		{
			// "Refact" alone matched "refactor" in JS bundles on
			// port-8081 hosts ("Klickie", "Portfolio" sites).
			name: "Refact",
			pr: PortResult{
				Host: "203.0.113.90", Port: 8081, Open: true, StatusCode: 200,
				ContentType: "text/html",
				BodySnippet: `<html><head><title>Klickie | Run your business on WhatsApp</title></head><body>function refactor(){}</body></html>`,
			},
			why: "matched 'refactor' substring instead of 'Refact Server Login'",
		},
		{
			// Tabby Terminal — "a terminal for a more modern age" —
			// is NOT TabbyML; ensure no code-assistant FP claims it.
			name: "Refact",
			pr: PortResult{
				Host: "203.0.113.91", Port: 8080, Open: true, StatusCode: 200,
				ContentType: "text/html",
				BodySnippet: `<html><head><title>Tabby - a terminal for a more modern age</title></head><body></body></html>`,
			},
			why: "Tabby Terminal must not match a code-assistant FP",
		},
		{
			// A generic FastAPI app returning {"error":"Unauthorized"}
			// without the Tabnine-specific X-API-Key message.
			name: "Tabnine Context Engine",
			pr: PortResult{
				Host: "203.0.113.92", Port: 443, Open: true, StatusCode: 401,
				ContentType: "application/json",
				BodySnippet: `{"error":"Unauthorized","message":"Authentication required"}`,
			},
			why: "generic 401 without the X-API-Key header string must not match Tabnine",
		},
		{
			// A generic health endpoint without the Sweep-specific
			// "autocomplete" field.
			name: "Sweep AI",
			pr: PortResult{
				Host: "203.0.113.93", Port: 80, Open: true, StatusCode: 200,
				ContentType: "application/json",
				BodySnippet: `{"status":"UP"}`,
			},
			why: "generic health body without 'autocomplete' must not match Sweep AI",
		},
		{
			// A bare 401 JSON envelope without errorCode must not
			// match Sourcebot.
			name: "Sourcebot",
			pr: PortResult{
				Host: "203.0.113.94", Port: 8080, Open: true, StatusCode: 401,
				ContentType: "application/json",
				BodySnippet: `{"statusCode":401,"message":"Unauthorized"}`,
			},
			why: "401 envelope without errorCode/NOT_AUTHENTICATED must not match Sourcebot",
		},
	}
	for _, c := range cases {
		if caMatches(c.name, c.pr) {
			t.Errorf("%s FP over-matched: %s", c.name, c.why)
		}
	}
}

// ── Guard: all code-assistant fingerprints are registered ───────────

func TestCodeAssistants_FingerprintsRegistered(t *testing.T) {
	for _, name := range []string{
		"OpenHands", "Sourcegraph", "Sourcebot", "Sweep AI",
		"Tabnine Context Engine", "Dyad", "bolt.diy", "Refact",
	} {
		if fpByName(name) == nil {
			t.Errorf("code-assistant fingerprint %q not registered in the catalog", name)
		}
	}
}
