package main

import (
	"testing"
)

// AutoGen Studio fingerprint (Microsoft AutoGen agent IDE).
//
// Source-verified against microsoft/autogen @ python/packages/autogen-studio.
// The FastAPI app mounts its API under /api/ and serves the React SPA at /.
//
//   GET /api/version → {"status":true,"message":"Version retrieved
//                       successfully","data":{"version":"..."}}
//   GET /api/health  → {"status":true,"message":"Service is healthy"}
//
// Both messages are unique-to-AutoGen-Studio strings. The /api/version
// response additionally carries the version in data.version.

func TestAutoGenStudio_MatchesVersionEndpoint(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.100", Port: 8081, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":true,"message":"Version retrieved successfully","data":{"version":"0.4.2"}}`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "AutoGen Studio" {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("AutoGen Studio FP did not match the /api/version response")
	}
}

func TestAutoGenStudio_MatchesHealthEndpoint(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.101", Port: 8081, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":true,"message":"Service is healthy"}`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "AutoGen Studio" {
			continue
		}
		for _, probe := range fp.Probes {
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("AutoGen Studio FP did not match the /api/health response")
	}
}

// Guard: a generic FastAPI app returning {"status":true} or a health
// response with a different message must NOT match.
func TestAutoGenStudio_RejectsGenericFastAPIHealth(t *testing.T) {
	for _, body := range []string{
		`{"status":true,"message":"OK"}`,
		`{"status":"healthy"}`,
		`{"status":true,"message":"pong"}`,
		`{"version":"1.0.0","status":"up"}`,
	} {
		pr := PortResult{
			Host: "203.0.113.102", Port: 8081, Open: true,
			StatusCode: 200, ContentType: "application/json",
			Headers:     map[string]string{"Content-Type": "application/json"},
			BodySnippet: body,
		}
		for _, fp := range Fingerprints {
			if fp.Name != "AutoGen Studio" {
				continue
			}
			for _, probe := range fp.Probes {
				if matchProbe(probe, pr) {
					t.Fatalf("AutoGen Studio FP over-matched a generic health body: %s", body)
				}
			}
		}
	}
}

// The FP must exist in the catalog at all.
func TestAutoGenStudio_FingerprintRegistered(t *testing.T) {
	if fpByName("AutoGen Studio") == nil {
		t.Fatal("AutoGen Studio fingerprint not registered in the catalog")
	}
}
