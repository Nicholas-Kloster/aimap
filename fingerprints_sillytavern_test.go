package main

import (
	"testing"
)

// Iter 8b. Old SillyTavern FP relied on a WWW-Authenticate: SillyTavern
// HTTP header. Modern SillyTavern (1.12+) redirects unauth /  to /login
// and serves an HTML page with <title>SillyTavern</title> and a
// /css/st-tailwind.css link. The header signal is gone.
//
// Test pair: the new probe matches the modern HTML response; the old
// probe (if it lingered) would not match this same response.

func TestSillyTavern_MatchesModernLoginPage(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.40", Port: 8000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><base href="/">` +
			`<title>SillyTavern</title>` +
			`<link rel="stylesheet" href="/css/st-tailwind.css"/>` +
			`<link rel="stylesheet" href="/css/login.css"/>` +
			`<meta name="darkreader-lock"/>`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "SillyTavern" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("SillyTavern FP did not match the modern login-page shape")
	}
}

// Guard against over-matching a random page that contains "SillyTavern"
// as a string but doesn't have the project-specific asset path.
func TestSillyTavern_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.41", Port: 8000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>My LLM Tools</title></head>` +
			`<body><h1>Setting up SillyTavern</h1>` +
			`<p>A tutorial on getting started with the SillyTavern chat UI.</p>` +
			`</body></html>`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "SillyTavern" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("SillyTavern FP over-matched a tutorial page mentioning the brand")
			}
		}
	}
}
