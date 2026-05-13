package main

import (
	"testing"
)

// TestOpenWebUI_MatchesRealIndex asserts the FP matches the real Open WebUI
// index page shape captured live 2026-05-13 from 43.173.102.75:3000.
//
// The discriminating signals on a real instance: <title>Open WebUI</title>,
// the /static/loader.js script path, and the crossorigin="use-credentials"
// attribute on static asset links. Brand-name "open-webui" alone is not
// enough — see the Helicone marketing-reflection lesson (iter 5).
func TestOpenWebUI_MatchesRealIndex(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.30",
		Port:        3000,
		Open:        true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!doctype html><html lang="en"><head>` +
			`<meta charset="utf-8" />` +
			`<link rel="icon" type="image/png" href="/static/favicon.png" crossorigin="use-credentials" />` +
			`<title>Open WebUI</title>` +
			`<script src="/static/loader.js" defer crossorigin="use-credentials"></script>` +
			`<p>open-webui</p>`,
	}

	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Open WebUI" {
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
		t.Fatal("Open WebUI FP no longer matches a real index page")
	}
}

// TestOpenWebUI_RejectsBareBrandMention guards against a page that just
// mentions "open-webui" in passing — e.g. a tutorial site, a GitHub-page
// mirror, a marketing reflection. Should NOT match.
func TestOpenWebUI_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.31",
		Port:        3000,
		Open:        true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>My Awesome AI Tutorial</title></head>` +
			`<body><p>Check out open-webui at github.com/open-webui/open-webui — ` +
			`it's a great UI for Ollama!</p></body></html>`,
	}

	for _, fp := range Fingerprints {
		if fp.Name != "Open WebUI" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Open WebUI FP over-matched a bare brand mention")
			}
		}
	}
}
