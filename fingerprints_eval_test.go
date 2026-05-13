package main

import (
	"testing"
)

// Iter 12: Promptfoo's HTML SPA shape.
// Verified live 2026-05-13 against 38.105.232.166:3000. The /api/health
// endpoint returned the HTML SPA (no API mounted), but / served the
// canonical Promptfoo HTML with <title>promptfoo</title> and a
// /promptfoo/favicon.png asset path. The existing FP only probes
// API endpoints; we need a probe for the HTML SPA too.
func TestPromptfoo_MatchesHTMLSPA(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.60", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!doctype html><html lang="en"><head>` +
			`<link rel="icon" type="image/png" href="/promptfoo/favicon.png" />` +
			`<title>promptfoo</title>` +
			`<meta name="description" content="LLM testing and evaluation" />`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Promptfoo" {
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
		t.Fatal("Promptfoo FP did not match the SPA HTML shape")
	}
}

func TestPromptfoo_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.61", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>LLM Eval Roundup</title></head>` +
			`<body><p>We benchmarked promptfoo against DeepEval and...</p>`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Promptfoo" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Promptfoo FP over-matched a bare brand mention")
			}
		}
	}
}

// Iter 12: Ray Serve root-JSON shape.
// Verified live 2026-05-13 against 16.52.175.212:80. Custom Ray Serve
// deployments often expose a root endpoint returning a small JSON like
// {"message": "Adaptive Inference Lambda with Ray Serve"} rather than
// the upstream /api/serve/deployments/ endpoint. Need a probe for the
// "Ray Serve" string in the root JSON.
func TestRayServe_MatchesRootJSON(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.70", Port: 80, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		// Live shape from 16.52.175.212:80 — body is an array, not an
		// object (some API-gateway response wrapping). The body still
		// contains both "Ray Serve" and "message" as substrings.
		BodySnippet: `["{\"message\": \"Adaptive Inference Lambda with Ray Serve\"}",200,{}]`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Ray Serve" {
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
		t.Fatal("Ray Serve FP did not match the root-JSON deployment shape")
	}
}

// Guard: a random JSON API mentioning "ray" or "serve" shouldn't trigger.
func TestRayServe_RejectsBareJSONMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.71", Port: 80, Open: true,
		StatusCode: 200, ContentType: "application/json",
		Headers: map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"ray_tracing": true, "serve_static": false, "version": "1.0"}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Ray Serve" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Ray Serve FP over-matched a bare ray+serve mention in JSON")
			}
		}
	}
}
