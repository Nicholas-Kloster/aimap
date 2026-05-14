package main

import (
	"testing"
)

// Iter 22: Flowise FP over-match against honeypot bait + deprecated endpoint.
//
// The 1,203-host MLflow delta sweep classified 13 hosts as Flowise. A
// 2026-05-14 deep-dive found ALL 13 were honeypot sensors (Shodan-tagged
// "honeypot", 2,000+ open ports each, /api/* paths returning randomized
// fake-device HTML). The single-word body_contains "flowise" on / matched
// the honeypots' Flowise-SPA bait pages.
//
// Also: probe 1 hit /api/v1/flows, which is the DEPRECATED endpoint. Modern
// Flowise uses /api/v1/chatflows.
//
// Real Flowise (verified live 2026-05-14 against 43.208.237.116 before it
// turned out to be a honeypot, and from upstream FlowiseAI/Flowise) ships
// <title>Flowise - Build AI Agents, Visually</title>.

func TestFlowise_MatchesRealIndex(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.110", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!doctype html><html lang="en"><head><meta charset="utf-8"/>` +
			`<title>Flowise - Build AI Agents, Visually</title>` +
			`<link rel="icon" href="/favicon.ico"/>` +
			`<script type="module" src="/assets/index.js"></script>`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Flowise" {
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
		t.Fatal("Flowise FP did not match the real index page title")
	}
}

func TestFlowise_RejectsHoneypotBait(t *testing.T) {
	// The honeypot serves the Flowise SPA shell at / but the body is just
	// a brand mention without the canonical title — and any page that
	// mentions "flowise" in passing should not match.
	for _, body := range []string{
		`<!DOCTYPE html><html><head><title>hoteldruid</title></head>` +
			`<body><p>we considered flowise and langflow before this</p></body></html>`,
		`<!DOCTYPE html><html><head><title>AI Tooling Comparison</title></head>` +
			`<body>Flowise vs Langflow vs Dify — a breakdown</body></html>`,
	} {
		pr := PortResult{
			Host: "203.0.113.111", Port: 3000, Open: true,
			StatusCode: 200, ContentType: "text/html",
			Headers:     map[string]string{"Content-Type": "text/html"},
			BodySnippet: body,
		}
		for _, fp := range Fingerprints {
			if fp.Name != "Flowise" {
				continue
			}
			for _, probe := range fp.Probes {
				if probe.Path != "/" && probe.Path != "" {
					continue
				}
				if matchProbe(probe, pr) {
					t.Fatalf("Flowise FP over-matched a bare brand mention: %.60s", body)
				}
			}
		}
	}
}

// Guard against the deprecated endpoint lingering: the API probe should
// target /api/v1/chatflows, not the removed /api/v1/flows.
func TestFlowise_UsesModernChatflowsEndpoint(t *testing.T) {
	fp := fpByName("Flowise")
	if fp == nil {
		t.Fatal("Flowise fingerprint not found")
	}
	hasChatflows := false
	for _, probe := range fp.Probes {
		if probe.Path == "/api/v1/chatflows" {
			hasChatflows = true
		}
		if probe.Path == "/api/v1/flows" {
			t.Error("Flowise FP still probes the deprecated /api/v1/flows endpoint")
		}
	}
	if !hasChatflows {
		t.Error("Flowise FP should probe the modern /api/v1/chatflows endpoint")
	}
}
