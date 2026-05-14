package main

import (
	"testing"
)

// Iter 20: n8n FP tightening.
// Verified live 2026-05-13 against 217.77.5.226:5678 and 89.207.169.68:10243.
// Real n8n deployments ship <title>n8n.io - Workflow Automation</title>
// in the body. Single-word body_contains "n8n" was over-match-prone (would
// fire on any page with the brand mentioned), same pathology as the
// Helicone/Open WebUI/Pipecat single-token brand matches that earlier
// iters fixed.

func TestN8n_MatchesCanonicalIndex(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.80", Port: 5678, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html lang="en"><head>` +
			`<meta charset="utf-8" />` +
			`<script>window.BASE_PATH = '/'; window.REST_ENDPOINT = 'rest';</script>` +
			`<title>n8n.io - Workflow Automation</title>` +
			`<script src="/assets/index-Be6oKJqR.js"></script>`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "n8n" {
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
		t.Fatal("n8n FP did not match a real n8n index page")
	}
}

func TestN8n_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.81", Port: 5678, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>No-Code Automation Roundup</title></head>` +
			`<body><p>We considered Make.com, n8n, and Zapier for our workflow needs...</p>`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "n8n" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("n8n FP over-matched a bare brand mention")
			}
		}
	}
}
