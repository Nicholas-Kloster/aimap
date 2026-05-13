package main

import (
	"testing"
)

// TestHeliconeFingerprint_RejectsMarketingReflection guards against the
// false positive observed live on 2026-05-13 against 188.34.196.197:3000,
// 5.100.255.188:3000, and a marketing-site-reflecting reverse proxy.
//
// The FP fires when a host's body contains both "_next/static" and
// "helicone". The Helicone *marketing* site (helicone.ai) is Next.js so it
// contains "_next/static", and it of course mentions "helicone" repeatedly.
// Any reverse proxy that serves the marketing page on port 3000 (a common
// thing — "I'll just point my dev port at helicone.ai") matches the FP.
//
// Discriminator: a self-hosted instance does NOT set a <link rel="canonical">
// pointing at https://www.helicone.ai/. That hardcoded canonical is what
// the marketing static site ships with.
func TestHeliconeFingerprint_RejectsMarketingReflection(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.50",
		Port:        3000,
		Open:        true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html class=""><head><meta charSet="utf-8"/>` +
			`<meta name="viewport" content="width=device-width"/>` +
			`<title>Helicone - Open-Source Generative AI Platform for Developers</title>` +
			`<link rel="icon" href="/static/logo.webp"/>` +
			`<link rel="canonical" href="https://www.helicone.ai/"/>` +
			`<meta property="og:title" content="Helicone"/>` +
			`<script src="/_next/static/chunks/main.js"></script>` +
			`<p>about helicone</p>`,
	}

	for _, fp := range Fingerprints {
		if fp.Name != "Helicone Self-Hosted" {
			continue
		}
		for _, probe := range fp.Probes {
			// Only run the GET / probe (we don't make network calls in tests).
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Helicone Self-Hosted FP matched a marketing-site reflection")
			}
		}
	}
}

// TestHeliconeFingerprint_StillMatchesSignedinBranding asserts the FP keeps
// matching a real self-hosted Helicone signin page that does NOT have the
// canonical-to-marketing link.
//
// (This is a conservative shape captured from upstream Helicone's
// self-hosting docs and the prior case study at benchmarkit.solutions
// before that host was decommissioned.)
func TestHeliconeFingerprint_StillMatchesSelfHostedSignin(t *testing.T) {
	pr := PortResult{
		Host:        "203.0.113.51",
		Port:        3000,
		Open:        true,
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><meta charSet="utf-8"/>` +
			`<title>Sign In · Helicone</title>` +
			`<link rel="icon" href="/favicon.ico"/>` +
			`<script src="/_next/static/chunks/webpack.js"></script>` +
			`<link rel="stylesheet" href="/_next/static/css/main.css"/>` +
			`<p>helicone</p>`,
	}

	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Helicone Self-Hosted" {
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
		t.Fatal("Helicone Self-Hosted FP no longer matches a real self-hosted signin page (false negative)")
	}
}
