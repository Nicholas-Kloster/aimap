package main

import (
	"testing"
)

// Iter 10: voice/audio tier audit.
//
// Coqui XTTS: the modern deployments (verified live 2026-05-13 against
// 195.87.80.179:8040) ship a custom HTML UI titled "XTTS - ..." rather
// than the upstream `/api/tts/speakers` API + the "coqui" brand string
// in the body. The old conjunctive `XTTS` + `coqui` requirement was too
// strict for these forks; we need a probe that catches the upstream API
// AND a separate probe that catches the custom-UI shape.
func TestCoquiXTTS_MatchesCustomHTMLUI(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.50", Port: 8040, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html lang="tr"><head>` +
			`<title>XTTS - Metin'den Ses Üret</title>` +
			`<link rel="stylesheet" href="/static/style.css">` +
			`<h1>🎤 XTTS - Metin'den Ses Üret</h1>` +
			`<form id="ttsForm" class="tts-form">`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Coqui XTTS" {
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
		t.Fatal("Coqui XTTS FP did not match a real custom-UI deployment with XTTS title")
	}
}

// LiveKit: the canonical "LiveKit Meet" demo app shipped by upstream
// (verified live 2026-05-13 against 143.20.37.151:3002) is a Next.js
// SPA. Its body has /images/livekit-meet-home.svg as a unique asset
// path but NO `livekit-agents` or `livekit-server` strings. The
// existing FP misses this very common deployment.
func TestLiveKit_MatchesMeetDemoApp(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.51", Port: 3002, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html lang="en"><head>` +
			`<meta charSet="utf-8"/>` +
			`<link rel="preload" as="image" href="/images/livekit-meet-home.svg"/>` +
			`<link rel="stylesheet" href="/_next/static/css/5a2d384c6ef993a4.css"/>` +
			`<script src="/_next/static/chunks/main-app-9e7ef5f44653aca3.js"></script>`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "LiveKit Agents" {
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
		t.Fatal("LiveKit FP did not match the canonical LiveKit Meet demo shape")
	}
}

// Guard: a random page that just mentions "XTTS" or "LiveKit" should NOT
// trigger the FPs. The conjunctive guard is the load-bearing constraint.
func TestCoquiXTTS_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.52", Port: 8040, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>Voice Tools Roundup</title></head>` +
			`<body><p>XTTS is a great open-source TTS option. Compare to ElevenLabs...</p>`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Coqui XTTS" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Coqui XTTS FP over-matched a brand-mention article")
			}
		}
	}
}

func TestLiveKit_RejectsBareBrandMention(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.53", Port: 3000, Open: true,
		StatusCode: 200, ContentType: "text/html",
		Headers: map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html><html><head><title>WebRTC Comparison</title></head>` +
			`<body><p>We considered LiveKit and Daily.co but settled on...</p>`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "LiveKit Agents" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/" && probe.Path != "" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("LiveKit FP over-matched a brand-mention article")
			}
		}
	}
}
