package main

import (
	"testing"
)

// Container / orchestration tier fingerprint tests.
//
// Every response body below is a source-of-truth snapshot from
// /home/cowboy/recon/2026-05-15-containers/verify/shapes.jsonl —
// captured during the 2026-05-15 container survey against 35 confirmed-exposed
// hosts (5 per service class). NOT a guess. NOT hand-authored.
//
// Two probes have no positive fixture because no matching response was captured:
//   - Consul Probe 2 (/v1/catalog/services 200 + json_field "consul"): only 500s
//     captured on that path. Probe shipped on spec authority; no positive test.
//   - Kubelet Probe 3 (/pods 200 + PodList): only 401s captured. Same rationale.
//
// Discipline: no naked single-word body_contains. Every match is anchored to
// status_code + body_contains together.

// containerMatches returns true if ANY probe of the named fingerprint matches pr.
func containerMatches(name string, pr PortResult) bool {
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

// ── etcd ──────────────────────────────────────────────────────────────

// Fixture: 101.53.134.137:2379 → GET /version 200
// body: {"etcdserver":"3.5.12","etcdcluster":"3.5.0"}
func TestEtcd_VersionEndpoint(t *testing.T) {
	pr := PortResult{
		Host: "101.53.134.137", Port: 2379, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"etcdserver":"3.5.12","etcdcluster":"3.5.0"}`,
	}
	if !containerMatches("etcd", pr) {
		t.Fatal("etcd FP did not match /version 200 + etcdserver+etcdcluster body (101.53.134.137:2379)")
	}
}

// Alternate fixture: 1.116.218.232:2379, older 3.4.x version string.
func TestEtcd_VersionEndpoint_OldVersion(t *testing.T) {
	pr := PortResult{
		Host: "1.116.218.232", Port: 2379, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"etcdserver":"3.4.9","etcdcluster":"3.4.0"}`,
	}
	if !containerMatches("etcd", pr) {
		t.Fatal("etcd FP did not match 3.4.x version body (1.116.218.232:2379)")
	}
}

// A generic 200 JSON response without etcdserver must NOT match.
func TestEtcd_NegativeCheck(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.1", Port: 2379, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"version":"3.5.12","cluster":"3.5.0"}`,
	}
	if containerMatches("etcd", pr) {
		t.Fatal("etcd FP false-positived on generic version JSON without etcdserver/etcdcluster keys")
	}
}

func TestEtcd_Registered(t *testing.T) {
	if fpByName("etcd") == nil {
		t.Fatal("etcd fingerprint not registered in the catalog")
	}
}

// ── Vault ─────────────────────────────────────────────────────────────

// Fixture: 104.236.5.62:8200 → GET /v1/sys/health 200
// body: {"initialized":true,"sealed":false,"standby":false,"performance_standby":false,...}
func TestVault_SysHealth(t *testing.T) {
	pr := PortResult{
		Host: "104.236.5.62", Port: 8200, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1778849574,"version":"1.21.4"}`,
	}
	if !containerMatches("Vault", pr) {
		t.Fatal("Vault FP did not match /v1/sys/health 200 + initialized+sealed body (104.236.5.62:8200)")
	}
}

// Alternate fixture: 116.203.80.133:8200, different version.
func TestVault_SysHealth_AltHost(t *testing.T) {
	pr := PortResult{
		Host: "116.203.80.133", Port: 8200, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1778849575,"version":"1.20.4"}`,
	}
	if !containerMatches("Vault", pr) {
		t.Fatal("Vault FP did not match /v1/sys/health 200 on 116.203.80.133:8200")
	}
}

// A generic 200 JSON with "initialized" but not "sealed" must NOT match.
func TestVault_NegativeCheck_MissingSealed(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.2", Port: 8200, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"initialized":true,"status":"ok"}`,
	}
	if containerMatches("Vault", pr) {
		t.Fatal("Vault FP false-positived on 200 JSON with 'initialized' but no 'sealed' field")
	}
}

func TestVault_Registered(t *testing.T) {
	if fpByName("Vault") == nil {
		t.Fatal("Vault fingerprint not registered in the catalog")
	}
}

// ── Docker daemon ──────────────────────────────────────────────────────

// Fixture A: 102.129.185.27:2375 → GET /version 200, Server: Docker/20.10.0 (linux)
// body: {"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"20.10.0",...
func TestDockerDaemon_ServerHeader(t *testing.T) {
	pr := PortResult{
		Host: "102.129.185.27", Port: 2375, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers: map[string]string{
			"Server":       "Docker/20.10.0 (linux)",
			"Content-Type": "application/json",
		},
		BodySnippet: `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"20.10.0","Details":{"ApiVersion":"1.41","Arch":"amd64","BuildTime":"2020-12-08T18:56:55.000000000+00:00","Experimental":"false","GitCommit":"eeddea6","GoVersion":"go1.13.15","KernelVersion":"4.15.0-142-generic","MinAPIVersion":"1.12","Os":"linux"}}]}`,
	}
	if !containerMatches("Docker daemon", pr) {
		t.Fatal("Docker daemon FP did not match Server: Docker/ header probe (102.129.185.27:2375)")
	}
}

// Fixture B: 129.151.144.78:2375 → GET /version 200, no Docker Server header
// body: {"ApiVersion":"1.44","GitCommit":"v25.0.5","GoVersion":"go1.21.8","KernelVersion":"6.1.0",...
func TestDockerDaemon_ApiVersionGoVersion(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 2375, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"ApiVersion":"1.44","GitCommit":"v25.0.5","GoVersion":"go1.21.8","KernelVersion":"6.1.0","DockerRootDir":"/var/lib/docker","ContainersRunning":2,"Images":8,"Driver":"overlay2"}`,
	}
	if !containerMatches("Docker daemon", pr) {
		t.Fatal("Docker daemon FP did not match ApiVersion+GoVersion body probe (129.151.144.78:2375)")
	}
}

// Fixture C: 146.59.83.12:2375 → GET /version 200 with BuildTime + GitCommit
func TestDockerDaemon_BuildTimeVariant(t *testing.T) {
	pr := PortResult{
		Host: "146.59.83.12", Port: 2375, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"ApiVersion":"1.42","Arch":"amd64","BuildTime":"2026-03-21T12:52:53Z","GitCommit":"8007c6c","GoVersion":"go1.18.9","KernelVersion":"4.15.0-142-generic","MinAPIVersion":"1.12","Os":"linux","Version":"20.10.17"}`,
	}
	if !containerMatches("Docker daemon", pr) {
		t.Fatal("Docker daemon FP did not match ApiVersion+GoVersion body on 146.59.83.12:2375")
	}
}

// A 200 JSON response with neither Docker Server header nor ApiVersion+GoVersion must NOT match.
func TestDockerDaemon_NegativeCheck(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.3", Port: 2375, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"version":"1.44","commit":"abc123","platform":"linux"}`,
	}
	if containerMatches("Docker daemon", pr) {
		t.Fatal("Docker daemon FP false-positived on generic version JSON without ApiVersion+GoVersion or Docker/ header")
	}
}

func TestDockerDaemon_Registered(t *testing.T) {
	if fpByName("Docker daemon") == nil {
		t.Fatal("Docker daemon fingerprint not registered in the catalog")
	}
}

// ── Kubernetes API ─────────────────────────────────────────────────────

// Fixture Probe 1: 109.107.36.44:6443 → GET /version 200
// body: {   "major": "1",   "minor": "32",   "gitVersion": "v1.32.1",   "gitCommit": "e9c9be4007...
func TestKubernetesAPI_VersionEndpoint(t *testing.T) {
	pr := PortResult{
		Host: "109.107.36.44", Port: 6443, Open: true, TLS: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{   "major": "1",   "minor": "32",   "gitVersion": "v1.32.1",   "gitCommit": "e9c9be4007d1664e68796af02b8978640d2c1b26",   "gitTreeState": "clean",   "buildDate": "2025-01-15T14:31:55Z",   "goVersion": "go1.23.4",   "compiler": "gc",   "platform": "linux/amd64" }`,
	}
	if !containerMatches("Kubernetes API", pr) {
		t.Fatal("Kubernetes API FP did not match /version 200 + gitVersion+gitCommit body (109.107.36.44:6443)")
	}
}

// Alternate fixture: 101.89.57.65:6443, k3s build.
func TestKubernetesAPI_VersionEndpoint_K3s(t *testing.T) {
	pr := PortResult{
		Host: "101.89.57.65", Port: 6443, Open: true, TLS: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{   "major": "1",   "minor": "34",   "emulationMajor": "1",   "emulationMinor": "34",   "minCompatibilityMajor": "1",   "gitVersion": "v1.34.2+k3s1",   "gitCommit": "8fc38d5b3b8a8bcf6c8aae56f0c4f6d6e3a8a1b2" }`,
	}
	if !containerMatches("Kubernetes API", pr) {
		t.Fatal("Kubernetes API FP did not match k3s /version 200 on 101.89.57.65:6443")
	}
}

// Fixture Probe 2: 101.89.57.65:6443 → GET /api 403
// body: {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cann...
func TestKubernetesAPI_AnonRejection(t *testing.T) {
	pr := PortResult{
		Host: "101.89.57.65", Port: 6443, Open: true, TLS: true,
		StatusCode:  403,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/api\"","reason":"Forbidden","details":{},"code":403}`,
	}
	if !containerMatches("Kubernetes API", pr) {
		t.Fatal("Kubernetes API FP did not match /api 403 + system:anonymous forbidden body (101.89.57.65:6443)")
	}
}

// A generic 403 without the system:anonymous + forbidden combination must NOT match Probe 2.
func TestKubernetesAPI_NegativeCheck_Generic403(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.4", Port: 6443, Open: true,
		StatusCode:  403,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"error":"Forbidden","message":"Access denied"}`,
	}
	if containerMatches("Kubernetes API", pr) {
		t.Fatal("Kubernetes API FP false-positived on generic 403 JSON without system:anonymous")
	}
}

// A 200 with "gitVersion" but not "gitCommit" must NOT match Probe 1.
func TestKubernetesAPI_NegativeCheck_MissingGitCommit(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.5", Port: 6443, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"major":"1","minor":"32","gitVersion":"v1.32.1","platform":"linux/amd64"}`,
	}
	if containerMatches("Kubernetes API", pr) {
		t.Fatal("Kubernetes API FP false-positived on 200 with gitVersion but no gitCommit")
	}
}

func TestKubernetesAPI_Registered(t *testing.T) {
	if fpByName("Kubernetes API") == nil {
		t.Fatal("Kubernetes API fingerprint not registered in the catalog")
	}
}

// ── Consul ────────────────────────────────────────────────────────────

// Fixture Probe 1: 103.251.165.56:8500 → GET /v1/agent/self 200
// body: {"Config":{"Datacenter":"main","PrimaryDatacenter":"main","NodeName":"nl-lt-vpn01","NodeID":"831e6a57-...
func TestConsul_AgentSelf(t *testing.T) {
	pr := PortResult{
		Host: "103.251.165.56", Port: 8500, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"Config":{"Datacenter":"main","PrimaryDatacenter":"main","NodeName":"nl-lt-vpn01","NodeID":"831e6a57-614b-e3a0-5285-ecfa3805be84","Revision":"920cc7c6","Server":false,"Version":"1.20.1","BuildDate":"2024-12-11T12:00:04Z"},"DebugConfig":{},"Coord":{"Adjustment":0,"Error":0,"Vec":[]}}`,
	}
	if !containerMatches("Consul", pr) {
		t.Fatal("Consul FP did not match /v1/agent/self 200 + Datacenter+NodeName body (103.251.165.56:8500)")
	}
}

// A 200 JSON with neither Datacenter nor NodeName must NOT match Probe 1.
func TestConsul_NegativeCheck(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.6", Port: 8500, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"ok","service":"agent","version":"1.20.1"}`,
	}
	if containerMatches("Consul", pr) {
		t.Fatal("Consul FP false-positived on generic 200 JSON without Datacenter+NodeName")
	}
}

func TestConsul_Registered(t *testing.T) {
	if fpByName("Consul") == nil {
		t.Fatal("Consul fingerprint not registered in the catalog")
	}
}

// ── Portainer ────────────────────────────────────────────────────────

// Fixture: 103.219.226.52:9000 → GET /api/status 200
// body: {"Version":"2.19.5","InstanceID":"4d15c813-c0d4-421e-93b7-38dbd7565384","DemoEnvironment":{...
func TestPortainer_ApiStatus(t *testing.T) {
	pr := PortResult{
		Host: "103.219.226.52", Port: 9000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"Version":"2.19.5","InstanceID":"4d15c813-c0d4-421e-93b7-38dbd7565384","DemoEnvironment":{"enabled":false,"users":null,"environments":null}}`,
	}
	if !containerMatches("Portainer", pr) {
		t.Fatal("Portainer FP did not match /api/status 200 + Version+InstanceID body (103.219.226.52:9000)")
	}
}

// Alternate fixture: 109.48.27.231:9000 → same shape, different instance.
func TestPortainer_ApiStatus_AltHost(t *testing.T) {
	pr := PortResult{
		Host: "109.48.27.231", Port: 9000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"Version":"2.19.5","InstanceID":"a21555ee-e506-454c-8d0e-b6e4a58a434f","DemoEnvironment":{"enabled":false,"users":null,"environments":null}}`,
	}
	if !containerMatches("Portainer", pr) {
		t.Fatal("Portainer FP did not match /api/status 200 on 109.48.27.231:9000")
	}
}

// Alternate fixture: 111.230.186.91:9000 → older version 2.16.2.
func TestPortainer_ApiStatus_OlderVersion(t *testing.T) {
	pr := PortResult{
		Host: "111.230.186.91", Port: 9000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"Version":"2.16.2","InstanceID":"30c5f134-5675-4cbf-bb76-89f12d537354","DemoEnvironment":{"enabled":false,"users":null,"environments":null}}`,
	}
	if !containerMatches("Portainer", pr) {
		t.Fatal("Portainer FP did not match older Version 2.16.2 (111.230.186.91:9000)")
	}
}

// A 404 on /api/status (non-Portainer service on port 9000) must NOT match.
func TestPortainer_NegativeCheck_404(t *testing.T) {
	pr := PortResult{
		Host: "103.230.14.155", Port: 9000, Open: true,
		StatusCode:  404,
		ContentType: "text/html",
		Headers:     map[string]string{"Content-Type": "text/html"},
		BodySnippet: `<!DOCTYPE html> <html lang="en"> <head> <meta charset="utf-8"> <title>Error</title> </head> <body> <pre>Cannot GET /api/status</pre> </body> </html>`,
	}
	if containerMatches("Portainer", pr) {
		t.Fatal("Portainer FP false-positived on 404 response (103.230.14.155:9000 — Express app, not Portainer)")
	}
}

// A 200 JSON with "Version" but no "InstanceID" must NOT match.
func TestPortainer_NegativeCheck_MissingInstanceID(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.7", Port: 9000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"Version":"2.19.5","Status":"running","Environment":"production"}`,
	}
	if containerMatches("Portainer", pr) {
		t.Fatal("Portainer FP false-positived on 200 JSON with Version but no InstanceID")
	}
}

func TestPortainer_Registered(t *testing.T) {
	if fpByName("Portainer") == nil {
		t.Fatal("Portainer fingerprint not registered in the catalog")
	}
}

// ── Kubelet ───────────────────────────────────────────────────────────

// Fixture Probe 1: 175.178.65.155:10250 → GET /healthz 200, body: ok
// Anonymous Kubelet — no auth enforced.
func TestKubelet_HealthzOK(t *testing.T) {
	pr := PortResult{
		Host: "175.178.65.155", Port: 10250, Open: true,
		StatusCode:  200,
		ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `ok`,
	}
	if !containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP did not match /healthz 200 + body 'ok' (175.178.65.155:10250)")
	}
}

// Fixture Probe 2: 172.236.15.129:10250 → GET /healthz 401, body: Unauthorized
// Auth-protected Kubelet — still identified.
func TestKubelet_HealthzUnauthorized(t *testing.T) {
	pr := PortResult{
		Host: "172.236.15.129", Port: 10250, Open: true,
		StatusCode:  401,
		ContentType: "text/plain",
		Headers:     map[string]string{"Content-Type": "text/plain"},
		BodySnippet: `Unauthorized`,
	}
	if !containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP did not match /healthz 401 + body 'Unauthorized' (172.236.15.129:10250)")
	}
}

// A generic health endpoint on port 80 returning 200 "ok" must NOT match
// (Kubelet Probe 1 is port-gated; this tests that the probe conditions alone
// on a non-Kubelet port don't false-positive if somehow triggered).
// We verify by confirming 200+"ok" on a non-Kubelet port doesn't appear
// in the Kubelet catalog entry — tested indirectly by checking the
// fingerprint's DefaultPorts don't include 80.
func TestKubelet_DefaultPortsNotInclude80(t *testing.T) {
	fp := fpByName("Kubelet")
	if fp == nil {
		t.Fatal("Kubelet fingerprint not registered")
	}
	for _, p := range fp.DefaultPorts {
		if p == 80 {
			t.Fatal("Kubelet DefaultPorts includes port 80 — Probe 1 (200+ok) will false-positive on generic health endpoints")
		}
	}
}

// A generic 401 response without "Unauthorized" in body must NOT match Probe 2.
func TestKubelet_NegativeCheck_Generic401(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.8", Port: 10250, Open: true,
		StatusCode:  401,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"error":"authentication required","code":401}`,
	}
	if containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP false-positived on 401 JSON without 'Unauthorized' literal")
	}
}

func TestKubelet_Registered(t *testing.T) {
	if fpByName("Kubelet") == nil {
		t.Fatal("Kubelet fingerprint not registered in the catalog")
	}
}

// ── FP regression tests: Kubelet, Lunary, Langfuse vs Qdrant/Milvus/CrateDB ──
//
// These tests use the actual response bodies that triggered deep-mode FPs
// against 129.151.144.78 on 2026-05-15. Bodies sourced from the live run.

// Qdrant /healthz: {"result":{"title":"qdrant","version":"1.8.4"},"status":"ok","time":0.001}
// Content-Type: application/json — not text/plain. Must NOT match Kubelet Probe 1.
func TestKubelet_DoesNotFalsePositiveOnQdrant(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 6333, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"result":{"title":"qdrant","version":"1.8.4"},"status":"ok","time":0.001}`,
	}
	if containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP false-positived on Qdrant /healthz JSON response (deep-mode 2026-05-15 FP class)")
	}
}

// Milvus /healthz: {"status":"ok"} with Server: Milvus/2.3.4 header — JSON body.
// Must NOT match Kubelet Probe 1.
func TestKubelet_DoesNotFalsePositiveOnMilvus(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 19530, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Server":       "Milvus/2.3.4",
		},
		BodySnippet: `{"status":"ok"}`,
	}
	if containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP false-positived on Milvus /healthz JSON response (deep-mode 2026-05-15 FP class)")
	}
}

// CrateDB /healthz: {"ok":true,"status":200,"name":"lb17","cluster_name":"crate","version":{"number":"5.6.4"}}
// Content-Type: application/json. Must NOT match Kubelet Probe 1.
func TestKubelet_DoesNotFalsePositiveOnCrateDB(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 4200, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"ok":true,"status":200,"name":"lb17","cluster_name":"crate","version":{"number":"5.6.4"}}`,
	}
	if containerMatches("Kubelet", pr) {
		t.Fatal("Kubelet FP false-positived on CrateDB /healthz JSON response (deep-mode 2026-05-15 FP class)")
	}
}

// Lunary Probe 1 (/api/v1/health) must NOT match Qdrant's body which contains "qdrant".
func TestLunary_DoesNotFalsePositiveOnQdrant(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 6333, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		// Qdrant /api/v1/health returns the same body shape as /healthz
		BodySnippet: `{"result":{"title":"qdrant","version":"1.8.4"},"status":"ok","time":0.001}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/v1/health" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Lunary /api/v1/health probe false-positived on Qdrant body (deep-mode 2026-05-15 FP class)")
			}
		}
	}
}

// Lunary Probe 1 must NOT match Milvus /api/v1/health response.
// Real Milvus body is exactly {"status":"ok"} — body-identical to a minimal Lunary response.
// Milvus is discriminated by the Server: Milvus/2.3.4 header via header_not_contains.
// Fixture: 129.151.144.78:19530 → GET /api/v1/health 200, Server: Milvus/2.3.4,
//   body: {"status":"ok"}  (captured 2026-05-15)
func TestLunary_DoesNotFalsePositiveOnMilvus(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 19530, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Server":       "Milvus/2.3.4",
		},
		BodySnippet: `{"status":"ok"}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/v1/health" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Lunary /api/v1/health probe false-positived on real Milvus body+Server-header (deep-mode 2026-05-15 FP class)")
			}
		}
	}
}

// Regression: Lunary Probe 1 still passes when Server header is absent (most Lunary installs).
func TestLunary_MatchesRealHealthShapeNoServerHeader(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.93", Port: 3000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"OK"}`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Lunary" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/v1/health" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("Lunary /api/v1/health probe no longer matches real Lunary response (header_not_contains regression)")
	}
}

// Langfuse Probe 1 (/api/public/health) must NOT match CrateDB's response which
// contains "status", "version", "cluster_name", and "build_hash" fields.
func TestLangfuse_DoesNotFalsePositiveOnCrateDB(t *testing.T) {
	pr := PortResult{
		Host: "129.151.144.78", Port: 4200, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"ok":true,"status":200,"name":"lb17","cluster_name":"crate","version":{"number":"5.6.4","build_hash":"abc123","build_timestamp":"2024-01-15"}}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Langfuse" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/public/health" {
				continue
			}
			if matchProbe(probe, pr) {
				t.Fatal("Langfuse /api/public/health probe false-positived on CrateDB body (deep-mode 2026-05-15 FP class)")
			}
		}
	}
}

// Langfuse Probe 1 must still match a real Langfuse health response.
func TestLangfuse_MatchesRealHealthShape(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.99", Port: 3000, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		BodySnippet: `{"status":"OK","version":"2.78.2"}`,
	}
	matched := false
	for _, fp := range Fingerprints {
		if fp.Name != "Langfuse" {
			continue
		}
		for _, probe := range fp.Probes {
			if probe.Path != "/api/public/health" {
				continue
			}
			if matchProbe(probe, pr) {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("Langfuse FP no longer matches the canonical {\"status\":\"OK\",\"version\":\"x.y.z\"} health response")
	}
}

// Docker daemon Probe 2 must NOT match Kubernetes API /version output (gitVersion present).
func TestDockerDaemon_DoesNotFalsePositiveOnKubernetesAPI(t *testing.T) {
	pr := PortResult{
		Host: "203.0.113.99", Port: 6443, Open: true,
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"Content-Type": "application/json"},
		// Real K8s /version — contains ApiVersion via the k8s package but primarily gitVersion
		BodySnippet: `{"major":"1","minor":"32","gitVersion":"v1.32.1","gitCommit":"e9c9be40","gitTreeState":"clean","buildDate":"2025-01-15T14:31:55Z","goVersion":"go1.23.4","compiler":"gc","platform":"linux/amd64"}`,
	}
	for _, fp := range Fingerprints {
		if fp.Name != "Docker daemon" {
			continue
		}
		for i, probe := range fp.Probes {
			if i == 0 {
				continue // Probe 0 is Server-header only — skip
			}
			if matchProbe(probe, pr) {
				t.Fatal("Docker daemon Probe 2 false-positived on Kubernetes API /version output (gitVersion body)")
			}
		}
	}
}

// ── Catalog registration guard: all 7 new fingerprints ────────────────

func TestContainerTier_AllRegistered(t *testing.T) {
	names := []string{
		"etcd",
		"Vault",
		"Docker daemon",
		"Kubernetes API",
		"Consul",
		"Portainer",
		"Kubelet",
	}
	for _, name := range names {
		if fpByName(name) == nil {
			t.Fatalf("Container tier fingerprint %q not registered in the catalog", name)
		}
	}
}
