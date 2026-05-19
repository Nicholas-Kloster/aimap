package main

import (
	"testing"
)

// Jetson-attribution tests for classifyJetsonRepos.
//
// All fixtures are real /v2/_catalog responses captured during the
// Jetson-tensorrt edge population survey 2026-05-18. Raw evidence in
// /home/cowboy/recon/jetson-tensorrt-2026-05-18/registries/F{1..5}-*.json.
// NOT a guess. NOT hand-authored.
//
// Cases:
//   F1 mfgbot       (37.27.229.120:5000  Hetzner FI)   -> high (l4t + jetson)
//   F2 Harbor       (172.245.18.104:55000 HostPapa US) -> none (no Jetson signals)
//   F3 GPU-Operator (14.103.220.38:5000  Volcano CN)   -> none (server stack, not Jetson)
//   F4 RAG-LLM      (43.133.1.147:5000   APNIC JP)     -> high (dustynv)
//   F5 Auriga       (47.93.158.253:5000  Aliyun CN)    -> high (isaac + aarch64)

// F1: explicit l4t-base + jetson/* + aarch64 across 12 repos.
func TestJetsonClassify_F1_Mfgbot_High(t *testing.T) {
	repos := []string{
		"mfgbot/aarch64",
		"mfgbot/base-aarch64",
		"mfgbot/base-aarch64-cuda",
		"mfgbot/base-x86_64",
		"mfgbot/l4t-base",
		"mfgbot/pytorch",
		"mfgbot/x86_64",
		"mfgbot-os",
		"mfgbot-os/jetson",
		"mfgbot-os/jetson/cuda",
		"mfgbot-os/jetson/pytorch",
		"nvcr.io/nvidia/l4t-base",
	}
	matched, conf := classifyJetsonRepos(repos)
	if conf != "high" {
		t.Fatalf("F1 mfgbot expected confidence=high, got %q (matched=%v)", conf, matched)
	}
	mustContain(t, matched, "mfgbot/l4t-base")
	mustContain(t, matched, "mfgbot-os/jetson")
	mustContain(t, matched, "nvcr.io/nvidia/l4t-base")
}

// F2: nvidia/deepstream + nvidia/k8s/cuda-sample present but neither is a
// Jetson signal (DeepStream and CUDA samples run on x86 too). Must NOT fire.
func TestJetsonClassify_F2_Harbor_None(t *testing.T) {
	repos := []string{
		"ddsderek/easyimage",
		"emqx/emqx",
		"goharbor/harbor-core",
		"goharbor/harbor-db",
		"grafana/grafana",
		"library/busybox",
		"library/nginx",
		"library/python",
		"nvidia/deepstream",
		"nvidia/k8s/cuda-sample",
		"ollama/ollama",
		"open-webui/open-webui",
		"prom/prometheus",
		"pytorch/torchserve",
	}
	matched, conf := classifyJetsonRepos(repos)
	if conf != "" {
		t.Fatalf("F2 Harbor expected no Jetson attribution; got conf=%q matched=%v", conf, matched)
	}
}

// F3: NVIDIA GPU Operator server-cluster stack. cuda/driver/gpu-operator/dcgm
// are x86 K8s components, not Jetson. Must NOT fire.
func TestJetsonClassify_F3_GpuOperator_None(t *testing.T) {
	repos := []string{
		"airshipit/kubernetes-entrypoint",
		"bitnamilegacy/haproxy",
		"library/busybox",
		"library/nginx",
		"nfd/node-feature-discovery",
		"nvidia/cloud-native/dcgm",
		"nvidia/cloud-native/k8s-driver-manager",
		"nvidia/cloud-native/k8s-mig-manager",
		"nvidia/cuda",
		"nvidia/driver",
		"nvidia/gpu-operator",
		"nvidia/k8s/container-toolkit",
		"nvidia/k8s/cuda-sample",
		"nvidia/k8s/dcgm-exporter",
		"nvidia/k8s-device-plugin",
		"openclaw/openclaw",
		"tailscale/tailscale",
		"tsl0922/ttyd",
	}
	matched, conf := classifyJetsonRepos(repos)
	if conf != "" {
		t.Fatalf("F3 GPU-Operator expected no Jetson attribution (x86 K8s stack); got conf=%q matched=%v", conf, matched)
	}
}

// F4: single-signal high confidence. `dustynv/ollama` is the only Jetson tag
// among 39 repos. The aiRegistryImages pass would match many; the Jetson
// pass must pick out dustynv specifically.
func TestJetsonClassify_F4_DustyNv_High(t *testing.T) {
	repos := []string{
		"clickhouse/clickhouse-server",
		"dqzboy/docker-registry-ui",
		"dustynv/ollama",
		"edwardelric233/ragflow",
		"langgenius/dify-api",
		"langgenius/dify-web",
		"leopony/ollama",
		"library/elasticsearch",
		"library/mariadb",
		"library/postgres",
		"library/redis",
		"library/ubuntu",
		"localai/localai",
		"metabase/metabase",
		"n8nio/n8n",
		"portainer/portainer-ce",
		"semitechnologies/weaviate",
	}
	matched, conf := classifyJetsonRepos(repos)
	if conf != "high" {
		t.Fatalf("F4 RAG-LLM expected confidence=high (dustynv/ollama); got conf=%q matched=%v", conf, matched)
	}
	mustContain(t, matched, "dustynv/ollama")
	// Should NOT also tag library/ubuntu or leopony/ollama as Jetson.
	mustNotContain(t, matched, "library/ubuntu")
	mustNotContain(t, matched, "leopony/ollama")
}

// F5: medium (isaac-lab, isaac-sim) + arch (aarch64, _arm) -> promoted to high.
func TestJetsonClassify_F5_Auriga_High(t *testing.T) {
	repos := []string{
		"auriga/ros2_dev-aarch64-cpp",
		"auriga/ros2_dev-x86_64-cpp",
		"autocut-gpu",
		"base_chassis_navigation_arm",
		"isaac-lab-base-full",
		"isaac-lab-ros2-full",
		"isaac_ros_dev-x86_64-cpp",
		"mineru",
		"multiarch/qemu-user-static",
		"nvcr.io/nvidia/cloudxr-runtime",
		"nvcr.io/nvidia/isaac-sim",
		"registry",
		"ros2_dev-x86_64-cpp",
		"ros_noetic",
		"ubuntu",
	}
	matched, conf := classifyJetsonRepos(repos)
	if conf != "high" {
		t.Fatalf("F5 Auriga expected confidence=high (isaac+aarch64); got conf=%q matched=%v", conf, matched)
	}
	mustContain(t, matched, "isaac-lab-base-full")
	mustContain(t, matched, "nvcr.io/nvidia/isaac-sim")
	mustContain(t, matched, "isaac_ros_dev-x86_64-cpp")
	mustContain(t, matched, "auriga/ros2_dev-aarch64-cpp")
	mustContain(t, matched, "base_chassis_navigation_arm")
}

// Negative regression: a registry exposing only commodity AI images plus
// generic library images must NOT trigger Jetson attribution.
func TestJetsonClassify_NegativeCommodityAI(t *testing.T) {
	repos := []string{
		"ollama/ollama",
		"vllm/vllm",
		"pytorch/torchserve",
		"library/redis",
		"library/postgres",
		"langgenius/dify-api",
	}
	_, conf := classifyJetsonRepos(repos)
	if conf != "" {
		t.Fatalf("commodity-AI registry must not trigger Jetson attribution; got conf=%q", conf)
	}
}

// Edge: a single isaac-* signal with no arch hint -> medium only.
func TestJetsonClassify_IsaacSimAlone_Medium(t *testing.T) {
	repos := []string{
		"nvcr.io/nvidia/isaac-sim",
		"library/nginx",
		"library/redis",
	}
	_, conf := classifyJetsonRepos(repos)
	if conf != "medium" {
		t.Fatalf("isaac-sim alone (no arch hint) must be medium; got conf=%q", conf)
	}
}

// Edge: aarch64-only (no Jetson signal) -> low. The arch alone is not
// sufficient to attribute to Jetson; many ARM64 systems run aarch64 images.
func TestJetsonClassify_Aarch64Alone_Low(t *testing.T) {
	repos := []string{
		"library/ubuntu-aarch64",
		"library/nginx",
	}
	_, conf := classifyJetsonRepos(repos)
	if conf != "low" {
		t.Fatalf("aarch64 alone must be low; got conf=%q", conf)
	}
}

// Edge: empty catalog -> no attribution.
func TestJetsonClassify_EmptyCatalog_None(t *testing.T) {
	_, conf := classifyJetsonRepos([]string{})
	if conf != "" {
		t.Fatalf("empty catalog must produce no confidence; got conf=%q", conf)
	}
}

// Helpers.
func mustContain(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, s := range haystack {
		if s == needle {
			return
		}
	}
	t.Fatalf("expected %q in %v", needle, haystack)
}

func mustNotContain(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, s := range haystack {
		if s == needle {
			t.Fatalf("did not expect %q in %v", needle, haystack)
		}
	}
}
