package main

import (
	"strings"
	"testing"
)

// Healthcare imaging classifier tests. Fixtures are synthetic-but-realistic
// based on known upstream image names: dcm4chee-arc-light Docker images,
// Orthanc (orthancteam/orthanc + osimis/orthanc), OHIF Viewer, Weasis, and
// DICOMweb route-fragment image-name patterns observed in past surveys.

func TestHealthcareClassify_DCM4CHEE_High(t *testing.T) {
	repos := []string{
		"dcm4che/dcm4chee-arc-psql",
		"dcm4che/dcm4chee-arc-keycloak",
		"dcm4che/slapd-dcm4chee",
		"library/postgres",
		"library/nginx",
	}
	matched, conf := classifyHealthcareRepos(repos)
	if conf != "high" {
		t.Fatalf("dcm4chee stack expected high; got %q matched=%v", conf, matched)
	}
	mustContain(t, matched, "dcm4che/dcm4chee-arc-psql")
}

func TestHealthcareClassify_Orthanc_High(t *testing.T) {
	repos := []string{
		"orthancteam/orthanc",
		"osimis/orthanc",
		"library/mariadb",
		"library/redis",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "high" {
		t.Fatalf("orthanc stack expected high; got %q", conf)
	}
}

func TestHealthcareClassify_OHIF_High(t *testing.T) {
	repos := []string{
		"ohif/viewer",
		"library/nginx",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "high" {
		t.Fatalf("OHIF Viewer expected high; got %q", conf)
	}
}

func TestHealthcareClassify_DICOMRoute_High(t *testing.T) {
	repos := []string{
		"hospital/pacs-server",
		"hospital/dicom-router",
		"library/postgres",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "high" {
		t.Fatalf("explicit pacs/dicom repo names expected high; got %q", conf)
	}
}

// Negative: a generic Postgres + Redis + nginx stack with no healthcare
// signals must NOT fire.
func TestHealthcareClassify_GenericStack_None(t *testing.T) {
	repos := []string{
		"library/postgres",
		"library/redis",
		"library/nginx",
		"library/python",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "" {
		t.Fatalf("generic stack must not trigger healthcare attribution; got %q", conf)
	}
}

// Negative: a Jetson registry (F1 mfgbot) must NOT cross-fire as healthcare.
func TestHealthcareClassify_JetsonF1_None(t *testing.T) {
	repos := []string{
		"mfgbot/l4t-base",
		"mfgbot-os/jetson",
		"nvcr.io/nvidia/l4t-base",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "" {
		t.Fatalf("Jetson mfgbot must not trigger healthcare attribution; got %q", conf)
	}
}

// Finance / algotrading classifier tests.

func TestFinanceClassify_Freqtrade_High(t *testing.T) {
	repos := []string{
		"freqtradeorg/freqtrade",
		"library/python",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "high" {
		t.Fatalf("freqtrade expected high; got %q", conf)
	}
}

func TestFinanceClassify_IBGateway_High(t *testing.T) {
	repos := []string{
		"voyz/ib-gateway",
		"library/python",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "high" {
		t.Fatalf("ib-gateway expected high; got %q", conf)
	}
}

func TestFinanceClassify_QuantLib_High(t *testing.T) {
	repos := []string{
		"trader/quantlib-engine",
		"library/postgres",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "high" {
		t.Fatalf("quantlib expected high; got %q", conf)
	}
}

func TestFinanceClassify_VectorBT_High(t *testing.T) {
	repos := []string{
		"quant/vectorbt-runner",
		"library/jupyter",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "high" {
		t.Fatalf("vectorbt expected high; got %q", conf)
	}
}

func TestFinanceClassify_BacktraderAlone_Medium(t *testing.T) {
	repos := []string{
		"library/backtrader-research",
		"library/jupyter",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "medium" {
		t.Fatalf("backtrader alone expected medium; got %q", conf)
	}
}

// Negative: commodity AI stack must NOT trigger finance attribution.
func TestFinanceClassify_AIStack_None(t *testing.T) {
	repos := []string{
		"ollama/ollama",
		"vllm/vllm",
		"library/postgres",
		"langgenius/dify-api",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "" {
		t.Fatalf("AI stack must not trigger finance attribution; got %q", conf)
	}
}

// Negative: F4 RAG-LLM (Jetson) must NOT cross-fire as finance.
func TestFinanceClassify_JetsonF4_None(t *testing.T) {
	repos := []string{
		"dustynv/ollama",
		"langgenius/dify-api",
		"library/postgres",
		"semitechnologies/weaviate",
	}
	_, conf := classifyFinanceRepos(repos)
	if conf != "" {
		t.Fatalf("Jetson F4 must not trigger finance attribution; got %q", conf)
	}
}

// Insight #35 regression: Russian regional-healthcare operator must fire on
// healthcare classifier. Burned 2026-05-19: 88.99.214.110:5000 has repos
// `external/krayzdrav/fss-public` etc. — krayzdrav = "regional health" in
// Russian/Ukrainian. v1.9.13 missed it; v1.9.15 expanded signals cover it.
func TestHealthcareClassify_RussianKrayzdrav_High(t *testing.T) {
	repos := []string{
		"external/krayzdrav/equipment",
		"external/krayzdrav/fss-public",
		"external/krayzdrav/portal-netrika",
		"external/krayzdrav/staff",
		"library/postgres",
	}
	matched, conf := classifyHealthcareRepos(repos)
	if conf != "high" {
		t.Fatalf("krayzdrav repos must trigger healthcare:high; got %q matched=%v", conf, matched)
	}
}

// International healthcare coverage: each major-language term should fire.
func TestHealthcareClassify_InternationalTerms_High(t *testing.T) {
	cases := []struct {
		name  string
		repos []string
	}{
		{"German klinik", []string{"vendor/klinik-portal", "library/nginx"}},
		{"Spanish salud", []string{"hospital/salud-portal", "library/postgres"}},
		{"French clinique", []string{"vendor/clinique-app", "library/redis"}},
		{"Italian ospedale", []string{"vendor/ospedale-portal", "library/mysql"}},
		{"Mandarin yiyuan", []string{"hospital/yiyuan-portal", "library/nginx"}},
		{"Japanese byouin", []string{"vendor/byouin-portal", "library/python"}},
	}
	for _, c := range cases {
		_, conf := classifyHealthcareRepos(c.repos)
		if conf != "high" {
			t.Fatalf("%s expected healthcare:high; got %q", c.name, conf)
		}
	}
}

// Negative: short English words containing healthcare-term substrings must NOT
// fire (anchoring discipline). E.g. `klinikum` contains `klinik` (legit), but
// `redis-bullshit` should not match anything. Test for false-positive
// avoidance.
func TestHealthcareClassify_NoCommonWordFP(t *testing.T) {
	repos := []string{
		"library/redis", "library/nginx", "library/postgres",
		"vendor/parasites",      // contains `site` (no health term substring though)
		"company/strange-image",
	}
	_, conf := classifyHealthcareRepos(repos)
	if conf != "" {
		t.Fatalf("commodity stack must not trigger healthcare; got %q", conf)
	}
}

// v1.9.15 regression: `ray` substring FP'd on `krayzdrav` in the AI-image
// commodity classifier. The aiRegistryImages list now uses anchored variants.
// Test indirectly by checking that aiRegistryImages does NOT contain bare
// `ray` as a single entry (which would substring-match on krayzdrav, prayer,
// etc.).
func TestAIRegistryImages_NoBareRay(t *testing.T) {
	for _, sig := range aiRegistryImages {
		if sig == "ray" {
			t.Fatalf("aiRegistryImages contains bare `ray` substring — will FP on krayzdrav/prayer/etc. Use anchored variants instead.")
		}
	}
}

// Confirm anchored ray variants still match legitimate Ray containers.
func TestAIRegistryImages_AnchoredRayStillMatches(t *testing.T) {
	candidates := []string{
		"rayproject/ray",
		"anyscale/ray",
		"my/ray-cluster",
	}
	for _, repo := range candidates {
		hit := false
		for _, sig := range aiRegistryImages {
			if strings.Contains(repo, sig) {
				hit = true
				break
			}
		}
		if !hit {
			t.Fatalf("legitimate Ray repo %q no longer matches any aiRegistryImages signal", repo)
		}
	}
}

// Cross-class isolation: a mixed-stack registry must produce the correct
// attribution per class, not blend them.
func TestClassifiers_CrossClassIsolation(t *testing.T) {
	repos := []string{
		"dcm4che/dcm4chee-arc-psql",  // healthcare high
		"freqtradeorg/freqtrade",      // finance high
		"dustynv/ollama",               // jetson high
		"library/postgres",             // none
	}

	_, jetson := classifyJetsonRepos(repos)
	if jetson != "high" {
		t.Fatalf("mixed stack: Jetson classifier expected high (dustynv); got %q", jetson)
	}
	_, health := classifyHealthcareRepos(repos)
	if health != "high" {
		t.Fatalf("mixed stack: healthcare classifier expected high (dcm4chee); got %q", health)
	}
	_, fin := classifyFinanceRepos(repos)
	if fin != "high" {
		t.Fatalf("mixed stack: finance classifier expected high (freqtrade); got %q", fin)
	}
}
