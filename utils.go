package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ── ANSI ────────────────────────────────────────────────────────────

const (
	cReset    = "\033[0m"
	cRed      = "\033[91m"
	cGreen    = "\033[92m"
	cYellow   = "\033[93m"
	cBlue     = "\033[94m"
	cCyan     = "\033[96m"
	cWhite    = "\033[97m"
	cBold     = "\033[1m"
	cDim      = "\033[2m"
	cRedBg    = "\033[41m"
	cYellowBg = "\033[43m"
	cBlueBg   = "\033[44m"
	cGrayBg   = "\033[100m"
)

func red(s string) string    { return cRed + s + cReset }
func green(s string) string  { return cGreen + s + cReset }
func yellow(s string) string { return cYellow + s + cReset }
func blue(s string) string   { return cBlue + s + cReset }
func cyan(s string) string   { return cCyan + s + cReset }
func bold(s string) string   { return cBold + s + cReset }
func dim(s string) string    { return cDim + s + cReset }

func sevIcon(sev string) string {
	switch sev {
	case "critical":
		return cRed + cBold + "✗✗" + cReset
	case "high":
		return cRed + "✗ " + cReset
	case "medium":
		return cYellow + "△ " + cReset
	case "low":
		return cBlue + "○ " + cReset
	default:
		return cDim + "· " + cReset
	}
}

func riskBadge(risk string) string {
	switch risk {
	case "critical":
		return cWhite + cRedBg + " CRIT " + cReset
	case "high":
		return cWhite + cRedBg + " HIGH " + cReset
	case "medium":
		return "\033[30m" + cYellowBg + " MED  " + cReset
	case "low":
		return cWhite + cBlueBg + " LOW  " + cReset
	default:
		return cWhite + cGrayBg + " INFO " + cReset
	}
}

func colorPad(text, color string, width int) string {
	pad := width - len(text)
	if pad < 0 {
		pad = 0
	}
	return color + text + cReset + strings.Repeat(" ", pad)
}

// ── Types ───────────────────────────────────────────────────────────

type Target struct {
	Host  string
	Ports []int
}

type PortResult struct {
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Open        bool              `json:"open"`
	TLS         bool              `json:"tls"`
	StatusCode  int               `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodySnippet string            `json:"body_snippet,omitempty"`
	Server      string            `json:"server,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

type ServiceMatch struct {
	Host      string          `json:"host"`
	Port      int             `json:"port"`
	Service   string          `json:"service"`
	Version   string          `json:"version,omitempty"`
	Severity  string          `json:"severity"`
	BaseURL   string          `json:"base_url"`
	MatchPath string          `json:"match_path"`
	MatchBody json.RawMessage `json:"match_body,omitempty"`
}

type Finding struct {
	Category string      `json:"category"`
	Title    string      `json:"title"`
	Detail   string      `json:"detail,omitempty"`
	Severity string      `json:"severity"`
	Data     interface{} `json:"data,omitempty"`
}

type EnumResult struct {
	Service    string                 `json:"service"`
	Host       string                 `json:"host"`
	Port       int                    `json:"port"`
	BaseURL    string                 `json:"base_url"`
	Version    string                 `json:"version,omitempty"`
	AuthStatus string                 `json:"auth_status"`
	RiskLevel  string                 `json:"risk_level"`
	Details    []string               `json:"details,omitempty"`
	Findings   []Finding              `json:"findings"`
	RawData    map[string]interface{} `json:"raw_data,omitempty"`
}

type ScanReport struct {
	Tool         string         `json:"tool"`
	ToolVersion  string         `json:"version"`
	Target       string         `json:"target"`
	Timestamp    string         `json:"timestamp"`
	PortsScanned int            `json:"ports_scanned"`
	OpenPorts    []PortResult   `json:"open_ports"`
	Services     []ServiceMatch `json:"services"`
	EnumResults  []EnumResult   `json:"enum_results"`
	Summary      Summary        `json:"summary"`
}

type Summary struct {
	TotalTargets  int    `json:"total_targets"`
	OpenPorts     int    `json:"open_ports"`
	ServicesFound int    `json:"services_found"`
	Unauthed      int    `json:"unauthenticated"`
	TotalFindings int    `json:"total_findings"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	Info          int    `json:"info"`
	Duration      string `json:"scan_duration"`
}

// ── HTTP ────────────────────────────────────────────────────────────

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}
}

func httpGET(c *http.Client, url string) (int, map[string]string, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "aimap/1.0 (security-research)")
	req.Header.Set("Accept", "application/json, text/html, */*")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	hdrs := make(map[string]string)
	for k, v := range resp.Header {
		hdrs[k] = strings.Join(v, ", ")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, hdrs, body, nil
}

// ── JSON ────────────────────────────────────────────────────────────

func parseJSON(data []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	return m, json.Unmarshal(data, &m)
}

func parseJSONArray(data []byte) ([]interface{}, error) {
	var a []interface{}
	return a, json.Unmarshal(data, &a)
}

func jStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func jHas(m map[string]interface{}, key string) bool { _, ok := m[key]; return ok }

func jMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]interface{}); ok {
			return sub
		}
	}
	return nil
}

func jArray(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			return arr
		}
	}
	return nil
}

func jFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}

// ── IP / target parsing ─────────────────────────────────────────────

func parseTargets(input string) []string {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "/") {
		return expandCIDR(input)
	}
	return []string{input}
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ── Formatting ──────────────────────────────────────────────────────

func fmtNum(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	rem := len(s) % 3
	if rem > 0 {
		b.WriteString(s[:rem])
	}
	for i := rem; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "~"
}

// ── Worker pool ─────────────────────────────────────────────────────

type WorkerPool struct{ sem chan struct{} }

func newPool(n int) *WorkerPool    { return &WorkerPool{sem: make(chan struct{}, n)} }
func (p *WorkerPool) Acquire()     { p.sem <- struct{}{} }
func (p *WorkerPool) Release()     { <-p.sem }
