package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("target", "", "Single target (IP, hostname, or CIDR)")
	list := flag.String("list", "", "File containing list of targets (one per line)")
	ports := flag.String("ports",
		"8080,8443,11434,8000,3000,6333,19530,8888,8501,9090,5000,4000,7860,3001",
		"Comma-separated ports to scan")
	timeout := flag.Duration("timeout", 5*time.Second, "Connection timeout")
	threads := flag.Int("threads", 20, "Concurrent scan threads")
	output := flag.String("o", "", "JSON report output file")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *target == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}

	var hosts []string
	if *target != "" {
		hosts = parseTargets(*target)
	}
	if *list != "" {
		f, err := os.Open(*list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot open target list: %v\n", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				hosts = append(hosts, parseTargets(line)...)
			}
		}
		f.Close()
	}

	if len(hosts) == 0 {
		printBanner()
		fmt.Println()
		fmt.Println("  Usage:")
		fmt.Println("    aimap -target <ip|host|cidr> [flags]")
		fmt.Println("    aimap -list targets.txt [flags]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Printf("\n  Fingerprints: %d AI/ML services\n\n", len(Fingerprints))
		os.Exit(0)
	}

	var portList []int
	for _, p := range strings.Split(*ports, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			portList = append(portList, n)
		}
	}

	targets := make([]Target, len(hosts))
	for i, h := range hosts {
		targets[i] = Target{Host: h, Ports: portList}
	}

	startTime := time.Now()

	// ── Banner ───────────────────────────────────────────────────
	printBanner()

	// ── Phase 1: Port Scan ───────────────────────────────────────
	printPhase(1, "PORT DISCOVERY")
	fmt.Println()
	fmt.Printf("    Scanning %s (%s hosts)\n", *target, fmtNum(len(hosts)))

	portStrs := make([]string, len(portList))
	for i, p := range portList {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portStr := strings.Join(portStrs, ",")
	if len(portStr) > 55 {
		portStr = portStr[:52] + "..."
	}
	fmt.Printf("    Ports: %s\n", portStr)
	fmt.Printf("    Threads: %d\n", *threads)
	fmt.Println()

	var progress atomic.Int64
	total := int64(len(hosts)) * int64(len(portList))

	var stopCh chan struct{}
	if !*verbose {
		stopCh = startProgress(&progress, total)
	}

	openPorts := scanPorts(targets, *timeout, *threads, *verbose, &progress)

	if !*verbose {
		close(stopCh)
		time.Sleep(20 * time.Millisecond) // let goroutine exit
		finalizeProgress(int64(len(hosts)))
	}

	printOpenPorts(openPorts)

	if len(openPorts) == 0 {
		fmt.Printf("\n  %s No open ports — nothing to fingerprint.\n\n", yellow("[!]"))
		if *output != "" {
			rpt := buildReport(hosts, len(portList), openPorts, nil, nil, time.Since(startTime))
			writeJSON(rpt, *output)
		}
		return
	}

	// ── Phase 2: Fingerprinting ──────────────────────────────────
	printPhase(2, "AI SERVICE FINGERPRINTING")

	services := matchFingerprints(openPorts, *timeout, *verbose)

	if len(services) == 0 {
		fmt.Printf("\n  %s No AI/ML services identified on open ports.\n\n", yellow("[!]"))
		if *output != "" {
			rpt := buildReport(hosts, len(portList), openPorts, services, nil, time.Since(startTime))
			writeJSON(rpt, *output)
		}
		return
	}

	printFingerprints(services, len(openPorts))

	// ── Phase 3: Deep Enumeration ────────────────────────────────
	printPhase(3, "DEEP ENUMERATION")

	enumResults := runEnumerators(services, *timeout, *verbose)

	for _, er := range enumResults {
		printServiceCard(er)
	}

	// ── Summary ──────────────────────────────────────────────────
	printSummaryTable(enumResults)

	rpt := buildReport(hosts, len(portList), openPorts, services, enumResults, time.Since(startTime))
	printStats(rpt)

	if *output != "" {
		writeJSON(rpt, *output)
	}

	fmt.Println()
}
