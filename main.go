package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	// Accept positional arg as target
	if *target == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}

	// Build host list
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
		fmt.Println(bold("aimap") + " v1.0.0 -- AI Infrastructure Scanner")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  aimap -target <ip|host|cidr> [flags]")
		fmt.Println("  aimap -list targets.txt [flags]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Printf("\nFingerprints: %d AI/ML services\n", len(Fingerprints))
		os.Exit(0)
	}

	// Parse ports
	var portList []int
	for _, p := range strings.Split(*ports, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			portList = append(portList, n)
		}
	}

	// Build scan targets
	targets := make([]Target, len(hosts))
	for i, h := range hosts {
		targets[i] = Target{Host: h, Ports: portList}
	}

	// ── Phase 0: Banner ──────────────────────────────────────────
	printBanner(hosts, portList)

	// ── Phase 1: Port scan ───────────────────────────────────────
	fmt.Printf("\n%s Phase 1: Port Scanning (%d host(s) x %d ports)\n",
		bold("[*]"), len(hosts), len(portList))
	openPorts := scanPorts(targets, *timeout, *threads, *verbose)
	fmt.Printf("%s Found %s open port(s)\n",
		green("[+]"), green(fmt.Sprintf("%d", len(openPorts))))

	if len(openPorts) == 0 {
		fmt.Printf("%s No open ports — nothing to fingerprint.\n", yellow("[!]"))
		if *output != "" {
			rpt := buildReport(hosts, len(portList), openPorts, nil, nil)
			writeJSON(rpt, *output)
		}
		return
	}

	// ── Phase 2: Fingerprinting ──────────────────────────────────
	fmt.Printf("\n%s Phase 2: Service Fingerprinting (%d fingerprints x %d ports)\n",
		bold("[*]"), len(Fingerprints), len(openPorts))
	services := matchFingerprints(openPorts, *timeout, *verbose)
	fmt.Printf("%s Identified %s AI/ML service(s)\n",
		green("[+]"), green(fmt.Sprintf("%d", len(services))))

	// ── Phase 3: Deep enumeration ────────────────────────────────
	var enumResults []EnumResult
	if len(services) > 0 {
		fmt.Printf("\n%s Phase 3: Deep Enumeration\n", bold("[*]"))
		enumResults = runEnumerators(services, *timeout, *verbose)
		fmt.Printf("%s Completed %d service enumeration(s)\n",
			green("[+]"), len(enumResults))
	}

	// ── Report ───────────────────────────────────────────────────
	rpt := buildReport(hosts, len(portList), openPorts, services, enumResults)
	printReport(rpt)

	if *output != "" {
		writeJSON(rpt, *output)
	}
}
