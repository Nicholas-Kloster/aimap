#!/usr/bin/env python3
"""
aimap-profile — target profiling + classification + disclosure-routing

Companion to aimap. Takes one target (IP or hostname), emits structured JSON
answering the questions every engagement repeats:
  - What is this target? (rDNS, WHOIS, ASN, TLS identity)
  - What category? (personal / institutional / commercial / research / honeypot)
  - What's the ethics posture? (HIPAA-adjacent? education? personal device? safe harbor?)
  - What's actually exposed? (active + passive fingerprint, discrepancy flags)
  - Who are its neighbors? (PTR /29, shared TLS SANs, CT namespace)
  - What's in the web surface? (embedded config, OpenAPI, framework)
  - Where do I disclose? (security.txt, MX, bounty program, SOC email)

Output is a single JSON blob for LLM / pipeline consumption.

Usage:
  aimap_profile.py --target <ip|host> [--mode fast|full] [-o out.json] [-v]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from typing import Any

import requests

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False


# ─── config ───────────────────────────────────────────────────────────────────

DEFAULT_UA = "aimap-profile/0.1 (passive recon; n15647931@gmail.com)"
HTTP_TIMEOUT = 8
NMAP_TIMEOUT = 120

# Hostname keyword → category hints
CATEGORY_HINTS = {
    "personal_device": ["airport", "timecapsule", "printer", "camera", "webcam", "synology", "qnap",
                        "hp-print", "raspberrypi", "home-nas", "labview", "nest", "ring.com"],
    "clinical_hipaa": ["uhmc", "sbuh", "sbmed", "epic", "cerner", "meditech", "athena", "careconnect",
                       "apollo", "ascom", "clindev", "clinprd", "medicine.edu", "hospital", "clinic",
                       "patient", "ehr", "phi", "radiology", "pathology"],
    "education": ["edu", ".ac.", "cs.", "student", "grade", "grading", "cse356", "bio.sunysb", "compas",
                  "homework", "course", "lecture", "library"],
    "commercial_staging": ["stg-", "staging", "dev.", "-dev.", "preprod", "pre-prod", "qa.",
                           "demo.", "beta.", "sandbox."],
    "research_lab": ["res-", "lab-", "labs.", "hpc", "cluster", "compute-", "gpu-",
                     "datascience", "quantum", "nlp", "ai-", "ml-", "bioinfo", "genomics",
                     "cybercardia", "cardia", "picasso", "hail", "scire", "wings.cs", "hlab",
                     "netsys", "lunr", "somas", "chem", "physics", "astro"],
    "honeypot_signal": ["canary", "honey", "opencanary", "cowrie", "tpot"],
}

# Service-banner keywords → category hints (from Shodan services)
SERVICE_BANNER_HINTS = {
    "personal_device": ["AirPort", "Time Capsule", "Apple Filing Protocol", "AFP",
                        "LabVIEW", "National Instruments", "NI Web-based", "TightVNC",
                        "Embedthis-http", "pc-station", "RealVNC",
                        "Synology", "QNAP", "OpenWrt", "DD-WRT", "HP LaserJet"],
    "honeypot_signal": ["Cowrie", "Canary", "Conpot", "T-Pot"],
}

# Product-hostname patterns that imply commercial SaaS staging/dev even on generic cloud rDNS
COMMERCIAL_CLOUD_PATTERN = re.compile(
    r"(agent|api|app|backend|chat|ai|llm|gpt|staging|dev|stg|prod|platform)\."
    r"[a-z0-9-]+\.(ai|io|app|dev|cloud|co|com|net)$", re.I
)

# Cloud-provider rDNS suffixes — signal "real hostname elsewhere"
CLOUD_RDNS_SUFFIXES = ("compute.amazonaws.com", "colocrossing.com", "googleusercontent.com",
                       "azure.com", "digitalocean.com", "linode.com", "oraclecloud.com",
                       "hetzner.de", "racknerd.com", "ovh.net")

# Impossible service combinations → honeypot score contributors
HONEYPOT_COMBOS = [
    ({"GlobalProtect", "Ivanti"}, 3),
    ({"FortiGate", "Asus"}, 3),       # mismatched cert issuer+subject
    ({"Cisco", "Fortinet"}, 2),
    ({"Ivanti", "Pulse"}, 1),
    ({"ASA", "F5"}, 2),
]

# Known bounty / disclosure program hints (public)
BOUNTY_HINTS = {
    "hackerone.com": "HackerOne program",
    "bugcrowd.com": "Bugcrowd program",
    "intigriti.com": "Intigriti program",
}


# ─── helpers ──────────────────────────────────────────────────────────────────

def run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def safe_get(url: str, **kw) -> requests.Response | None:
    try:
        return requests.get(url, timeout=HTTP_TIMEOUT, verify=False,
                            headers={"User-Agent": DEFAULT_UA}, **kw)
    except requests.RequestException:
        return None


# ─── module 1: identity ───────────────────────────────────────────────────────

def mod_identity(target: str) -> dict[str, Any]:
    """rDNS, forward DNS, WHOIS org, ASN, geo hint."""
    out: dict[str, Any] = {"input": target, "is_ip": is_ip(target)}

    if out["is_ip"]:
        ip = target
        rc, rdns, _ = run(["dig", "+short", "-x", ip], timeout=10)
        out["rdns"] = [l for l in rdns.strip().split("\n") if l]
        out["forward_dns"] = None
    else:
        out["rdns"] = None
        rc, fwd, _ = run(["dig", "+short", target, "A"], timeout=10)
        out["forward_dns"] = [l for l in fwd.strip().split("\n") if l and not l.startswith(";")]
        ip = out["forward_dns"][0] if out["forward_dns"] else None

    out["resolved_ip"] = ip

    if ip:
        rc, whois_out, _ = run(["whois", ip], timeout=20)
        org = re.search(r"^OrgName:\s*(.+)$", whois_out, re.M | re.I)
        net = re.search(r"^NetName:\s*(.+)$", whois_out, re.M | re.I)
        cidr = re.search(r"^CIDR:\s*(.+)$", whois_out, re.M | re.I)
        country = re.search(r"^Country:\s*(.+)$", whois_out, re.M | re.I)
        asn = re.search(r"^OriginAS:\s*(.+)$", whois_out, re.M | re.I)
        out["whois"] = {
            "org": (org.group(1).strip() if org else None),
            "netname": (net.group(1).strip() if net else None),
            "cidr": (cidr.group(1).strip() if cidr else None),
            "country": (country.group(1).strip() if country else None),
            "asn": (asn.group(1).strip() if asn else None),
        }

    return out


# ─── module 2+3: active + passive surface ─────────────────────────────────────

def mod_surface_active(ip: str) -> dict[str, Any]:
    """nmap top-100 with service detection. Short timeout, designed to be polite."""
    out: dict[str, Any] = {"method": "nmap", "ports": [], "raw_excerpt": None}
    rc, stdout, _ = run(
        ["nmap", "-Pn", "-T4", "--top-ports", "100", "-sV",
         "--version-intensity", "2", "--max-retries", "1",
         "--host-timeout", "45s", ip],
        timeout=NMAP_TIMEOUT,
    )
    if rc != 0 and rc != 124:
        out["error"] = f"nmap exit {rc}"
    for line in stdout.splitlines():
        m = re.match(r"^(\d+)/tcp\s+(\w+)\s+(\S+)(?:\s+(.*))?$", line.strip())
        if m:
            port, state, svc, ver = m.groups()
            if state in ("open", "filtered", "open|filtered"):
                out["ports"].append({
                    "port": int(port), "state": state,
                    "service": svc, "version": (ver or "").strip(),
                })
    out["raw_excerpt"] = "\n".join(stdout.splitlines()[-15:])
    return out


def mod_surface_passive(ip: str) -> dict[str, Any]:
    """Shodan historical record + quick CT check for hostname."""
    out: dict[str, Any] = {"method": "shodan", "available": HAS_SHODAN}
    if not HAS_SHODAN:
        out["error"] = "shodan python module not installed"
        return out
    try:
        api = shodan.Shodan(_shodan_key())
        host = api.host(ip)
        out["hostnames"] = host.get("hostnames", [])
        out["ports"] = host.get("ports", [])
        out["last_update"] = host.get("last_update")
        out["vulns"] = sorted(host.get("vulns", []))[:40]  # cap
        out["services"] = []
        for svc in host.get("data", []):
            out["services"].append({
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "product": svc.get("product"),
                "http_title": (svc.get("http") or {}).get("title"),
                "http_server": (svc.get("http") or {}).get("server"),
                "ssl_cert_subject": ((svc.get("ssl") or {}).get("cert") or {}).get("subject"),
                "ssl_cert_issuer": ((svc.get("ssl") or {}).get("cert") or {}).get("issuer"),
            })
    except Exception as e:
        out["error"] = f"shodan: {e}"
    return out


def _shodan_key() -> str:
    """Read key from env or from standard Shodan CLI config locations."""
    import os
    from pathlib import Path
    k = os.environ.get("SHODAN_API_KEY")
    if k: return k
    for p in (Path.home() / ".config" / "shodan" / "api_key",
              Path.home() / ".shodan" / "api_key"):
        if p.exists():
            return p.read_text().strip()
    raise RuntimeError("no Shodan key found (env SHODAN_API_KEY or ~/.config/shodan/api_key)")


# ─── module 4: discrepancy + honeypot scoring ─────────────────────────────────

def mod_discrepancy(active: dict, passive: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"honeypot_score": 0, "signals": []}
    active_ports = {p["port"] for p in active.get("ports", []) if p["state"] == "open"}
    passive_ports = set(passive.get("ports", []) or [])

    only_passive = passive_ports - active_ports
    only_active = active_ports - passive_ports
    if only_passive:
        out["signals"].append(f"Shodan sees {sorted(only_passive)} but active scan does not "
                              f"— possible rate-limit / ACL / defunct services")
    if only_active:
        out["signals"].append(f"Active sees {sorted(only_active)} not in Shodan — new exposure "
                              "or Shodan data stale")

    # honeypot heuristics from passive services
    svc_tags = set()
    for svc in passive.get("services", []) or []:
        for field in (svc.get("product"), svc.get("http_title"), svc.get("ssl_cert_subject"),
                      svc.get("ssl_cert_issuer"), svc.get("http_server")):
            if not field: continue
            s = str(field)
            for tag in ("GlobalProtect", "Ivanti", "FortiGate", "Asus", "Cisco", "Fortinet",
                        "Pulse", "ASA", "F5", "Canary", "Honeypot"):
                if tag.lower() in s.lower():
                    svc_tags.add(tag)
    out["tags_observed"] = sorted(svc_tags)
    for combo, score in HONEYPOT_COMBOS:
        if combo.issubset(svc_tags):
            out["honeypot_score"] += score
            out["signals"].append(f"honeypot combo detected: {sorted(combo)} (+{score})")
    if out["honeypot_score"] >= 3:
        out["verdict"] = "likely honeypot / deception asset"
    elif out["honeypot_score"] >= 1:
        out["verdict"] = "mixed signals; investigate before treating as real target"
    else:
        out["verdict"] = "no honeypot signals"
    return out


# ─── module 5: classification ─────────────────────────────────────────────────

# Priority order for primary_category — most-specific / highest-ethical-gate first
CATEGORY_PRIORITY = [
    "honeypot_signal",
    "clinical_hipaa",
    "personal_device",
    "commercial_staging",
    "commercial_saas",
    "research_lab",
    "education",
]


def mod_classification(identity: dict, passive: dict, active: dict,
                       discrepancy: dict | None = None) -> dict[str, Any]:
    """Heuristic category + ethics flags. Pulls from hostnames, TLS SANs, service banners."""
    # Assemble the haystack
    hostnames = list(passive.get("hostnames") or [])
    # pull TLS SAN CNs from Shodan service objects
    tls_sans: list[str] = []
    service_banners: list[str] = []
    for svc in (passive.get("services") or []):
        for field in ("product", "http_title", "http_server"):
            v = svc.get(field)
            if v: service_banners.append(str(v))
        for cert_field in ("ssl_cert_subject", "ssl_cert_issuer"):
            v = svc.get(cert_field)
            if isinstance(v, dict):
                cn = v.get("CN") or v.get("cn")
                if cn: tls_sans.append(str(cn))
            elif isinstance(v, str):
                tls_sans.append(v)

    hay = " ".join(filter(None, [
        " ".join(identity.get("rdns") or []),
        " ".join(identity.get("forward_dns") or []),
        " ".join(hostnames),
        " ".join(tls_sans),
        (identity.get("whois") or {}).get("org") or "",
        (identity.get("whois") or {}).get("netname") or "",
    ])).lower()

    categories_hit: list[str] = []
    for cat, keywords in CATEGORY_HINTS.items():
        if any(k.lower() in hay for k in keywords):
            categories_hit.append(cat)

    # Service-banner signals add categories that hostnames alone would miss
    banner_hay = " ".join(service_banners).lower()
    for cat, keywords in SERVICE_BANNER_HINTS.items():
        if any(k.lower() in banner_hay for k in keywords) and cat not in categories_hit:
            categories_hit.append(cat)

    # Honeypot override: skip commercial classification if deception signals present
    is_honeypot = bool(discrepancy and discrepancy.get("honeypot_score", 0) >= 3)
    if is_honeypot and "honeypot_signal" not in categories_hit:
        categories_hit.append("honeypot_signal")

    # Cloud-rDNS + any non-cloud TLS subject or product hostname = commercial hosted service
    # (suppress if honeypot — the fake SANs are part of the deception)
    rdns_joined = " ".join(identity.get("rdns") or []).lower()
    is_cloud_rdns = any(s in rdns_joined for s in CLOUD_RDNS_SUFFIXES)
    if is_cloud_rdns and not is_honeypot:
        non_cloud_found = False
        for h in hostnames + tls_sans:
            h_low = h.lower().lstrip("*.")
            # Skip the cloud-provider hostname itself
            if any(s in h_low for s in CLOUD_RDNS_SUFFIXES):
                continue
            # Any remaining real-domain hostname = product signal
            if "." in h_low and not h_low.endswith((".local", ".internal", ".lan")):
                non_cloud_found = True
                if COMMERCIAL_CLOUD_PATTERN.search(h):
                    if "commercial_staging" not in categories_hit:
                        categories_hit.append("commercial_staging")
                    break
        # Even without staging-subdomain pattern, cloud rDNS + real product TLS subject = commercial
        if non_cloud_found and "commercial_staging" not in categories_hit:
            categories_hit.append("commercial_saas")

    # Multi-tenant / shared-hosting signal: many SANs or many hostnames on single IP
    san_count = 0
    for svc in (passive.get("services") or []):
        cert = (svc.get("ssl_cert_subject") or {})
        # Shodan puts SAN count in the cert; approximate via hostname list length
    # Count distinct hostnames as proxy for SAN count
    distinct_hosts = len({h for h in hostnames + tls_sans if "." in h})
    multi_tenant = distinct_hosts >= 5

    ethics = []
    if "clinical_hipaa" in categories_hit:
        ethics.append("HIPAA-adjacent network — no active probing of clinical systems")
    if "education" in categories_hit:
        ethics.append("Educational institution — CFAA exposure; prefer institutional CSIRT disclosure")
    if "personal_device" in categories_hit:
        ethics.append("Personal/consumer device — archive or institutional CSIRT only")
    if "honeypot_signal" in categories_hit:
        ethics.append("Honeypot/deception signals — assume adversary logging")
    if "commercial_staging" in categories_hit:
        ethics.append("Commercial staging — check for published Safe Harbor before testing")
    if "commercial_saas" in categories_hit:
        ethics.append("Commercial cloud-hosted service — verify scope / bounty program before testing")
    if "research_lab" in categories_hit:
        ethics.append("Research lab / HPC — likely shared multi-user; scope carefully")
    if multi_tenant:
        ethics.append(f"Multi-tenant shared hosting — {distinct_hosts} distinct hostnames on one IP; "
                      "blast radius concern")

    # Primary category: follow priority order, not alphabetical
    primary = "unclassified"
    for cat in CATEGORY_PRIORITY:
        if cat in categories_hit:
            primary = cat
            break
    return {
        "primary_category": primary,
        "all_hits": categories_hit,
        "ethics_flags": ethics,
        "multi_tenant": multi_tenant,
        "distinct_hostnames": distinct_hosts,
    }


# ─── module 6: adjacency (PTR /29 + CT enum of apex) ──────────────────────────

def mod_adjacency(ip: str, identity: dict, passive: dict, fast: bool) -> dict[str, Any]:
    out: dict[str, Any] = {"ptr_sweep": [], "ct_namespaces": {}}

    # PTR sweep of /29 (8 IPs) around the target — fast, passive
    try:
        ipobj = ipaddress.ip_address(ip)
        base = int(ipobj) & ~7  # /29 boundary
        targets = [str(ipaddress.ip_address(base + i)) for i in range(8)]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            rdns_results = list(ex.map(lambda t: (t, run(["dig", "+short", "-x", t], 5)[1].strip()), targets))
        out["ptr_sweep"] = [
            {"ip": t, "rdns": r.split("\n")[0] if r else None}
            for t, r in rdns_results
        ]
    except Exception as e:
        out["ptr_error"] = str(e)

    # CT namespace enumeration (only if --full and we have a usable apex)
    if not fast:
        apex_candidates = set()
        for h in (passive.get("hostnames") or []) + (identity.get("rdns") or []):
            parts = h.strip(".").split(".")
            if len(parts) >= 2:
                apex_candidates.add(".".join(parts[-3:]) if len(parts) >= 3 else ".".join(parts[-2:]))
        for apex in list(apex_candidates)[:3]:  # cap at 3 apices
            try:
                r = safe_get(f"https://crt.sh/?q=%25.{apex}&output=json")
                if r and r.ok and r.text and r.text.strip().startswith("["):
                    data = r.json()
                    names = sorted({n.strip().lower()
                                    for row in data
                                    for n in (row.get("name_value") or "").split("\n")})
                    out["ct_namespaces"][apex] = {"count": len(names), "sample": names[:20]}
            except Exception:
                pass
    return out


# ─── module 7: web surface ────────────────────────────────────────────────────

def mod_web_surface(ip: str, hostnames: list[str]) -> dict[str, Any]:
    """Pull / and common paths over HTTPS + HTTP. Extract embedded config."""
    out: dict[str, Any] = {"probes": []}
    urls = [f"https://{ip}/", f"http://{ip}/"]
    for h in (hostnames or [])[:3]:
        urls.insert(0, f"https://{h}/")

    seen = set()
    for url in urls:
        if url in seen: continue
        seen.add(url)
        r = safe_get(url)
        if not r: continue
        body = r.text[:50_000]
        probe = {
            "url": url,
            "status": r.status_code,
            "server": r.headers.get("Server"),
            "title": (re.search(r"<title[^>]*>([^<]+)</title>", body, re.I) or [None, None])[1],
            "generator": (re.search(r'<meta name="generator" content="([^"]+)"', body, re.I)
                          or [None, None])[1],
        }
        # embedded configs
        for pat_name, pat in [
            ("nuxt_config", r"window\.__NUXT__\s*=\s*({[^<]+?});"),
            ("next_data", r'id="__NEXT_DATA__"[^>]*>([^<]+)</script>'),
            ("initial_state", r"window\.__INITIAL_STATE__\s*=\s*({[^<]+?});"),
        ]:
            m = re.search(pat, body)
            if m:
                probe.setdefault("embedded", {})[pat_name] = m.group(1)[:3000]
        # tokens / API keys / secrets
        secrets = re.findall(
            r"(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}"
            r"|ghp_[a-zA-Z0-9]+|eyJ[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{10,})",
            body,
        )
        if secrets:
            probe["secret_candidates"] = list(set(secrets))[:10]
        out["probes"].append(probe)
        if r.status_code in (200, 401, 403):
            break  # got a live response on this target, stop
    return out


# ─── module 8: disclosure routing ─────────────────────────────────────────────

def mod_disclosure(identity: dict, passive: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"security_txt": {}, "mx_checks": {}, "bounty_program": None}
    apex_candidates = set()
    for h in (passive.get("hostnames") or []) + (identity.get("rdns") or []):
        parts = h.strip(".").split(".")
        if len(parts) >= 2:
            apex_candidates.add(".".join(parts[-2:]))
    for apex in list(apex_candidates)[:3]:
        for proto in ("https", "http"):
            for path in ("/.well-known/security.txt", "/security.txt"):
                url = f"{proto}://{apex}{path}"
                r = safe_get(url, allow_redirects=True)
                if r and r.status_code == 200 and "Contact" in r.text[:2000]:
                    out["security_txt"][apex] = {"url": url, "body": r.text[:2000]}
                    break
    # MX for apex (is soc@ / security@ deliverable?)
    for apex in list(apex_candidates)[:3]:
        rc, mx, _ = run(["dig", "+short", "MX", apex], 6)
        out["mx_checks"][apex] = [l.strip() for l in mx.strip().split("\n") if l.strip()]
    # quick bounty scan: does any apex appear in hackerone/bugcrowd public program list?
    # (very rough — just a google-ish check avoided for now; placeholder)
    out["bounty_program"] = None
    # abuse contact from WHOIS
    whois_org = (identity.get("whois") or {}).get("org")
    if whois_org:
        out["whois_abuse_hint"] = f"Check WHOIS 'abuse' record for {whois_org}"
    return out


# ─── orchestrator ─────────────────────────────────────────────────────────────

def profile(target: str, mode: str = "fast", verbose: bool = False) -> dict:
    start = time.time()
    report: dict[str, Any] = {
        "meta": {"tool": "aimap-profile", "version": "0.1", "mode": mode,
                 "target_input": target, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    }
    if verbose: print("[*] identity", file=sys.stderr)
    report["identity"] = mod_identity(target)
    ip = report["identity"].get("resolved_ip")
    if not ip:
        report["error"] = "could not resolve IP"
        return report

    if verbose: print("[*] passive surface (shodan)", file=sys.stderr)
    report["surface_passive"] = mod_surface_passive(ip)

    if mode == "full":
        if verbose: print("[*] active surface (nmap)", file=sys.stderr)
        report["surface_active"] = mod_surface_active(ip)
    else:
        report["surface_active"] = {"method": "skipped", "reason": "fast mode"}

    if verbose: print("[*] discrepancy / honeypot scoring", file=sys.stderr)
    report["discrepancy"] = mod_discrepancy(report["surface_active"], report["surface_passive"])

    if verbose: print("[*] classification", file=sys.stderr)
    report["classification"] = mod_classification(report["identity"],
                                                  report["surface_passive"],
                                                  report["surface_active"],
                                                  report["discrepancy"])

    if verbose: print("[*] adjacency", file=sys.stderr)
    report["adjacency"] = mod_adjacency(ip, report["identity"], report["surface_passive"],
                                        fast=(mode == "fast"))

    if verbose: print("[*] web surface", file=sys.stderr)
    hostnames = (report["identity"].get("rdns") or []) + (report["surface_passive"].get("hostnames") or [])
    report["web_surface"] = mod_web_surface(ip, hostnames)

    if verbose: print("[*] disclosure routing", file=sys.stderr)
    report["disclosure"] = mod_disclosure(report["identity"], report["surface_passive"])

    report["meta"]["elapsed_seconds"] = round(time.time() - start, 1)
    return report


def main():
    p = argparse.ArgumentParser(description="aimap-profile — target classification + disclosure routing")
    p.add_argument("--target", required=True, help="IP or hostname")
    p.add_argument("--mode", choices=["fast", "full"], default="fast",
                   help="fast = passive only (Shodan + CT + DNS + web GET). "
                        "full = adds nmap and deeper CT enumeration.")
    p.add_argument("-o", "--output", help="write JSON to file (default: stdout)")
    p.add_argument("-v", "--verbose", action="store_true", help="stderr progress")
    args = p.parse_args()

    # suppress SSL warnings for passive probes
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    report = profile(args.target, mode=args.mode, verbose=args.verbose)
    out = json.dumps(report, indent=2, default=str)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"[ok] wrote {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
