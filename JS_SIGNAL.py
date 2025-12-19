#!/usr/bin/env python3
#Nusatenggara Timur Development Coded By Rolandino
import requests, re, time, json, hashlib, math
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from collections import defaultdict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

HEADERS = {

    
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),

    
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "application/javascript,text/javascript,application/json,"
        "application/manifest+json,"
        "image/avif,image/webp,image/apng,image/svg+xml,"
        "*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Accept-Charset": "utf-8",
    "Accept-Encoding": "gzip, deflate, br, zstd",

    
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",

    
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-User": "?1",

    
    "Sec-CH-UA": (
        '"Chromium";v="121", '
        '"Google Chrome";v="121", '
        '"Not;A=Brand";v="99"'
    ),
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Linux"',
    "Sec-CH-UA-Platform-Version": '"6.6.0"',
    "Sec-CH-UA-Full-Version": '"121.0.6167.85"',
    "Sec-CH-UA-Full-Version-List": (
        '"Chromium";v="121.0.6167.85", '
        '"Google Chrome";v="121.0.6167.85", '
        '"Not;A=Brand";v="99.0.0.0"'
    ),
    "Sec-CH-UA-Arch": '"x86"',
    "Sec-CH-UA-Bitness": '"64"',
    "Sec-CH-UA-WoW64": "?0",
    "Sec-CH-UA-Model": '""',
    "Sec-CH-UA-Form-Factors": '"Desktop"',

    
    "DNT": "1",
    "Sec-GPC": "1",

    
    "Connection": "keep-alive",
    "Keep-Alive": "timeout=5, max=1000",

    
    "Priority": "u=0, i",
    "TE": "trailers",

    
    "X-Client-Data": "CI22yQEIpLbJAQjBtskBCKmdygEIqKPKAQ==",
    "X-Requested-With": "XMLHttpRequest",
    "X-Chrome-Connected": "source=Chrome,mode=stable",
    "X-Chrome-UMA-Enabled": "1",

    
    "X-Goog-Experiment": "1",
    "X-Goog-Api-Client": "gl-js/20231201",
    "X-Goog-Encode-Response-If-Executable": "base64",

    
    "RTT": "50",
    "Downlink": "10",
    "ECT": "4g",
    "Viewport-Width": "1920",
    "Device-Memory": "8",

    
    "X-Research-Purpose": "security-research",
    "X-Research-Method": "passive-js-analysis",
    "X-Research-Scope": "public-resources-only",
    "X-Research-Policy": "google-vrp-compliant",

    
    "Referer": "https://www.google.com/",
    "Origin": "https://www.google.com",

    
    "Accept-CH": (
        "Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, "
        "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, "
        "Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List"
    ),
}

SIGNALS = {

    
    "HIGH": [
        
        "cc_latency_start_time",
        "cc_latency_end_time",
        "performance.now",
        "performance.timing",
        "navigationStart",
        "domContentLoadedEventEnd",
        "loadEventEnd",

        
        "document.visibilityState",
        "visibilitychange",
        "document.hasFocus",
        "pagehide",
        "pageshow",

        
        "pointerType",
        "pointerdown",
        "pointermove",
        "mousemove",
        "keydown",
        "keyup",

        
        "navigator.connection",
        "effectiveType",
        "rtt",
        "downlink",

        
        "indexedDB",
        "localStorage",
        "sessionStorage",
        "cookieEnabled",

        
        "deviceMemory",
        "hardwareConcurrency",
        "navigator.userAgentData",
    ],

    
    
    "MEDIUM": [
        
        "getBoundingClientRect",
        "getClientRects",
        "offsetWidth",
        "offsetHeight",
        "clientWidth",
        "clientHeight",

        
        "IntersectionObserver",
        "ResizeObserver",
        "MutationObserver",
        "PerformanceObserver",

        
        "requestAnimationFrame",
        "cancelAnimationFrame",
        "onwebkitanimationstart",
        "onanimationstart",
        "transitionend",

        
        "requestIdleCallback",
        "cancelIdleCallback",
        "queueMicrotask",

        
        "matchMedia",
        "prefers-reduced-motion",
        "prefers-color-scheme",

        
        "scrollX",
        "scrollY",
        "innerWidth",
        "innerHeight",
        "visualViewport",
    ],

    
    
    "INTERNAL": [
        
        "AF_initDataCallback",
        "AF_dataServiceRequests",
        "AF_initDataChunkQueue",
        "boq",
        "boq_identity",
        "boq_security",
        "boq_wiz",

        
        "experiment",
        "experiments",
        "expIds",
        "variation",
        "treatment",
        "dogfood",
        "trustedTester",
        "testOnly",
        "canary",
        "rollout",
        "fieldTrial",

        
        "x-client-data",
        "x-goog-visitor-id",
        "x-goog-authuser",
        "x-goog-pageid",
        "x-goog-ext",

        
        "cc_",
        "logEvent",
        "logError",
        "sendBeacon",
        "navigator.sendBeacon",
        "clearcut",
        "clearcutEndpoint",

        
        "authuser",
        "sessionIndex",
        "identifier",
        "signin",
        "logout",

        
        "spdx-license-identifier",
        "sourceMappingURL",
        "__webpack_require__",
        "__webpack_exports__",
    ],

    
    "LOW": [
        
        "featureFlag",
        "featureFlags",
        "enabledFeatures",
        "disabledFeatures",

        
        "env",
        "environment",
        "prod",
        "staging",
        "sandbox",
        "test",

        
        "buildLabel",
        "buildVersion",
        "commitHash",
        "releaseChannel",

        
        "telemetry",
        "metrics",
        "analytics",
        "instrumentation",
    ]
}

def entropy(s):
    if not s:
        return 0
    prob = [s.count(c)/len(s) for c in set(s)]
    return round(-sum(p * math.log2(p) for p in prob), 2)

def sha256(data):
    return hashlib.sha256(data.encode(errors="ignore")).hexdigest()

def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        return r.text
    except:
        return ""

def extract_js(html, base):
    soup = BeautifulSoup(html, "html.parser")
    js = set()
    for s in soup.find_all("script"):
        if s.get("src"):
            js.add(urljoin(base, s["src"]))
    return list(js)

def banner():
    console.print(
        Panel.fit(
            "[bold red]• SIMPLE GOOGLE SIGNAL SCANNER •[/]\n"
            "[green]– Team Crackers Communitiy[/]\n"
            "– Coded By Rolandino",
            border_style="red"
        )
    )

def main():
    banner()

    target = Prompt.ask(
        "[bold]Target URL[/]",
        default="https://target.com"
    ).strip()

    if not target.startswith("http"):
        console.print("[red]Url Harus https://[/]")
        return

    console.print(f"\n[cyan]Fetching Target:[/] {target}")
    html = fetch(target)

    js_files = extract_js(html, target)
    console.print(f"[green]JS Assets Found:[/] {len(js_files)}\n")

    results = []
    version_map = {}

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[bold]{task.description}"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Scanning Js Files", total=len(js_files))

        for js in js_files:
            content = fetch(js)
            if not content:
                progress.advance(task)
                continue

            h = sha256(content)
            version_map[js] = h

            for sev, keys in SIGNALS.items():
                for k in keys:
                    if re.search(rf"\b{re.escape(k)}\b", content):
                        results.append({
                            "severity": sev,
                            "signal": k,
                            "js": js,
                            "hash": h,
                            "entropy": entropy(k)
                        })
            progress.advance(task)
            time.sleep(0.05)

    
    table = Table(title="Detected Js Behavioral Signals")
    table.add_column("Severity", style="bold")
    table.add_column("Signal")
    table.add_column("Entropy")
    table.add_column("JS Source", overflow="fold")

    for r in results:
        color = "green"
        if r["severity"] == "MEDIUM":
            color = "yellow"
        if r["severity"] == "HIGH":
            color = "red"

        table.add_row(
            f"[{color}]{r['severity']}[/]",
            r["signal"],
            str(r["entropy"]),
            r["js"]
        )

    console.print(table)

    
    with open("signal_findings.json", "w") as f:
        json.dump(results, f, indent=2)

    
    groups = defaultdict(list)
    for js, h in version_map.items():
        groups[h].append(js)
    version_diff = {k: v for k, v in groups.items() if len(v) > 1}

    
    with open("VRP_REPORT.md", "w") as f:
        f.write(f"""# Google VRP – Passive JS Signal Analysis

## Target
{target}

## Summary
Passive JavaScript analysis identified internal telemetry and behavior-based signals.

## Findings
Total signals detected: {len(results)}

## Potential Impact
- User state inference
- Experiment / rollout detection
- Behavioral fingerprinting

## JS Versioning Diff
{json.dumps(version_diff, indent=2)}

## Methodology
Passive inspection only. No auth bypass, no exploitation.

## Severity
Medium (VRP Eligible)
""")

    console.print("\n[bold green]✔ Exported:[/]")
    console.print(" • signal_findings.json")
    console.print(" • VRP_REPORT.md")
    console.print(" • Js version Diff Completed")
    console.rule("[bold green]Selesai[/]")

if __name__ == "__main__":
    main()