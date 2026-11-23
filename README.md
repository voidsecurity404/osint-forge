# osint-forge

**Graph-based OSINT & attack-surface reconnaissance for a single domain or IP.**

osint-forge takes one target, runs passive discovery and — only with your
explicit authorization — active probing, and assembles everything it finds into
a **live, cross-linked graph**: subdomains, IPs, open ports, services,
technologies, TLS certificates, ASNs, emails, archived URLs, security findings
and matched CVEs. The graph is rendered in an Obsidian-style view you can click
through, and exported to six formats (plus a full Obsidian vault).

It ships as a **Wails desktop app** and a **headless CLI** (`reconcli`) that
share the exact same scanning engine — the GUI for interactive investigation,
the CLI for automation, CI pipelines and continuous monitoring.

[![CI](https://github.com/voidsecurity404/osint-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/voidsecurity404/osint-forge/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-444)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> ⚠️ **Authorization is required.** Active scanning (nmap, HTTP probing,
> fuzzing, zone transfer, nuclei, screenshots) only runs when you explicitly
> assert that you are allowed to test the target. Use it **only** against assets
> you own or have written permission to assess. You are responsible for staying
> within scope and within the law.

---

## Table of contents

- [Quick start](#quick-start)
- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Data sources](#data-sources)
- [CVE engine](#cve-engine)
- [Reports & exports](#reports--exports)
- [Continuous monitoring (diffing)](#continuous-monitoring-diffing)
- [CLI usage](#cli-usage)
- [Configuration & API keys](#configuration--api-keys)
- [Safety model](#safety-model)
- [Where your data lives](#where-your-data-lives)
- [Requirements](#requirements)
- [Building](#building)
- [Project layout](#project-layout)
- [License & disclaimer](#license--disclaimer)

---

## Quick start

The simplest way to run the desktop app is the bundled launcher, **`start.sh`**.
It works from any shell (bash, zsh, fish) because it re-executes itself under
bash, and it resolves its own location — so you can run it from anywhere.

```sh
git clone https://github.com/voidsecurity404/osint-forge.git
cd osint-forge

./start.sh              # run the app (builds the binary on first run if missing)
```

`start.sh` understands a few subcommands:

| Command            | What it does                                                        |
| ------------------ | ------------------------------------------------------------------- |
| `./start.sh`       | Run the prebuilt app. If no binary exists yet, it builds one first. |
| `./start.sh run`   | Same as above (explicit).                                           |
| `./start.sh dev`   | Run in **dev mode** with hot reload (needs Go + the Wails CLI).     |
| `./start.sh build` | (Re)build the production binary into `build/bin/osint-forge`.       |
| `./start.sh help`  | Print the built-in help.                                            |

Under the hood it builds with the `webkit2_41` tag (required on Arch/Omarchy,
where only `webkit2gtk-4.1` exists) and, if [`mise`](https://mise.jdx.dev) is
installed, uses it to put the Go toolchain and the Wails CLI on `PATH`. Running
a prebuilt binary needs none of that — only building does.

Prefer `make`? See [Building](#building). Want the headless scanner instead of
the GUI? Jump to [CLI usage](#cli-usage).

---

## What it does

- **Single input, full picture.** Give it `example.com` or `203.0.113.10`; it
  normalizes URLs, ports and IPv6 brackets for you, then fans out across every
  applicable source.
- **Passive OSINT by default.** DNS, RDAP/WHOIS, Certificate Transparency,
  passive DNS, the Wayback Machine, ASN mapping, subdomain brute-force and
  (with keys) Shodan, Censys, GitHub code search — none of which send a single
  packet to the target.
- **Authorized active probing.** Port and service scanning (nmap, with a
  pure-Go fallback), HTTP/TLS fingerprinting, content fuzzing, robots/sitemap
  harvesting, web-security checks, subdomain-takeover detection, nuclei
  templates and headless screenshots.
- **Automatic CVE matching.** Discovered service and technology versions are
  matched against the NVD, then enriched with CISA **KEV** (known-exploited)
  and FIRST **EPSS** (exploitation probability) so you see what actually
  matters first.
- **A graph you can read.** Everything becomes nodes and edges rendered with
  Cytoscape.js; click any node for its details, open URLs/CVEs, or fetch a live
  page's raw HTML from the detail panel.
- **Shareable output.** Export to JSON, HTML, Markdown, CSV, SARIF, or a
  cross-linked Obsidian vault.
- **Change detection.** Re-scan a target and get a diff of what appeared or
  disappeared since last time — new subdomains, new open ports, new CVEs.

---

## How it works

Every capability is a `core.Source` — a small, self-contained unit of
reconnaissance. The pipeline runs them in **four ordered stages**, and within a
stage every source runs **concurrently**, streaming graph deltas to the UI as
they arrive:

```
  Discovery  ─▶  Resolve  ─▶  Probe  ─▶  Enrich
  (passive:     (names →     (active:     (derived: CVEs,
   find names)   IPs)         scan what    reports, breach
                              was found)    checks)
```

- **Discovery** — passive sources find names and infrastructure (DNS, crt.sh,
  OTX, brute-force, …).
- **Resolve** — discovered hostnames are resolved to IPs so active probing has
  concrete targets.
- **Probe** — active sources hit what was found (port scan, HTTP, reverse-IP,
  zone transfer, …).
- **Enrich** — derived analysis runs last (CVE matching, TLS checks, fuzzing,
  takeover, breach lookups, report data).

The central data model (`internal/graph`) is a concurrency-safe graph. Node IDs
are deterministic (e.g. `ip:203.0.113.10`), so the *same* entity discovered by
different sources collapses into a single node instead of duplicating. A panic
in any one source is recovered and logged — it **never** crashes the scan, and
the remaining sources carry on.

The desktop GUI and the `reconcli` CLI are two front-ends over this one engine,
so a scan behaves identically whether you run it interactively or in CI.

---

## Data sources

### Passive — no packets reach the target (always run)

| Source            | What it finds                                               | Key required            |
| ----------------- | ----------------------------------------------------------- | ----------------------- |
| **DNS**           | A/AAAA/MX/NS/TXT/CNAME records + reverse DNS                | –                       |
| **RDAP / WHOIS**  | Registration data via RDAP (modern WHOIS)                   | –                       |
| **crt.sh**        | Subdomains from Certificate Transparency logs               | –                       |
| **ASN (Cymru)**   | IP → Autonomous System + routed BGP prefix (Team Cymru DNS) | –                       |
| **Wayback**       | Historical URLs/endpoints from the Internet Archive         | –                       |
| **OTX**           | Passive-DNS hostnames & IPs (AlienVault OTX)                | –                       |
| **Brute-force**   | Common subdomains via a bundled 5000-entry wordlist         | –                       |
| **Reverse-IP**    | Other domains & subdomains on the same IP                   | SecurityTrails / VT     |
| **Shodan**        | Open ports, service banners, extra hostnames                | Shodan                  |
| **Censys**        | Host services with product/version + DNS names              | Censys (ID + secret)    |
| **GitHub**        | Public code mentioning the target (leaked configs/keys)     | GitHub token            |

> ASN uses Team Cymru's DNS service specifically to avoid leaking target IPs in
> a cleartext HTTP request to a third party. Keyless sources work out of the
> box; keyed sources are simply skipped when their key is absent.

### Active — requires authorization (consent)

| Source                | What it does                                                             | Needs                 |
| --------------------- | ----------------------------------------------------------------------- | --------------------- |
| **nmap**              | Service/version detection; maps ports, services & CPEs                   | `nmap` on PATH        |
| **Port scan**         | Pure-Go fallback scanner with banner grabbing                           | –                     |
| **HTTP probe**        | Live URL, status, page title, detected technologies                     | –                     |
| **TLS checks**        | Flags TLS 1.0/1.1 and expired / soon-expiring certificates              | –                     |
| **robots / sitemap**  | Harvests server-declared paths (zero false positives)                   | –                     |
| **Content fuzzing**   | Path/content discovery with bundled SecLists, soft-404 aware            | –                     |
| **Web checks**        | CORS misconfig, exposed `.git`/`.env`, directory listing, risky methods | –                     |
| **Takeover**          | Subdomain-takeover detection via dangling-CNAME fingerprints            | –                     |
| **Favicon hash**      | Shodan-style MurmurHash3 favicon hash                                   | –                     |
| **nuclei**            | Runs ProjectDiscovery nuclei templates against live hosts               | `nuclei` on PATH      |
| **Screenshots**       | Headless-browser screenshots of live web hosts                          | Chromium on PATH      |
| **Zone transfer**     | Attempts AXFR against the domain's name servers                         | toggle                |
| **HIBP**              | Checks harvested emails against Have I Been Pwned breaches               | HIBP key              |

Bundled wordlists (SecLists subsets) are **embedded in the binary**, so content
fuzzing and brute-forcing work with no extra downloads. Web checks verify
response content before reporting, keeping findings high-confidence.

---

## CVE engine

`internal/cve` turns discovered software into a prioritized vulnerability list:

1. **Match** — service/technology versions (from nmap, Shodan, Censys, HTTP
   fingerprinting) are converted to CPE and queried against the **NVD 2.0 API**;
   keyword fallback handles products without a clean CPE.
2. **Cache** — every query is cached in a local **SQLite** database (pure-Go
   driver — no cgo, no system SQLite needed) with a freshness TTL, so repeat
   scans are fast and respectful of NVD's rate limits.
3. **Enrich & prioritize** — each CVE is annotated with:
   - **CISA KEV** — is it a *known-exploited* vulnerability?
   - **FIRST EPSS** — the probability it will be exploited in the next 30 days.
   - **CVSS** severity.

   The most severe matches are kept per service to keep the graph readable.

An NVD API key is optional — it only raises the request rate limit.

---

## Reports & exports

From the GUI's export menu or the CLI's output flags:

| Format       | Best for                                                    |
| ------------ | ---------------------------------------------------------- |
| **JSON**     | Machine processing / piping into other tools               |
| **HTML**     | A standalone, styled report you can hand to a stakeholder  |
| **Markdown** | Wiki pages, tickets, pull-request write-ups                |
| **CSV**      | Findings + CVEs in a spreadsheet                           |
| **SARIF**    | CI / code-scanning dashboards (SARIF 2.1.0)                |
| **Obsidian** | A full vault: one cross-linked note per node (`[[wikilinks]]`) |

The Obsidian export reproduces the same relationships as the in-app graph, so
you can explore findings in Obsidian's own graph view.

---

## Continuous monitoring (diffing)

Every scan is saved as a per-target snapshot. Re-scan later and osint-forge
diffs against the previous run, reporting exactly **what changed** — new
subdomains, newly opened ports, freshly matched CVEs, or assets that
disappeared. This turns a one-off recon tool into a lightweight attack-surface
monitor. In the CLI, add `-diff`; in the GUI it's a button.

---

## CLI usage

The headless `reconcli` shares the full engine and needs only a Go toolchain to
build (no GUI dependencies):

```sh
make cli        # → build/bin/reconcli
```

```sh
reconcli example.com                     # passive OSINT only
reconcli -active example.com             # + active probing (authorized targets only)
reconcli -active -diff example.com       # save a snapshot and print what changed
reconcli -active -md report.md -sarif report.sarif example.com
reconcli -active -obsidian ./vault example.com
reconcli -timeout 15m -active example.com
reconcli -quiet -json out.json example.com
reconcli -no-scope -active example.com   # disable the scope guard (DANGEROUS)
```

Flags:

| Flag                 | Meaning                                                      |
| -------------------- | ----------------------------------------------------------- |
| `-active`            | Also run active probing (authorized targets only)           |
| `-diff`              | Save this scan and print the diff vs. the previous run      |
| `-timeout <dur>`     | Overall scan budget, e.g. `30m` (0 = config default)        |
| `-quiet`             | Suppress per-node streaming output                          |
| `-json / -md / -csv / -sarif / -html <path>` | Write a report in that format          |
| `-obsidian <dir>`    | Export an Obsidian vault to the directory                   |
| `-no-scope`          | Disable the active-probing scope guard (**dangerous**)      |

---

## Configuration & API keys

Settings and API keys live in a JSON file under the XDG config directory:

```
~/.config/osint-forge/config.json
```

Edit them from the GUI's settings panel, or directly on disk (written with
`0600` permissions). **No keys are stored in this repository**, and a missing
key simply disables the source that needs it — everything keyless still runs.

| Setting                 | Unlocks / controls                                         |
| ----------------------- | ---------------------------------------------------------- |
| `shodan_key`            | Shodan passive host data                                   |
| `censys_id` + `censys_secret` | Censys Search v2                                     |
| `securitytrails_key`    | Reverse-IP / passive DNS                                   |
| `virustotal_key`        | Reverse-IP / passive DNS                                   |
| `github_token`          | GitHub code search (leaked-secret dorking)                 |
| `hibp_key`              | Have I Been Pwned breach checks                            |
| `nvd_key`               | Higher NVD rate limit (optional)                           |
| `nmap_args`             | Extra nmap flags (default `-sV -T4 --top-ports 1000`)      |
| `fuzz_enabled` / `fuzz_wordlist` | Content fuzzing + wordlist selection             |
| `subdomain_bruteforce` / `zone_transfer` | DNS brute-force / AXFR toggles           |
| `status_codes`          | Which HTTP status codes to record (`2xx,3xx,401,403,…`)    |
| `nuclei` / `screenshots` | Enable nuclei / Chromium screenshots (when the binary is on PATH) |
| `max_concurrent`        | Worker-pool size                                           |

---

## Safety model

- **Scope guard** (`scope_strict`, **on by default**) — active probes only hit
  the target's registrable domain, its subdomains, and discovered IPs. The
  unrelated hostnames that reverse-IP, shared hosting and certificate SANs
  routinely surface are **never** actively scanned, because they belong to other
  organizations. You can add extra in-scope domains/CIDRs via `extra_scope`.
- **Consent gate** — the entire active-probing source set is excluded unless you
  assert authorization (`consent` in the GUI, `-active` in the CLI).
- **Scan budget** (`scan_timeout_min`) — a hard overall time limit; a scan can
  never run unbounded.
- **Polite rate limiting** (`rate_limit_per_host`) — caps requests/sec per host
  for fuzzing and brute-forcing.
- **Crash isolation** — a panic in any single source is recovered; the rest of
  the scan continues.

---

## Where your data lives

Nothing you scan is written into the project directory. All runtime state goes
to your user directories:

| Data                       | Location                                      |
| -------------------------- | --------------------------------------------- |
| Settings & API keys        | `~/.config/osint-forge/config.json`           |
| CVE cache (SQLite)         | `~/.cache/osint-forge/cve.sqlite`             |
| Scan history / snapshots   | `~/.cache/osint-forge/history/<target>/`      |
| Screenshots                | `~/.cache/osint-forge/…`                       |

(Exact base paths follow your OS's XDG / cache conventions.)

---

## Requirements

**To run the prebuilt app or the CLI:** nothing — they're self-contained static
binaries. SQLite is a pure-Go driver, and all wordlists are embedded.

**To build the desktop GUI:**

- [Go](https://go.dev) **1.26+**
- The [Wails v2 CLI](https://wails.io) — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- `webkit2gtk-4.1` development libraries (Linux)

**Optional external tools** (auto-detected on `PATH`, each feature is skipped if
its tool is missing):

- `nmap` — richer service/version scanning
- `nuclei` — template-based vulnerability checks
- A Chromium-based browser — headless screenshots

---

## Building

```sh
make gui      # wails build -tags webkit2_41  → desktop app
make run      # wails dev   -tags webkit2_41  → hot-reload dev mode
make cli      # build/bin/reconcli            → headless CLI (no system deps)
make test     # go test ./internal/...
make vet      # go vet ./internal/... ./cmd/...
make fmt      # gofmt
make tidy     # go mod tidy
```

Or use the launcher: `./start.sh build`, `./start.sh dev`, `./start.sh run`.

---

## Project layout

```
osint-forge/
├── app.go                 # Wails-bound backend API (methods callable from JS)
├── main.go                # Wails app bootstrap
├── start.sh               # cross-shell launcher (run / dev / build)
├── cmd/reconcli/          # headless CLI over the same engine
├── internal/
│   ├── core/              # pipeline, stages, target parsing, scope guard
│   ├── graph/             # concurrency-safe entity graph + Obsidian export
│   ├── recon/             # passive OSINT sources
│   ├── scan/              # active probing sources (+ embedded wordlists)
│   ├── cve/               # NVD matching, SQLite cache, KEV + EPSS enrichment
│   ├── report/            # JSON / HTML / Markdown / CSV / SARIF renderers
│   └── history/           # per-target snapshots + diffing
└── frontend/              # Svelte + Cytoscape.js UI
```

---

## License & disclaimer

Released under the [MIT License](LICENSE).

**Disclaimer.** osint-forge is intended for authorized security assessment,
research and education. Scanning or probing systems you do not own or have
explicit permission to test may be illegal. The authors accept no liability for
misuse. Always stay in scope, and keep active probing behind the consent gate.
