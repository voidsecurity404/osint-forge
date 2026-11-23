# osint-forge

A graph-based OSINT & attack-surface reconnaissance tool. It takes a single
domain or IP, runs passive discovery and (with consent) active probing, and
builds a live, cross-linked graph of everything it finds — subdomains, IPs,
ports, services, technologies, certificates, ASNs, emails, archived URLs,
security findings and matched CVEs — rendered in an Obsidian-like view.

> ⚠️ Active scanning (nmap, HTTP probing, fuzzing, zone transfer, nuclei,
> screenshots) is only performed when you explicitly assert authorization. Use
> it **only** against assets you are allowed to test.

## Architecture

Every capability is a `core.Source` that runs in one of four ordered stages
(Discovery → Resolve → Probe → Enrich); within a stage sources run
concurrently and stream graph deltas to the UI. A panic in any one source is
recovered and never crashes the app.

- `internal/recon` — passive OSINT: DNS, RDAP/WHOIS, crt.sh, OTX, Wayback,
  Team Cymru ASN, subdomain brute-force, reverse-IP (SecurityTrails/VirusTotal),
  Shodan, Censys, GitHub code search, HIBP.
- `internal/scan` — active probing: nmap (+ pure-Go fallback with banner
  grabbing), HTTP fingerprinting, TLS checks, robots/sitemap, content fuzzing,
  web-security checks, subdomain-takeover, favicon hashing, nuclei, screenshots.
- `internal/cve` — matches discovered service/tech versions to NVD CVEs, cached
  in SQLite, enriched with CISA KEV and FIRST EPSS.
- `internal/graph` — the concurrency-safe entity graph and Obsidian export.
- `internal/report` — JSON, HTML, Markdown, CSV and SARIF reports.
- `internal/history` — per-target scan snapshots and diffing (monitoring).

## Safety features

- **Scope guard** (`scope_strict`, on by default): active probes only hit the
  target's registrable domain, its subdomains and discovered IPs — never the
  unrelated hostnames that reverse-IP / shared hosting / cert SANs surface.
- **Scan budget** (`scan_timeout_min`): a hard overall time limit.
- **Polite rate limiting** (`rate_limit_per_host`): caps requests/sec per host.

## Build

The desktop app is built with [Wails](https://wails.io) and needs
`webkit2gtk-4.1`:

```sh
make gui      # wails build -tags webkit2_41
make run      # wails dev   -tags webkit2_41
```

The headless CLI and the test suite need only a Go toolchain:

```sh
make cli      # build/bin/reconcli
make test
make vet
```

## CLI

```sh
reconcli example.com                 # passive only
reconcli -active example.com         # + active probing (authorized targets only)
reconcli -active -diff example.com   # save a snapshot and show what changed
reconcli -active -md report.md -sarif report.sarif example.com
reconcli -timeout 15m -active example.com
reconcli -no-scope ...               # disable the scope guard (dangerous)
```

Optional API keys and tool toggles are stored in the config file under the XDG
config dir (`~/.config/osint-forge/config.json`) and set from the GUI's
settings panel: Shodan, Censys (id+secret), HIBP, GitHub token,
SecurityTrails, VirusTotal, NVD, plus `nuclei`/`screenshots` (run when the
`nuclei` / a Chromium binary is on `PATH`).
