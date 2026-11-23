// Command reconcli runs an osint-forge scan headlessly and prints the resulting
// graph. It shares the exact same pipeline and sources as the GUI, so it doubles
// as an end-to-end test harness and the seed of the Phase 5 CLI / DevOps mode.
//
// Usage:
//
//	reconcli [-active] <ip-or-domain>
//
// Without -active only passive OSINT runs (dns, whois, crt.sh, reverse-ip).
// With -active it also runs nmap/port-scan and HTTP probing — only use it
// against targets you are authorized to scan.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/cve"
	"osint-forge/internal/graph"
	"osint-forge/internal/history"
	"osint-forge/internal/recon"
	"osint-forge/internal/report"
	"osint-forge/internal/scan"
)

// stubEmitter prints live events to stderr.
type stubEmitter struct{ quiet bool }

func (e stubEmitter) EmitDelta(d graph.Delta) {
	if e.quiet {
		return
	}
	for _, n := range d.Nodes {
		fmt.Fprintf(os.Stderr, "  + [%s] %s\n", n.Type, n.Label)
	}
}
func (e stubEmitter) EmitLog(l core.LogLine) {
	fmt.Fprintf(os.Stderr, "  · %-12s %s\n", l.Source, l.Message)
}
func (e stubEmitter) EmitProgress(p core.Progress) {
	fmt.Fprintf(os.Stderr, "== %s (%d/%d) nodes=%d edges=%d\n", p.Phase, p.Done, p.Total, p.Nodes, p.Edges)
}

func main() {
	active := flag.Bool("active", false, "also run active scans (nmap/http) — authorized targets only")
	quiet := flag.Bool("quiet", false, "suppress per-node output")
	obsidian := flag.String("obsidian", "", "export the result as an Obsidian vault to this directory")
	timeout := flag.Duration("timeout", 0, "overall scan budget (e.g. 30m); 0 = config default")
	noScope := flag.Bool("no-scope", false, "disable the active-probing scope guard (DANGEROUS)")
	jsonOut := flag.String("json", "", "write a JSON report to this path")
	mdOut := flag.String("md", "", "write a Markdown report to this path")
	csvOut := flag.String("csv", "", "write a findings/CVE CSV to this path")
	sarifOut := flag.String("sarif", "", "write a SARIF 2.1.0 report to this path")
	htmlOut := flag.String("html", "", "write an HTML report to this path")
	doDiff := flag.Bool("diff", false, "save this scan and print what changed since the previous run")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: reconcli [-active] [-quiet] <ip-or-domain>")
		os.Exit(2)
	}

	cfg, _ := config.Load()
	t := core.ParseTarget(flag.Arg(0))
	if t.IP == "" && t.Domain == "" {
		fmt.Fprintln(os.Stderr, "invalid target")
		os.Exit(2)
	}

	g := graph.New()
	em := stubEmitter{quiet: *quiet}

	sources := []core.Source{
		recon.DNSSource{},
		recon.WhoisSource{Cfg: cfg},
		recon.CrtShSource{Cfg: cfg},
		recon.ResolveSource{},
		recon.ReverseIPSource{Cfg: cfg},
		recon.ASNSource{Cfg: cfg},
		recon.WaybackSource{Cfg: cfg},
		recon.OTXSource{Cfg: cfg},
		recon.BruteforceSource{Cfg: cfg},
		recon.ShodanSource{Cfg: cfg},
		recon.CensysSource{Cfg: cfg},
		recon.GitHubSource{Cfg: cfg},
	}
	if *active {
		sources = append(sources,
			scan.NmapSource{Cfg: cfg},
			scan.PortScanSource{Cfg: cfg},
			scan.HTTPSource{Cfg: cfg},
			scan.RobotsSource{Cfg: cfg},
			scan.FuzzSource{Cfg: cfg},
			scan.TLSSource{Cfg: cfg},
			scan.WebChecksSource{Cfg: cfg},
			scan.TakeoverSource{Cfg: cfg},
			scan.NucleiSource{Cfg: cfg},
			scan.ScreenshotSource{Cfg: cfg},
			recon.AXFRSource{Cfg: cfg},
			recon.HIBPSource{Cfg: cfg},
		)
	}
	if p, err := cve.DefaultPath(); err == nil {
		if store, err := cve.Open(p); err == nil {
			defer store.Close()
			sources = append(sources, cve.Source{
				Cfg: cfg, Store: store, Client: cve.NewClient(cfg.NVDKey, cfg.HTTPUserAgent),
			})
		}
	}

	pipe := core.NewPipeline(em, g, sources...)
	pipe.SetScope(core.NewScope(t, cfg.ScopeStrict && !*noScope, cfg.ExtraScope))

	ctx := context.Background()
	budget := *timeout
	if budget == 0 && cfg.ScanTimeoutMin > 0 {
		budget = time.Duration(cfg.ScanTimeoutMin) * time.Minute
	}
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	pipe.Run(ctx, t)

	// Final summary to stdout.
	snap := g.Snapshot()
	byType := map[graph.NodeType]int{}
	for _, n := range snap.Nodes {
		byType[n.Type]++
	}
	fmt.Printf("\n=== RESULT for %s ===\n", flag.Arg(0))
	var types []string
	for t := range byType {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Printf("%-12s %d\n", t, byType[graph.NodeType(t)])
	}
	fmt.Printf("TOTAL        %d nodes, %d edges\n", len(snap.Nodes), len(snap.Edges))

	if *obsidian != "" {
		n, err := g.ExportVault(*obsidian)
		if err != nil {
			fmt.Fprintln(os.Stderr, "obsidian export:", err)
			os.Exit(1)
		}
		fmt.Printf("Obsidian vault: %d notes → %s\n", n, *obsidian)
	}

	// Reports.
	writeReport := func(path string, data []byte, err error, label string) {
		if path == "" {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, label+" export:", err)
			return
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, label+" write:", err)
			return
		}
		fmt.Printf("%s → %s\n", label, path)
	}
	if *jsonOut != "" {
		data, err := report.JSON(snap)
		writeReport(*jsonOut, data, err, "JSON")
	}
	if *mdOut != "" {
		writeReport(*mdOut, []byte(report.Markdown(snap, flag.Arg(0))), nil, "Markdown")
	}
	if *csvOut != "" {
		data, err := report.CSV(snap)
		writeReport(*csvOut, data, err, "CSV")
	}
	if *sarifOut != "" {
		data, err := report.SARIF(snap, flag.Arg(0))
		writeReport(*sarifOut, data, err, "SARIF")
	}
	if *htmlOut != "" {
		writeReport(*htmlOut, []byte(report.HTML(snap, flag.Arg(0))), nil, "HTML")
	}

	// Monitoring: save this scan, then report what changed vs the previous one.
	if *doDiff {
		label := t.Domain
		if label == "" {
			label = t.IP
		}
		if _, err := history.Save(label, snap); err != nil {
			fmt.Fprintln(os.Stderr, "history save:", err)
		}
		diff, err := history.DiffLastTwo(label)
		if err != nil {
			fmt.Fprintln(os.Stderr, "diff:", err)
		} else if !diff.HasPrevious {
			fmt.Println("\n=== DIFF === (birinchi scan — taqqoslash uchun oldingi natija yo'q)")
		} else {
			fmt.Printf("\n=== DIFF vs %s ===\n", diff.Previous.Format("2006-01-02 15:04"))
			fmt.Printf("  +%d yangi, -%d yo'qolgan\n", len(diff.Added), len(diff.Removed))
			for _, n := range diff.Added {
				fmt.Printf("  + [%s] %s\n", n.Type, n.Label)
			}
			for _, n := range diff.Removed {
				fmt.Printf("  - [%s] %s\n", n.Type, n.Label)
			}
		}
	}
}
