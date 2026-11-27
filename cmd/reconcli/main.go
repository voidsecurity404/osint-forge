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
	"os/signal"
	"sort"
	"strings"
	"syscall"
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
	fmt.Fprintf(os.Stderr, "== %s (%d/%d) узлов=%d связей=%d\n", p.Phase, p.Done, p.Total, p.Nodes, p.Edges)
}

func main() {
	active := flag.Bool("active", false, "также выполнить активное сканирование (nmap/http) — только для разрешённых целей")
	quiet := flag.Bool("quiet", false, "не выводить каждый найденный узел")
	obsidian := flag.String("obsidian", "", "экспортировать результат как хранилище Obsidian в эту папку")
	timeout := flag.Duration("timeout", 0, "общий лимит времени сканирования (например, 30m); 0 = из настроек")
	noScope := flag.Bool("no-scope", false, "отключить защиту области сканирования (ОПАСНО)")
	jsonOut := flag.String("json", "", "записать JSON-отчёт по этому пути")
	mdOut := flag.String("md", "", "записать Markdown-отчёт по этому пути")
	csvOut := flag.String("csv", "", "записать CSV с находками/CVE по этому пути")
	sarifOut := flag.String("sarif", "", "записать отчёт SARIF 2.1.0 по этому пути")
	htmlOut := flag.String("html", "", "записать HTML-отчёт по этому пути")
	doDiff := flag.Bool("diff", false, "сохранить сканирование и показать изменения с прошлого запуска")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "использование: reconcli [флаги] <ip-или-домен>   (флаги указываются ДО цели)")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		if flag.NArg() > 1 && strings.HasPrefix(flag.Arg(1), "-") {
			fmt.Fprintf(os.Stderr, "reconcli: %q указан после цели — флаги нужно писать ДО цели\n", flag.Arg(1))
		}
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err, "(используются настройки по умолчанию)")
	}
	t := core.ParseTarget(flag.Arg(0))
	if !t.Valid {
		fmt.Fprintf(os.Stderr, "неверная цель %q: укажите корректный IP-адрес или домен (например, 1.1.1.1 или example.com)\n", flag.Arg(0))
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
		scan.ParamSource{Cfg: cfg},
	}
	if *active {
		sources = append(sources,
			scan.NmapSource{Cfg: cfg},
			scan.PortScanSource{Cfg: cfg},
			scan.HTTPSource{Cfg: cfg},
			scan.WebPortsSource{Cfg: cfg},
			scan.RobotsSource{Cfg: cfg},
			scan.FuzzSource{Cfg: cfg},
			scan.TLSSource{Cfg: cfg},
			scan.WebChecksSource{Cfg: cfg},
			scan.TakeoverSource{Cfg: cfg},
			scan.BuiltinChecksSource{Cfg: cfg},
			scan.NucleiSource{Cfg: cfg}, // optional: only if external nuclei is installed
			scan.ScreenshotSource{Cfg: cfg},
			scan.JSAnalyzeSource{Cfg: cfg},
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

	// Ctrl+C stops the scan gracefully: the partial result is still printed
	// and the reports are still written.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	complete := ctx.Err() == nil
	if !complete {
		fmt.Fprintln(os.Stderr, "⚠ сканирование не завершилось полностью (остановлено или истёк лимит времени) — результат неполный")
	}

	// Final summary to stdout.
	snap := g.Snapshot()
	byType := map[graph.NodeType]int{}
	for _, n := range snap.Nodes {
		byType[n.Type]++
	}
	fmt.Printf("\n=== РЕЗУЛЬТАТ для %s ===\n", flag.Arg(0))
	var types []string
	for t := range byType {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Printf("%-12s %d\n", t, byType[graph.NodeType(t)])
	}
	fmt.Printf("ИТОГО        %d узлов, %d связей\n", len(snap.Nodes), len(snap.Edges))

	if *obsidian != "" {
		n, err := g.ExportVault(*obsidian)
		if err != nil {
			fmt.Fprintln(os.Stderr, "экспорт Obsidian:", err)
			os.Exit(1)
		}
		fmt.Printf("Хранилище Obsidian: %d заметок → %s\n", n, *obsidian)
	}

	// Reports.
	writeReport := func(path string, data []byte, err error, label string) {
		if path == "" {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, label+" экспорт:", err)
			return
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, label+" запись:", err)
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

	// Monitoring: report what changed vs the previous stored scan, then save
	// this one (diff first: Save may replace an identical last scan).
	if *doDiff {
		label := t.Domain
		if label == "" {
			label = t.IP
		}
		diff, err := history.DiffAgainstPrevious(label, snap)
		if !complete {
			fmt.Fprintln(os.Stderr, "diff: неполное сканирование не сохранено и не сравнивалось")
			os.Exit(1)
		}
		if _, serr := history.Save(label, snap); serr != nil {
			fmt.Fprintln(os.Stderr, "сохранение истории:", serr)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "diff:", err)
		} else if !diff.HasPrevious {
			fmt.Println("\n=== DIFF === (первое сканирование — сравнивать не с чем)")
		} else {
			fmt.Printf("\n=== DIFF относительно %s ===\n", diff.Previous.Format("2006-01-02 15:04"))
			fmt.Printf("  +%d новых, -%d исчезло\n", len(diff.Added), len(diff.Removed))
			for _, n := range diff.Added {
				fmt.Printf("  + [%s] %s\n", n.Type, n.Label)
			}
			for _, n := range diff.Removed {
				fmt.Printf("  - [%s] %s\n", n.Type, n.Label)
			}
		}
	}
}
