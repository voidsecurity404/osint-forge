package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/core"
	"osint-forge/internal/history"
	"osint-forge/internal/notify"
)

// Monitor re-scans watched targets on an interval and, when the newest scan
// differs from the one before, sends an alert to the configured channels.
type Monitor struct {
	app *App

	mu      sync.Mutex
	watches map[string]*Watch // key: target label
	stopCh  chan struct{}
	stopped bool
	path    string // where watches are persisted; "" = memory only (tests)
}

// Watch is one monitored target.
type Watch struct {
	Target      string    `json:"target"`
	IntervalMin int       `json:"intervalMin"`
	Consent     bool      `json:"consent"`
	Added       time.Time `json:"added"`
	LastRun     time.Time `json:"lastRun"`
	NextRun     time.Time `json:"nextRun"`
	LastChange  string    `json:"lastChange,omitempty"`
	// Filter selects which changes trigger an alert (zero = all changes).
	Filter AlertFilter `json:"filter"`
}

// minIntervalMin is the floor between two runs of the same target.
const minIntervalMin = 5

func NewMonitor(app *App) *Monitor {
	return &Monitor{app: app, watches: map[string]*Watch{}, stopCh: make(chan struct{})}
}

// Persist makes the watch list survive restarts: it loads any saved watches
// from path and saves every later change there.
func (m *Monitor) Persist(path string) error {
	m.mu.Lock()
	m.path = path
	m.mu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []Watch
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("monitor: %s: %w", path, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range list {
		w := list[i]
		t := core.ParseTarget(w.Target)
		if !t.Valid {
			continue
		}
		w.Target = labelOf(t)
		if w.IntervalMin < minIntervalMin {
			w.IntervalMin = minIntervalMin
		}
		m.watches[w.Target] = &w
	}
	return nil
}

// saveLocked writes the watch list atomically. Caller holds m.mu.
func (m *Monitor) saveLocked() {
	if m.path == "" {
		return
	}
	list := make([]Watch, 0, len(m.watches))
	for _, w := range m.watches {
		list = append(list, *w)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Target < list[j].Target })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("monitor: save: %v", err)
		return
	}
	if err := os.Rename(tmp, m.path); err != nil {
		log.Printf("monitor: save: %v", err)
	}
}

// Start runs the scheduler loop (one tick a minute).
func (m *Monitor) Start() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-t.C:
				m.tick(time.Now())
			}
		}
	}()
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
	}
}

// List returns the current watches, sorted by target.
func (m *Monitor) List() []Watch {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Watch, 0, len(m.watches))
	for _, w := range m.watches {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// Add (or update) a watch that alerts on every change.
func (m *Monitor) Add(target string, intervalMin int, consent bool) (Watch, error) {
	return m.AddWatch(target, intervalMin, consent, AlertFilter{})
}

// AddWatch adds (or updates) a watch with an alert filter.
func (m *Monitor) AddWatch(target string, intervalMin int, consent bool, filter AlertFilter) (Watch, error) {
	t := core.ParseTarget(target)
	if !t.Valid {
		return Watch{}, fmt.Errorf("noto'g'ri nishon")
	}
	label := labelOf(t)
	if intervalMin < minIntervalMin {
		intervalMin = minIntervalMin // floor: never hammer a target
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w := &Watch{Target: label, IntervalMin: intervalMin, Consent: consent, Added: time.Now(),
		NextRun: time.Now().Add(time.Duration(intervalMin) * time.Minute), Filter: filter.normalize()}
	if old := m.watches[label]; old != nil {
		w.Added, w.LastRun, w.LastChange = old.Added, old.LastRun, old.LastChange
	}
	m.watches[label] = w
	m.saveLocked()
	return *w, nil
}

// Remove a watch.
func (m *Monitor) Remove(target string) {
	label := labelOf(core.ParseTarget(target))
	if label == "" {
		label = strings.TrimSpace(target)
	}
	m.mu.Lock()
	delete(m.watches, label)
	m.saveLocked()
	m.mu.Unlock()
}

// tick starts the scans that are due. A watch's schedule only advances when
// its scan really started; when another scan is running it is retried on the
// next tick instead of silently skipping a whole interval.
func (m *Monitor) tick(now time.Time) {
	m.mu.Lock()
	var due []Watch
	for _, w := range m.watches {
		if !now.Before(w.NextRun) {
			due = append(due, *w)
		}
	}
	m.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].NextRun.Before(due[j].NextRun) })

	for _, w := range due {
		err := m.app.startScan(ScanRequest{Target: w.Target, Consent: w.Consent, Monitor: true})
		if err != nil {
			m.app.mu.Lock()
			busy := m.app.running
			m.app.mu.Unlock()
			if busy {
				return // a scan is running; retry on the next tick
			}
			m.setLastChange(w.Target, "skan boshlanmadi: "+err.Error())
		}
		m.mu.Lock()
		if cur := m.watches[w.Target]; cur != nil {
			cur.LastRun = now
			cur.NextRun = now.Add(time.Duration(cur.IntervalMin) * time.Minute)
			m.saveLocked()
		}
		m.mu.Unlock()
		if err == nil {
			return // one scan at a time; the next due watch starts on a later tick
		}
	}
}

// setLastChange records a status line for a watch.
func (m *Monitor) setLastChange(label, msg string) {
	m.mu.Lock()
	if w := m.watches[label]; w != nil {
		w.LastChange = msg + " (" + time.Now().Format("15:04") + ")"
		m.saveLocked()
	}
	m.mu.Unlock()
}

// onScanDone is wired via App.OnScanDone; it alerts when a monitored scan
// differs from the previous one.
func (m *Monitor) onScanDone(res ScanResult) {
	if !res.Request.Monitor {
		return
	}
	label := labelOf(core.ParseTarget(res.Request.Target))
	if !res.Complete {
		// Cancelled or out of time: missing entities are not "removed".
		m.setLastChange(label, "skan to'liq tugamadi — taqqoslanmadi")
		return
	}
	m.mu.Lock()
	var filter AlertFilter
	if w := m.watches[label]; w != nil {
		filter = w.Filter
	}
	m.mu.Unlock()
	all := res.Diff
	diff := filter.Apply(all)
	if !diff.HasPrevious {
		m.setLastChange(label, "birinchi skan saqlandi")
		return
	}
	if len(all.Added) == 0 && len(all.Removed) == 0 {
		m.setLastChange(label, "o'zgarishsiz")
		return
	}
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		m.setLastChange(label, fmt.Sprintf("+%d / −%d o'zgarish bor, lekin filtrga mos emas — xabar yuborilmadi", len(all.Added), len(all.Removed)))
		return
	}
	m.setLastChange(label, fmt.Sprintf("+%d yangi, −%d yo'qolgan", len(diff.Added), len(diff.Removed)))

	m.app.mu.Lock()
	cfg := m.app.cfg
	m.app.mu.Unlock()
	nc := notify.Config{TelegramToken: cfg.TelegramToken, TelegramChatID: cfg.TelegramChatID, WebhookURL: cfg.WebhookURL}
	if !nc.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := notify.Send(ctx, nc, formatAlert(label, diff)); err != nil {
		log.Printf("monitor: %v", err)
		m.setLastChange(label, "xabar yuborilmadi: "+err.Error())
	}
}

func formatAlert(target string, d history.Diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🕸️ osint-forge — %s da o'zgarish\n", target)
	fmt.Fprintf(&b, "+%d yangi, −%d yo'qolgan\n", len(d.Added), len(d.Removed))
	n := 0
	for _, node := range d.Added {
		if n >= 15 {
			b.WriteString("…\n")
			break
		}
		fmt.Fprintf(&b, "➕ %s: %s\n", node.Type, node.Label)
		n++
	}
	for _, node := range d.Removed {
		if n >= 25 {
			break
		}
		fmt.Fprintf(&b, "➖ %s: %s\n", node.Type, node.Label)
		n++
	}
	return b.String()
}
