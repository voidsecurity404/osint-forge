// Package scan holds active probing sources: nmap port/service scanning, a
// pure-Go fallback port scanner, and HTTP fingerprinting.
package scan

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// NmapAvailable reports whether the nmap binary is on PATH.
func NmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// NmapSource runs nmap service/version detection against discovered IPs and maps
// open ports and services into the graph. Service nodes carry product/version/
// cpe props that the CVE engine later consumes.
type NmapSource struct{ Cfg config.Config }

func (NmapSource) Name() string                { return "nmap" }
func (NmapSource) Stage() core.Stage           { return core.StageProbe }
func (NmapSource) Applicable(core.Target) bool { return NmapAvailable() }

// nmap XML (subset).
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string   `xml:"name,attr"`
					Product string   `xml:"product,attr"`
					Version string   `xml:"version,attr"`
					CPEs    []string `xml:"cpe"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// scopedIPs returns the discovered IPs an active scanner may touch, split by
// address family, plus how many were skipped as out of scope (e.g. the MX/NS
// servers of the domain, which belong to other organisations).
func scopedIPs(c *core.Collector) (v4, v6 []string, skipped int) {
	for _, ip := range c.ListByType(graph.NodeIP) {
		if !c.InScope(ip) {
			skipped++
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6, skipped
}

// nmapArgs builds the command line for one address family. nmap ignores IPv6
// targets without -6 and cannot mix families in one run.
func nmapArgs(userArgs string, ips []string, ipv6 bool) []string {
	var args []string
	for _, a := range strings.Fields(userArgs) {
		if a == "-6" {
			continue // added below only for the IPv6 run
		}
		args = append(args, a)
	}
	if len(args) == 0 {
		args = []string{"-sV", "-T4", "--top-ports", "1000"}
	}
	if ipv6 {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	return append(args, ips...)
}

func (s NmapSource) Run(ctx context.Context, c *core.Collector) error {
	v4, v6, skipped := scopedIPs(c)
	if skipped > 0 {
		c.Log(core.LogInfo, fmt.Sprintf("%d IP qamrovdan tashqarida (masalan MX/NS serverlari) — skanlanmaydi", skipped))
	}
	var errs []error
	for _, fam := range []struct {
		ips  []string
		ipv6 bool
	}{{v4, false}, {v6, true}} {
		if len(fam.ips) == 0 || ctx.Err() != nil {
			continue
		}
		if err := s.scan(ctx, c, nmapArgs(s.Cfg.NmapArgs, fam.ips, fam.ipv6), len(fam.ips)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s NmapSource) scan(ctx context.Context, c *core.Collector, args []string, hosts int) error {
	c.Log(core.LogInfo, fmt.Sprintf("scanning %d host(s): nmap %s", hosts, strings.Join(args, " ")))
	out, err := exec.CommandContext(ctx, "nmap", args...).Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil // cancelled / scan budget reached — not a tool failure
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return fmt.Errorf("nmap: %v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("nmap: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return fmt.Errorf("nmap xml: %w", err)
	}

	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ip = a.Addr
			}
		}
		if ip == "" {
			continue
		}
		ipID := c.Node(graph.NodeIP, ip, ip, nil)
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			addPort(c, ipID, ip, p.PortID, p.Protocol, p.Service.Name,
				p.Service.Product, p.Service.Version, firstCPE(p.Service.CPEs))
		}
		c.Flush()
	}
	return nil
}

func firstCPE(cpes []string) string {
	if len(cpes) > 0 {
		return cpes[0]
	}
	return ""
}

// addPort adds a port node and (when a service is identified) a service node
// carrying the data the CVE engine needs. Shared with the fallback scanner.
func addPort(c *core.Collector, ipID, ip, portID, proto, name, product, version, cpe string) {
	portKey := fmt.Sprintf("%s:%s/%s", ip, portID, proto)
	portLabel := fmt.Sprintf("%s/%s", portID, proto)
	pID := c.Node(graph.NodePort, portKey, portLabel, map[string]any{
		"port": portID, "proto": proto, "service": name,
	})
	c.Edge(ipID, pID, "has_port")

	if product == "" && name == "" {
		return
	}
	svcLabel := strings.TrimSpace(name + " " + product + " " + version)
	svcKey := fmt.Sprintf("%s:%s", ip, portID)
	sID := c.Node(graph.NodeService, svcKey, svcLabel, map[string]any{
		"name": name, "product": product, "version": version, "cpe": cpe,
		"ip": ip, "port": portID,
	})
	c.Edge(pID, sID, "runs_service")
}
