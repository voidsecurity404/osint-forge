// Package scan holds active probing sources: nmap port/service scanning, a
// pure-Go fallback port scanner, and HTTP fingerprinting.
package scan

import (
	"context"
	"encoding/xml"
	"fmt"
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

func (s NmapSource) Run(ctx context.Context, c *core.Collector) error {
	ips := c.ListByType(graph.NodeIP)
	if len(ips) == 0 {
		return nil
	}

	args := strings.Fields(s.Cfg.NmapArgs)
	if len(args) == 0 {
		args = []string{"-sV", "-T4", "--top-ports", "1000"}
	}
	args = append(args, "-oX", "-")
	args = append(args, ips...)

	c.Log(core.LogInfo, "scanning "+fmt.Sprint(len(ips))+" host(s): nmap "+strings.Join(args, " "))
	out, err := exec.CommandContext(ctx, "nmap", args...).Output()
	if err != nil {
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
