package scan

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// commonPorts is the fallback scan set when nmap is unavailable.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
}

// portServiceGuess maps well-known ports to a service name (no version).
var portServiceGuess = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
	110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds", 3306: "mysql",
	3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
	8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

// PortScanSource is a dependency-free TCP connect scanner used only when nmap is
// not installed. It cannot detect versions, so it produces no CVE input.
type PortScanSource struct{ Cfg config.Config }

func (PortScanSource) Name() string                { return "portscan" }
func (PortScanSource) Stage() core.Stage           { return core.StageProbe }
func (PortScanSource) Applicable(core.Target) bool { return !NmapAvailable() }

func (s PortScanSource) Run(ctx context.Context, c *core.Collector) error {
	ips := c.ListByType(graph.NodeIP)
	if len(ips) == 0 {
		return nil
	}
	conc := s.Cfg.MaxConcurrent
	if conc <= 0 {
		conc = 16
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, ip := range ips {
		ipID := c.Node(graph.NodeIP, ip, ip, nil)
		for _, port := range commonPorts {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip, ipID string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				if conn := dial(ctx, ip, port); conn != nil {
					product, version := "", ""
					if bannerPorts[port] {
						if p, v, ok := parseBanner(grabBanner(conn)); ok {
							product, version = p, v
						}
					}
					_ = conn.Close()
					addPort(c, ipID, ip, fmt.Sprint(port), "tcp",
						portServiceGuess[port], product, version, "")
					c.Flush()
				}
			}(ip, ipID, port)
		}
	}
	wg.Wait()
	c.Log(core.LogInfo, "fallback port scan complete")
	return nil
}

func dial(ctx context.Context, ip string, port int) net.Conn {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	return conn
}

// bannerPorts speak a plaintext banner on connect, so a short read reveals the
// product/version the version-less connect scan otherwise misses.
var bannerPorts = map[int]bool{21: true, 22: true, 23: true, 25: true, 110: true, 143: true}

// grabBanner reads the service's greeting line (best effort, short deadline).
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return ""
	}
	line := string(buf[:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// bannerRe pulls a "Name<sep>1.2(.3)" product/version out of a banner line
// (e.g. "SSH-2.0-OpenSSH_8.2p1", "220 ProFTPD 1.3.5a Server").
var bannerRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+]+)[ _/-]v?(\d+\.\d+(?:\.\d+)?)`)

func parseBanner(banner string) (product, version string, ok bool) {
	// SSH banners are "SSH-<proto>-<software>"; skip the proto version so we
	// fingerprint the software (OpenSSH_8.2p1), not "SSH 2.0".
	if strings.HasPrefix(banner, "SSH-") {
		if i := strings.Index(banner[4:], "-"); i >= 0 {
			banner = banner[4+i+1:]
		}
	}
	m := bannerRe.FindStringSubmatch(banner)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
