package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// TLSSource inspects the TLS configuration of each HTTPS host: it flags support
// for deprecated protocol versions (TLS 1.0/1.1) and certificates that are
// expired or expiring soon.
type TLSSource struct{ Cfg config.Config }

func (TLSSource) Name() string                { return "tls" }
func (TLSSource) Stage() core.Stage           { return core.StageEnrich }
func (TLSSource) Applicable(core.Target) bool { return true }

func (s TLSSource) Run(ctx context.Context, c *core.Collector) error {
	for _, host := range s.httpsHosts(c) {
		s.inspect(ctx, c, host)
		c.Flush()
	}
	return nil
}

// httpsHosts collects hostnames that answered over https.
func (s TLSSource) httpsHosts(c *core.Collector) []string {
	set := map[string]bool{}
	for _, u := range c.ListByType(graph.NodeURL) {
		if !strings.HasPrefix(u, "https://") {
			continue
		}
		n, ok := c.GetNode(graph.NodeURL, u)
		if !ok {
			continue
		}
		if _, live := n.Props["status"]; !live {
			continue
		}
		host := strings.TrimPrefix(u, "https://")
		host = strings.TrimSuffix(host, "/")
		// Strip IPv6 brackets; net.JoinHostPort / ServerName want the bare host and
		// would otherwise double-bracket it.
		host = strings.Trim(host, "[]")
		if host != "" {
			set[host] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

func (s TLSSource) inspect(ctx context.Context, c *core.Collector, host string) {
	hostID := graph.NodeID(graph.NodeSubdomain, host) // may also be a domain id; edge still valid

	// Certificate expiry via a normal handshake.
	if cert := s.leafCert(ctx, host); cert != nil {
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		switch {
		case days < 0:
			c.Finding("high", "cert-expired:"+host, "TLS sertifikat muddati o'tgan: "+host,
				fmt.Sprintf("Sertifikat %s da tugagan (%d kun oldin).", cert.NotAfter.Format("2006-01-02"), -days), hostID)
		case days < 21:
			c.Finding("medium", "cert-expiring:"+host, "TLS sertifikat tez tugaydi: "+host,
				fmt.Sprintf("Sertifikat %d kundan so'ng (%s) tugaydi.", days, cert.NotAfter.Format("2006-01-02")), hostID)
		}
	}

	// Deprecated protocol support.
	for _, v := range []struct {
		ver  uint16
		name string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}} {
		if s.supports(ctx, host, v.ver) {
			c.Finding("medium", "weak-tls:"+host+":"+v.name, "Eskirgan "+v.name+" qo'llab-quvvatlanadi: "+host,
				v.name+" eskirgan va zaif hisoblanadi; o'chirilishi kerak.", hostID)
		}
	}
}

func (s TLSSource) dial(ctx context.Context, host string, conf *tls.Config) (*tls.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 7 * time.Second}, Config: conf}
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

func (s TLSSource) leafCert(ctx context.Context, host string) *x509.Certificate {
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	conn, err := s.dial(ctx, host, conf)
	if err != nil {
		return nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

func (s TLSSource) supports(ctx context.Context, host string, ver uint16) bool {
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: ver, MaxVersion: ver}
	conn, err := s.dial(ctx, host, conf)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
