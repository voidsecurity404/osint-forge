package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
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
	for _, ep := range s.httpsEndpoints(c) {
		if ctx.Err() != nil {
			return nil
		}
		s.inspect(ctx, c, ep.host, ep.port)
		c.Flush()
	}
	return nil
}

type tlsTarget struct{ host, port string }

// tlsEndpoint extracts host and port (default 443) from an https URL. The host
// is returned without IPv6 brackets.
func tlsEndpoint(raw string) (host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", "", false
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), port, true
}

func joinHostPort(host, port string) string { return net.JoinHostPort(host, port) }

// httpsEndpoints collects the distinct host:port pairs that answered over https
// (including web services on non-standard ports found by the port scan).
func (s TLSSource) httpsEndpoints(c *core.Collector) []tlsTarget {
	set := map[tlsTarget]bool{}
	var out []tlsTarget
	for _, u := range c.ListByType(graph.NodeURL) {
		host, port, ok := tlsEndpoint(u)
		if !ok || !c.InScope(host) {
			continue
		}
		t := tlsTarget{host, port}
		if set[t] {
			continue
		}
		n, ok := c.GetNode(graph.NodeURL, u)
		if !ok {
			continue
		}
		if _, live := n.Props["status"]; !live {
			continue
		}
		set[t] = true
		out = append(out, t)
	}
	return out
}

func (s TLSSource) inspect(ctx context.Context, c *core.Collector, host, port string) {
	hostID := c.HostID(host) // real node id: domain, subdomain or ip
	name, key := host, host
	if port != "443" {
		name = joinHostPort(host, port)
		key = host + ":" + port
	}

	// Certificate expiry via a normal handshake.
	if cert := s.leafCert(ctx, host, port); cert != nil {
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		switch {
		case days < 0:
			c.Finding("high", "cert-expired:"+key, "TLS sertifikat muddati o'tgan: "+name,
				fmt.Sprintf("Sertifikat %s da tugagan (%d kun oldin).", cert.NotAfter.Format("2006-01-02"), -days), hostID)
		case days < 21:
			c.Finding("medium", "cert-expiring:"+key, "TLS sertifikat tez tugaydi: "+name,
				fmt.Sprintf("Sertifikat %d kundan so'ng (%s) tugaydi.", days, cert.NotAfter.Format("2006-01-02")), hostID)
		}
	}

	// Deprecated protocol support.
	for _, v := range []struct {
		ver  uint16
		name string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}} {
		if s.supports(ctx, host, port, v.ver) {
			c.Finding("medium", "weak-tls:"+key+":"+v.name, "Eskirgan "+v.name+" qo'llab-quvvatlanadi: "+name,
				v.name+" eskirgan va zaif hisoblanadi; o'chirilishi kerak.", hostID)
		}
	}
}

func (s TLSSource) dial(ctx context.Context, host, port string, conf *tls.Config) (*tls.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 7 * time.Second}, Config: conf}
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// serverName is the SNI to send: a host name, never an IP literal.
func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func (s TLSSource) leafCert(ctx context.Context, host, port string) *x509.Certificate {
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: serverName(host)}
	conn, err := s.dial(ctx, host, port, conf)
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

func (s TLSSource) supports(ctx context.Context, host, port string, ver uint16) bool {
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: serverName(host), MinVersion: ver, MaxVersion: ver}
	conn, err := s.dial(ctx, host, port, conf)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
