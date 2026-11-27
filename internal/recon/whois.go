package recon

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"osint-forge/internal/config"
	"osint-forge/internal/core"
	"osint-forge/internal/graph"
)

// WhoisSource fetches registration data via RDAP (the modern WHOIS) from the
// rdap.org bootstrap, which routes to the right registry. No API key needed.
type WhoisSource struct{ Cfg config.Config }

func (WhoisSource) Name() string                { return "whois/rdap" }
func (WhoisSource) Stage() core.Stage           { return core.StageDiscovery }
func (WhoisSource) Applicable(core.Target) bool { return true }

// rdapResponse captures the subset of RDAP we surface.
type rdapResponse struct {
	Handle   string       `json:"handle"`
	LDHName  string       `json:"ldhName"`
	Name     string       `json:"name"` // for IP networks
	Country  string       `json:"country"`
	Entities []rdapEntity `json:"entities"`
	Events   []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

type rdapEntity struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
}

func (s WhoisSource) Run(ctx context.Context, c *core.Collector) error {
	t := c.Target
	if t.Domain != "" {
		// RDAP domain lookups must target the registrable domain (eTLD+1), not
		// an arbitrary subdomain, or the registry returns HTTP 400.
		reg := t.Domain
		if r, err := publicsuffix.EffectiveTLDPlusOne(t.Domain); err == nil {
			reg = r
		}
		s.query(ctx, c, "https://rdap.org/domain/"+reg, graph.NodeDomain, t.Domain)
	}
	if t.IP != "" {
		s.query(ctx, c, "https://rdap.org/ip/"+t.IP, graph.NodeIP, t.IP)
	}
	c.Flush()
	return nil
}

func (s WhoisSource) query(ctx context.Context, c *core.Collector, url string, rootType graph.NodeType, rootKey string) {
	var r rdapResponse
	if err := getJSON(ctx, s.Cfg, url, nil, &r); err != nil {
		c.Log(core.LogWarn, "rdap: "+err.Error())
		return
	}
	rootID := graph.NodeID(rootType, rootKey)

	props := map[string]any{}
	if r.Country != "" {
		props["country"] = r.Country
	}
	if r.Name != "" {
		props["network"] = r.Name
	}
	for _, ev := range r.Events {
		if ev.Action == "registration" {
			props["registered"] = ev.Date
		}
		if ev.Action == "expiration" {
			props["expires"] = ev.Date
		}
	}
	if len(props) > 0 {
		c.Node(rootType, rootKey, rootKey, props)
	}

	for _, e := range r.Entities {
		org := vcardName(e.VCardArray)
		if org == "" {
			continue
		}
		role := "registered_by"
		if len(e.Roles) > 0 {
			role = e.Roles[0]
		}
		orgID := c.Node(graph.NodeWhois, org, org, map[string]any{"roles": e.Roles})
		c.Edge(rootID, orgID, role)
	}
	c.Log(core.LogInfo, fmt.Sprintf("rdap: получено (объектов: %d)", len(r.Entities)))
}

// vcardName extracts the "fn" (full name / org) value from an RDAP jCard array.
// The structure is ["vcard", [ ["fn", {}, "text", "Example Inc"], ... ]].
func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	items, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, it := range items {
		field, ok := it.([]any)
		if !ok || len(field) < 4 {
			continue
		}
		if name, _ := field[0].(string); strings.EqualFold(name, "fn") {
			if val, ok := field[3].(string); ok {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}
