package cve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// kevURL is the CISA Known Exploited Vulnerabilities catalog (CVEs seen being
// actively exploited in the wild — the ones that matter most).
const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const kevTTL = 24 * time.Hour

// KEVSet is a set of CVE IDs known to be exploited.
type KEVSet map[string]bool

// kevCatalog is the subset of the CISA feed we parse.
type kevCatalog struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// LoadKEV returns the KEV set, served from the SQLite cache when fresh and
// downloaded from CISA otherwise. Failure returns an empty set (non-fatal).
func (s *Store) LoadKEV(ctx context.Context, userAgent string) KEVSet {
	set := KEVSet{}
	if ids, fresh := s.cachedKEV(); fresh {
		for _, id := range ids {
			set[id] = true
		}
		return set
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return set
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return s.staleKEV() // fall back to whatever we had
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s.staleKEV()
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return s.staleKEV()
	}
	ids := make([]string, 0, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if v.CveID != "" {
			ids = append(ids, v.CveID)
			set[v.CveID] = true
		}
	}
	_ = s.saveKEV(ids)
	return set
}

func (s *Store) ensureKEVTables() {
	s.db.Exec(`CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY);`)
	s.db.Exec(`CREATE TABLE IF NOT EXISTS kev_meta (k TEXT PRIMARY KEY, v INTEGER);`)
}

func (s *Store) cachedKEV() (ids []string, fresh bool) {
	s.ensureKEVTables()
	var fetched int64
	if err := s.db.QueryRow(`SELECT v FROM kev_meta WHERE k='fetched_at'`).Scan(&fetched); err != nil {
		return nil, false
	}
	if time.Since(time.Unix(fetched, 0)) > kevTTL {
		return nil, false
	}
	return s.allKEV(), true
}

func (s *Store) staleKEV() KEVSet {
	set := KEVSet{}
	for _, id := range s.allKEV() {
		set[id] = true
	}
	return set
}

func (s *Store) allKEV() []string {
	rows, err := s.db.Query(`SELECT cve_id FROM kev`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *Store) saveKEV(ids []string) error {
	s.ensureKEVTables()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM kev`); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO kev(cve_id) VALUES(?)`, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO kev_meta(k, v) VALUES('fetched_at', ?)`, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
