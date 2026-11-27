package cve

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Match is a single CVE associated with a query (CPE or keyword).
type Match struct {
	ID        string  `json:"id"`
	Severity  string  `json:"severity"` // CRITICAL/HIGH/MEDIUM/LOW/NONE
	Score     float64 `json:"score"`    // CVSS base score
	Summary   string  `json:"summary"`
	Published string  `json:"published"`
}

// cacheTTL is how long a query's results stay fresh before re-fetching NVD.
const cacheTTL = 7 * 24 * time.Hour

// Store is the SQLite-backed CVE cache.
type Store struct{ db *sql.DB }

// DefaultPath returns the on-disk location of the CVE database.
func DefaultPath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "osint-forge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "cve.sqlite"), nil
}

// Open opens (and migrates) the CVE store at the given path.
func Open(path string) (*Store, error) {
	// busy_timeout: the web server and a reconcli run may share this file; a
	// second writer waits for the lock instead of failing with SQLITE_BUSY.
	// WAL lets readers proceed while a write is in progress.
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc sqlite is happiest single-writer
	schema := `
	CREATE TABLE IF NOT EXISTS query_log (
		query      TEXT PRIMARY KEY,
		fetched_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS match (
		query     TEXT NOT NULL,
		cve_id    TEXT NOT NULL,
		severity  TEXT,
		score     REAL,
		summary   TEXT,
		published TEXT,
		PRIMARY KEY (query, cve_id)
	);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Cached returns the cached matches for a query and whether they are still
// fresh. A fresh empty result (found=true, len 0) means "known: no CVEs".
func (s *Store) Cached(query string) (matches []Match, fresh bool, err error) {
	var fetched int64
	err = s.db.QueryRow(`SELECT fetched_at FROM query_log WHERE query = ?`, query).Scan(&fetched)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if time.Since(time.Unix(fetched, 0)) > cacheTTL {
		return nil, false, nil
	}
	rows, err := s.db.Query(
		`SELECT cve_id, severity, score, summary, published FROM match WHERE query = ? ORDER BY score DESC`, query)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var m Match
		if err := rows.Scan(&m.ID, &m.Severity, &m.Score, &m.Summary, &m.Published); err != nil {
			return nil, false, err
		}
		matches = append(matches, m)
	}
	return matches, true, rows.Err()
}

// Save stores a query's matches and marks the query fetched.
func (s *Store) Save(query string, matches []Match) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO query_log(query, fetched_at) VALUES(?, ?)`,
		query, time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM match WHERE query = ?`, query); err != nil {
		return err
	}
	for _, m := range matches {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO match(query, cve_id, severity, score, summary, published)
			 VALUES(?,?,?,?,?,?)`,
			query, m.ID, m.Severity, m.Score, m.Summary, m.Published); err != nil {
			return err
		}
	}
	return tx.Commit()
}
