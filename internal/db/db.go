// Package db — port dari NEXTJS-SHORTURL/src/lib/db.js.
// SQLite (modernc.org/sqlite, pure Go) di ./data/shorturl.db + migrasi ringan.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct{ SQL *sql.DB }

type User struct {
	ID           int64
	Email        string
	Name         sql.NullString
	PasswordHash string
	APIKey       sql.NullString
	CreatedAt    string
}

type URLRow struct {
	ID           int64
	ShortCode    string
	OriginalURL  string
	Clicks       int64
	UserID       sql.NullInt64
	PasswordHash sql.NullString
	ExpiresAt    sql.NullString
	DomainID     sql.NullInt64
	CreatedAt    string
}

type Click struct {
	CreatedAt string
	Country   sql.NullString
	Device    sql.NullString
	Referrer  sql.NullString
}

type Daily struct {
	Day   string `json:"day"`
	Total int64  `json:"total"`
}

type Domain struct {
	ID            int64
	UserID        int64
	Hostname      string
	VerifyToken   string
	Status        string
	LastError     sql.NullString
	LastCheckedAt sql.NullString
	VerifiedAt    sql.NullString
	CreatedAt     string
	LinkCount     int64
}

// Open — buka/buat DB + skema + migrasi ringan.
func Open(dataDir string) (*DB, error) {
	if dataDir == "" {
		dataDir = "./data"
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.Join(dataDir, "shorturl.db") + "?cache=shared"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	if _, err := sqldb.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		return nil, err
	}
	if _, err := sqldb.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return nil, err
	}
	d := &DB{SQL: sqldb}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	_, err := d.SQL.Exec(`
	CREATE TABLE IF NOT EXISTS users (
	  id            INTEGER PRIMARY KEY AUTOINCREMENT,
	  email         TEXT UNIQUE NOT NULL,
	  name          TEXT,
	  password_hash TEXT NOT NULL,
	  api_key       TEXT UNIQUE,
	  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS urls (
	  id            INTEGER PRIMARY KEY AUTOINCREMENT,
	  short_code    TEXT UNIQUE NOT NULL,
	  original_url  TEXT NOT NULL,
	  clicks        INTEGER DEFAULT 0,
	  user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
	  password_hash TEXT,
	  expires_at    TEXT,
	  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_short_code ON urls(short_code);
	CREATE TABLE IF NOT EXISTS sessions (
	  token      TEXT PRIMARY KEY,
	  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  expires_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS clicks (
	  id         INTEGER PRIMARY KEY AUTOINCREMENT,
	  url_id     INTEGER NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
	  country    TEXT,
	  device     TEXT,
	  referrer   TEXT,
	  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_clicks_url ON clicks(url_id);
	CREATE INDEX IF NOT EXISTS idx_clicks_time ON clicks(created_at);
	CREATE TABLE IF NOT EXISTS domains (
	  id              INTEGER PRIMARY KEY AUTOINCREMENT,
	  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  hostname        TEXT UNIQUE NOT NULL COLLATE NOCASE,
	  verify_token    TEXT NOT NULL,
	  status          TEXT NOT NULL DEFAULT 'pending',
	  last_error      TEXT,
	  last_checked_at DATETIME,
	  verified_at     DATETIME,
	  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id);
	CREATE INDEX IF NOT EXISTS idx_domains_host ON domains(hostname);
	`)
	if err != nil {
		return err
	}
	// Migrasi ringan: tambah kolom yang belum ada (DB lama).
	urlCols, _ := d.columns("urls")
	for col, ddl := range map[string]string{
		"user_id":       "ALTER TABLE urls ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
		"password_hash": "ALTER TABLE urls ADD COLUMN password_hash TEXT",
		"expires_at":    "ALTER TABLE urls ADD COLUMN expires_at TEXT",
		"domain_id":     "ALTER TABLE urls ADD COLUMN domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL",
	} {
		if !urlCols[col] {
			if _, err := d.SQL.Exec(ddl); err != nil {
				return fmt.Errorf("migrasi urls.%s: %w", col, err)
			}
		}
	}
	clickCols, _ := d.columns("clicks")
	if !clickCols["ip_prefix"] {
		if _, err := d.SQL.Exec("ALTER TABLE clicks ADD COLUMN ip_prefix TEXT"); err != nil {
			return err
		}
	}
	_, _ = d.SQL.Exec("CREATE INDEX IF NOT EXISTS idx_urls_user ON urls(user_id)")
	return nil
}

func (d *DB) columns(table string) (map[string]bool, error) {
	rows, err := d.SQL.Query(fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", table))
	if err != nil {
		return map[string]bool{}, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		out[name] = true
	}
	return out, nil
}

// Queries — wrapper query (satu instance dipakai semua handler; sql.DB aman konkurensi).
type Queries struct{ db *DB }

func (d *DB) Q() *Queries { return &Queries{db: d} }

// ─── urls ───

func (q *Queries) InsertURL(code, originalURL string, passwordHash, expiresAt *string, userID, domainID *int64) error {
	_, err := q.db.SQL.Exec(
		`INSERT INTO urls (short_code, original_url, password_hash, expires_at, user_id, domain_id) VALUES (?, ?, ?, ?, ?, ?)`,
		code, originalURL, nullStr(passwordHash), nullStr(expiresAt), nullInt(userID), nullInt(domainID),
	)
	return err
}

func (q *Queries) FindByCodeAndDomain(code string, domainID *int64) (*URLRow, error) {
	var row *sql.Row
	if domainID == nil {
		row = q.db.SQL.QueryRow(`SELECT id, short_code, original_url, clicks, user_id, password_hash, expires_at, domain_id, created_at FROM urls WHERE short_code = ? AND domain_id IS NULL`, code)
	} else {
		row = q.db.SQL.QueryRow(`SELECT id, short_code, original_url, clicks, user_id, password_hash, expires_at, domain_id, created_at FROM urls WHERE short_code = ? AND domain_id = ?`, code, *domainID)
	}
	var r URLRow
	if err := row.Scan(&r.ID, &r.ShortCode, &r.OriginalURL, &r.Clicks, &r.UserID, &r.PasswordHash, &r.ExpiresAt, &r.DomainID, &r.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

func (q *Queries) IncrementClicks(urlID int64) error {
	_, err := q.db.SQL.Exec(`UPDATE urls SET clicks = clicks + 1 WHERE id = ?`, urlID)
	return err
}

func (q *Queries) AliasExists(code string) (bool, error) {
	var one int
	err := q.db.SQL.QueryRow(`SELECT 1 FROM urls WHERE short_code = ?`, code).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// IsExpired — expires_at (YYYY-MM-DD) < hari ini (lokal).
func IsExpired(expiresAt sql.NullString) bool {
	if !expiresAt.Valid || expiresAt.String == "" {
		return false
	}
	today := time.Now().Format("2006-01-02")
	return expiresAt.String < today
}

func (q *Queries) RecordClick(urlID int64, country, device, referrer, ipPrefix *string) error {
	_, err := q.db.SQL.Exec(
		`INSERT INTO clicks (url_id, country, device, referrer, ip_prefix) VALUES (?, ?, ?, ?, ?)`,
		urlID, nullStr(country), nullStr(device), nullStr(referrer), nullStr(ipPrefix),
	)
	return err
}

func (q *Queries) RecordRedirect(row *URLRow, country, device, referrer, ipPrefix *string) error {
	if err := q.IncrementClicks(row.ID); err != nil {
		return err
	}
	return q.RecordClick(row.ID, country, device, referrer, ipPrefix)
}

// ─── users ───

func (q *Queries) FindUserByEmail(email string) (*User, error) {
	return q.scanUser(q.db.SQL.QueryRow(`SELECT id, email, name, password_hash, api_key, created_at FROM users WHERE email = ?`, email))
}

func (q *Queries) FindUserByID(id int64) (*User, error) {
	return q.scanUser(q.db.SQL.QueryRow(`SELECT id, email, name, password_hash, api_key, created_at FROM users WHERE id = ?`, id))
}

func (q *Queries) FindUserByAPIKey(key string) (*User, error) {
	if key == "" {
		return nil, nil
	}
	return q.scanUser(q.db.SQL.QueryRow(`SELECT id, email, name, password_hash, api_key, created_at FROM users WHERE api_key = ?`, key))
}

func (q *Queries) scanUser(row *sql.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.APIKey, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (q *Queries) CreateUser(email, passwordHash string, name *string) (int64, error) {
	res, err := q.db.SQL.Exec(`INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)`, email, passwordHash, nullStr(name))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (q *Queries) SetUserAPIKey(userID int64, key string) error {
	_, err := q.db.SQL.Exec(`UPDATE users SET api_key = ? WHERE id = ?`, key, userID)
	return err
}

func (q *Queries) SetUserName(userID int64, name string) error {
	_, err := q.db.SQL.Exec(`UPDATE users SET name = ? WHERE id = ?`, name, userID)
	return err
}

func (q *Queries) SetUserPassword(userID int64, hash string) error {
	_, err := q.db.SQL.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	return err
}

func (q *Queries) DeleteUserWithData(userID int64) error {
	tx, err := q.db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM urls WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (q *Queries) CountLinksByUser(userID int64) (int64, error) {
	var total int64
	err := q.db.SQL.QueryRow(`SELECT COUNT(*) FROM urls WHERE user_id = ?`, userID).Scan(&total)
	return total, err
}

// ─── sessions ───

func (q *Queries) CreateSession(token string, userID int64, expires time.Time) error {
	_, err := q.db.SQL.Exec(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expires.UTC().Format("2006-01-02 15:04:05"))
	return err
}

func (q *Queries) GetSessionUser(token string) (*User, error) {
	return q.scanUser(q.db.SQL.QueryRow(
		`SELECT u.id, u.email, u.name, u.password_hash, u.api_key, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > datetime('now')`, token))
}

func (q *Queries) DestroySession(token string) error {
	if token == "" {
		return nil
	}
	_, err := q.db.SQL.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (q *Queries) DeleteOtherSessions(userID int64, keepToken string) error {
	if keepToken != "" {
		_, err := q.db.SQL.Exec(`DELETE FROM sessions WHERE user_id = ? AND token <> ?`, userID, keepToken)
		return err
	}
	_, err := q.db.SQL.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// ─── links milik user ───

func (q *Queries) ListLinksByUser(userID int64) ([]*URLRow, error) {
	rows, err := q.db.SQL.Query(`SELECT id, short_code, original_url, clicks, user_id, password_hash, expires_at, domain_id, created_at FROM urls WHERE user_id = ? ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*URLRow
	for rows.Next() {
		var r URLRow
		if err := rows.Scan(&r.ID, &r.ShortCode, &r.OriginalURL, &r.Clicks, &r.UserID, &r.PasswordHash, &r.ExpiresAt, &r.DomainID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, nil
}

func (q *Queries) GetLinkByID(id int64) (*URLRow, error) {
	var r URLRow
	err := q.db.SQL.QueryRow(`SELECT id, short_code, original_url, clicks, user_id, password_hash, expires_at, domain_id, created_at FROM urls WHERE id = ?`, id).
		Scan(&r.ID, &r.ShortCode, &r.OriginalURL, &r.Clicks, &r.UserID, &r.PasswordHash, &r.ExpiresAt, &r.DomainID, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (q *Queries) UpdateLinkDestination(id int64, url string) error {
	_, err := q.db.SQL.Exec(`UPDATE urls SET original_url = ? WHERE id = ?`, url, id)
	return err
}

func (q *Queries) DeleteLink(id int64) error {
	_, err := q.db.SQL.Exec(`DELETE FROM urls WHERE id = ?`, id)
	return err
}

// ─── analytics ───

func (q *Queries) GetClicksByURL(urlID int64, limitDays int) ([]*Click, error) {
	rows, err := q.db.SQL.Query(
		fmt.Sprintf(`SELECT created_at, country, device, referrer FROM clicks WHERE url_id = ? AND created_at >= datetime('now', '-%d days') ORDER BY created_at ASC`, limitDays), urlID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Click
	for rows.Next() {
		var c Click
		if err := rows.Scan(&c.CreatedAt, &c.Country, &c.Device, &c.Referrer); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, nil
}

func (q *Queries) GetClicksDaily(urlID int64, limitDays int) ([]Daily, error) {
	rows, err := q.db.SQL.Query(
		fmt.Sprintf(`SELECT date(created_at) AS day, COUNT(*) AS total FROM clicks WHERE url_id = ? AND created_at >= datetime('now', '-%d days') GROUP BY day ORDER BY day ASC`, limitDays), urlID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Daily
	for rows.Next() {
		var d Daily
		if err := rows.Scan(&d.Day, &d.Total); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if out == nil {
		out = []Daily{}
	}
	return out, nil
}

type NameCount struct {
	Value  string `json:"value"`
	Clicks int64  `json:"clicks"`
}

func (q *Queries) groupClicksByUser(userID int64, column string, limitDays, limit int) ([]NameCount, error) {
	allowed := map[string]bool{"country": true, "device": true, "referrer": true}
	if !allowed[column] {
		return nil, fmt.Errorf("kolom tidak valid")
	}
	window := ""
	if limitDays > 0 {
		window = fmt.Sprintf(`AND c.created_at >= datetime('now', '-%d days')`, limitDays)
	}
	limitClause := ""
	if limit > 0 {
		limitClause = fmt.Sprintf(`LIMIT %d`, limit)
	}
	rows, err := q.db.SQL.Query(
		fmt.Sprintf(`SELECT c.%s AS value, COUNT(*) AS clicks FROM clicks c JOIN urls u ON u.id = c.url_id WHERE u.user_id = ? AND c.%s IS NOT NULL AND c.%s <> '' %s GROUP BY c.%s ORDER BY clicks DESC, value ASC %s`,
			column, column, column, window, column, limitClause), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameCount
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Value, &nc.Clicks); err != nil {
			return nil, err
		}
		out = append(out, nc)
	}
	return out, nil
}

func (q *Queries) GetCountryStatsByUser(userID int64, limitDays, limit int) ([]map[string]any, error) {
	rows, err := q.groupClicksByUser(userID, "country", limitDays, limit)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, map[string]any{"country": r.Value, "clicks": r.Clicks})
	}
	return out, nil
}

func (q *Queries) GetDeviceStatsByUser(userID int64, limitDays int) ([]map[string]any, error) {
	rows, err := q.groupClicksByUser(userID, "device", limitDays, 0)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, map[string]any{"device": r.Value, "clicks": r.Clicks})
	}
	return out, nil
}

func (q *Queries) CountCountriesByUser(userID int64) (int64, error) {
	var total int64
	err := q.db.SQL.QueryRow(`SELECT COUNT(DISTINCT c.country) FROM clicks c JOIN urls u ON u.id = c.url_id WHERE u.user_id = ? AND c.country IS NOT NULL AND c.country <> ''`, userID).Scan(&total)
	return total, err
}

func (q *Queries) CountClicksByUser(userID int64, limitDays int) (int64, error) {
	window := ""
	if limitDays > 0 {
		window = fmt.Sprintf(`AND c.created_at >= datetime('now', '-%d days')`, limitDays)
	}
	var total int64
	err := q.db.SQL.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM clicks c JOIN urls u ON u.id = c.url_id WHERE u.user_id = ? %s`, window), userID).Scan(&total)
	return total, err
}

func (q *Queries) GetTopCountryByURL(urlID int64) (string, error) {
	var country sql.NullString
	err := q.db.SQL.QueryRow(`SELECT country FROM clicks WHERE url_id = ? AND country IS NOT NULL AND country <> '' GROUP BY country ORDER BY COUNT(*) DESC, country ASC LIMIT 1`, urlID).Scan(&country)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if country.Valid {
		return country.String, nil
	}
	return "", nil
}

// ─── domains ───

func (q *Queries) ListDomainsByUser(userID int64) ([]*Domain, error) {
	rows, err := q.db.SQL.Query(`SELECT d.id, d.user_id, d.hostname, d.verify_token, d.status, d.last_error, d.last_checked_at, d.verified_at, d.created_at, (SELECT COUNT(*) FROM urls u WHERE u.domain_id = d.id) FROM domains d WHERE d.user_id = ? ORDER BY d.created_at DESC, d.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.UserID, &d.Hostname, &d.VerifyToken, &d.Status, &d.LastError, &d.LastCheckedAt, &d.VerifiedAt, &d.CreatedAt, &d.LinkCount); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, nil
}

func (q *Queries) GetDomainByID(id int64) (*Domain, error) {
	var d Domain
	err := q.db.SQL.QueryRow(`SELECT id, user_id, hostname, verify_token, status, last_error, last_checked_at, verified_at, created_at, (SELECT COUNT(*) FROM urls u WHERE u.domain_id = domains.id) FROM domains WHERE id = ?`, id).
		Scan(&d.ID, &d.UserID, &d.Hostname, &d.VerifyToken, &d.Status, &d.LastError, &d.LastCheckedAt, &d.VerifiedAt, &d.CreatedAt, &d.LinkCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (q *Queries) FindDomainByHostname(hostname string) (*Domain, error) {
	var d Domain
	err := q.db.SQL.QueryRow(`SELECT id, user_id, hostname, verify_token, status, last_error, last_checked_at, verified_at, created_at, (SELECT COUNT(*) FROM urls u WHERE u.domain_id = domains.id) FROM domains WHERE hostname = ? COLLATE NOCASE`, hostname).
		Scan(&d.ID, &d.UserID, &d.Hostname, &d.VerifyToken, &d.Status, &d.LastError, &d.LastCheckedAt, &d.VerifiedAt, &d.CreatedAt, &d.LinkCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (q *Queries) FindVerifiedDomainByHostname(hostname string) (*Domain, error) {
	var d Domain
	err := q.db.SQL.QueryRow(`SELECT id, user_id, hostname, verify_token, status, last_error, last_checked_at, verified_at, created_at, (SELECT COUNT(*) FROM urls u WHERE u.domain_id = domains.id) FROM domains WHERE hostname = ? COLLATE NOCASE AND status = 'verified'`, hostname).
		Scan(&d.ID, &d.UserID, &d.Hostname, &d.VerifyToken, &d.Status, &d.LastError, &d.LastCheckedAt, &d.VerifiedAt, &d.CreatedAt, &d.LinkCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (q *Queries) InsertDomain(userID int64, hostname, verifyToken string) (int64, error) {
	res, err := q.db.SQL.Exec(`INSERT INTO domains (user_id, hostname, verify_token) VALUES (?, ?, ?)`, userID, hostname, verifyToken)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (q *Queries) SetDomainVerification(id int64, status string, lastError *string) error {
	_, err := q.db.SQL.Exec(`UPDATE domains SET status = ?, last_error = ?, last_checked_at = datetime('now'), verified_at = CASE WHEN ? = 'verified' THEN datetime('now') ELSE verified_at END WHERE id = ?`,
		status, nullStr(lastError), status, id)
	return err
}

func (q *Queries) DeleteDomainWithUnlink(id int64) error {
	tx, err := q.db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE urls SET domain_id = NULL WHERE domain_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM domains WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveDomainForHost — host → domainId (nil = utama). denied=true bila host asing + strict.
func (q *Queries) ResolveDomainForHost(host string, isPrimary func(string) bool, strict func() bool) (domainID *int64, denied bool, err error) {
	if host == "" || isPrimary(host) {
		return nil, false, nil
	}
	d, err := q.FindVerifiedDomainByHostname(host)
	if err != nil {
		return nil, false, err
	}
	if d != nil {
		id := d.ID
		return &id, false, nil
	}
	if !strict() {
		return nil, false, nil
	}
	return nil, true, nil
}

func nullStr(s *string) any {
	if s == nil || *s == "" {
		// Bedakan NULL vs "": password/expires/domain memakai NULL.
		// Untuk kolom teks biasa "" ikut jadi NULL agar konsisten dengan JS (?? null).
		return nil
	}
	return *s
}

func nullInt(n *int64) any {
	if n == nil {
		return nil
	}
	return *n
}
