// Package server — HTTP router + handler. Port 1:1 perilaku NEXTJS-SHORTURL.
package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"shorturl/internal/auth"
	"shorturl/internal/db"
	dnsutil "shorturl/internal/dns"
	"shorturl/internal/geo"
	"shorturl/internal/hosts"
	"shorturl/internal/logger"
	"shorturl/internal/meta"
	"shorturl/internal/ratelimit"
	"shorturl/internal/validate"
	"shorturl/web"
)

type Server struct {
	Q         *db.Queries
	Templates *template.Template
}

func New(q *db.Queries) (*Server, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"dict": func(values ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(values); i += 2 {
				if k, ok := values[i].(string); ok {
					m[k] = values[i+1]
				}
			}
			return m
		},
	}).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{Q: q, Templates: tpl}, nil
}

// ─── helpers JSON ───

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request) (map[string]any, bool) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	var body map[string]any
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		if err == io.EOF {
			return map[string]any{}, true
		}
		return nil, false
	}
	return body, true
}

func strField(body map[string]any, key string) string {
	if body == nil {
		return ""
	}
	if v, ok := body[key].(string); ok {
		return v
	}
	return ""
}

func strptr(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func setSessionCookie(w http.ResponseWriter, token string) {
	c := auth.SessionCookie()
	c.Value = token
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, auth.ExpiredCookie())
}

// resolveUser — Bearer API key dulu, fallback cookie sesi.
func (s *Server) resolveUser(r *http.Request) (*db.User, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		parts := strings.SplitN(h, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if u, err := s.Q.FindUserByAPIKey(strings.TrimSpace(parts[1])); err != nil {
				return nil, err
			} else if u != nil {
				return u, nil
			}
		}
	}
	return auth.AuthUser(s.Q, r)
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (*db.User, bool) {
	u, err := s.resolveUser(r)
	if err != nil {
		writeErr(w, 500, "Gagal memuat sesi.")
		return nil, false
	}
	if u == nil {
		// Untuk API: JSON 401. Untuk halaman: redirect ditangani pemanggil.
		writeErr(w, 401, "Harus masuk dulu.")
		return nil, false
	}
	return u, true
}

// ─── short code ───

const alphabet = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"

func generateCode(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		// rejection sederhana: modulo bias kecil, bisa diterima untuk 7 char.
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

var redirectReserved = map[string]struct{}{
	"api": {}, "favicon.ico": {}, "robots.txt": {}, "sitemap.xml": {}, "pw": {}, "expired": {},
}

// ─── router ───

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// API
	mux.HandleFunc("POST /api/shorten", s.handleShorten)
	mux.HandleFunc("POST /api/unlock", s.handleUnlock)
	mux.HandleFunc("GET /api/links", s.handleLinksList)
	mux.HandleFunc("POST /api/links", s.handleLinksEdit)
	mux.HandleFunc("GET /api/links/{id}", s.handleLinkDetail)
	mux.HandleFunc("DELETE /api/links/{id}", s.handleLinkDelete)
	mux.HandleFunc("POST /api/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/account", s.handleAccountGet)
	mux.HandleFunc("PATCH /api/account", s.handleAccountPatch)
	mux.HandleFunc("DELETE /api/account", s.handleAccountDelete)
	mux.HandleFunc("POST /api/account/password", s.handlePasswordChange)
	mux.HandleFunc("POST /api/account/api-key", s.handleAPIKeyRegen)
	mux.HandleFunc("GET /api/domains", s.handleDomainsList)
	mux.HandleFunc("POST /api/domains", s.handleDomainAdd)
	mux.HandleFunc("DELETE /api/domains/{id}", s.handleDomainDelete)
	mux.HandleFunc("POST /api/domains/{id}/verify", s.handleDomainVerify)
	mux.HandleFunc("GET /README.md", s.handleReadme)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	// Halaman
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /register", s.handleRegisterPage)
	mux.HandleFunc("GET /pw", s.handlePwPage)
	mux.HandleFunc("GET /expired", s.handleExpiredPage)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("GET /dashboard/links", s.handleDashboardLinks)
	mux.HandleFunc("GET /dashboard/analytics", s.handleDashboardAnalytics)
	mux.HandleFunc("GET /dashboard/qr", s.handleDashboardQR)
	mux.HandleFunc("GET /dashboard/api", s.handleDashboardAPI)
	mux.HandleFunc("GET /dashboard/settings", s.handleDashboardSettings)
	// Static + redirect publik (paling akhir)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /{code}", s.handleRedirect)
	return s.withHeaders(s.withNotFound(mux))
}

// withNotFound — sergah respons 404 polos menjadi halaman not-found bergaya,
// kecuali yang sudah menulis body sendiri.
func (s *Server) withNotFound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &notFoundWriter{ResponseWriter: w, s: s}
		next.ServeHTTP(cw, r)
	})
}

type notFoundWriter struct {
	http.ResponseWriter
	s         *Server
	wrote     bool
	converted bool
}

func (w *notFoundWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if status == http.StatusNotFound {
		w.converted = true
		w.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.ResponseWriter.WriteHeader(http.StatusNotFound)
		_ = w.s.Templates.ExecuteTemplate(w.ResponseWriter, "notfound.html", map[string]any{"Title": "Tidak Ditemukan — Yue Short"})
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *notFoundWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.converted {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(web.FS, "static")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok"})
}

func (s *Server) handleReadme(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		// fallback: embed dari NEXTJS tidak ada — sajikan ringkas.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("Yue Short — URL Shortener (port Go).\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// ─── POST /api/shorten ───

func (s *Server) handleShorten(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(r)
	if !ok {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	raw := strField(body, "url")
	if strings.TrimSpace(raw) == "" {
		writeErr(w, 400, "URL wajib diisi.")
		return
	}
	originalURL := validate.NormalizeURL(raw)
	if originalURL == "" {
		writeErr(w, 400, "URL tidak valid. Contoh: https://example.com/halaman")
		return
	}
	alias := ""
	if v, isStr := body["alias"].(string); isStr {
		alias = strings.TrimSpace(v)
	}
	if alias != "" {
		if msg := validate.ValidateAliasFormat(alias); msg != "" {
			writeErr(w, 400, msg)
			return
		}
	}
	password := strField(body, "password")
	if password != "" {
		if msg := validate.ValidatePassword(password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
	}
	expiresAt := strField(body, "expiresAt")
	if expiresAt != "" {
		if msg := validate.ValidateExpiresAt(expiresAt); msg != "" {
			writeErr(w, 400, msg)
			return
		}
	}
	user, err := s.resolveUser(r)
	if err != nil {
		writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
		return
	}
	// Custom domain opsional
	var domainID *int64
	var domainName string
	if v, present := body["domainId"]; present && v != nil && v != "" {
		var requested int64
		switch n := v.(type) {
		case json.Number:
			ri, err := n.Int64()
			if err != nil || ri <= 0 {
				writeErr(w, 400, "ID domain tidak valid.")
				return
			}
			requested = ri
		case float64:
			if n != float64(int64(n)) || int64(n) <= 0 {
				writeErr(w, 400, "ID domain tidak valid.")
				return
			}
			requested = int64(n)
		case string:
			if strings.TrimSpace(n) == "" {
				requested = 0
			} else {
				ri, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
				if err != nil || ri <= 0 {
					writeErr(w, 400, "ID domain tidak valid.")
					return
				}
				requested = ri
			}
		default:
			writeErr(w, 400, "ID domain tidak valid.")
			return
		}
		if requested > 0 {
			if user == nil {
				writeErr(w, 401, "Masuk dulu untuk memakai custom domain.")
				return
			}
			domain, err := s.Q.GetDomainByID(requested)
			if err != nil {
				writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
				return
			}
			if domain == nil || domain.UserID != user.ID {
				writeErr(w, 404, "Domain tidak ditemukan.")
				return
			}
			if domain.Status != "verified" {
				writeErr(w, 409, "Domain belum terverifikasi. Selesaikan verifikasi DNS dulu.")
				return
			}
			id := domain.ID
			domainID = &id
			domainName = domain.Hostname
		}
	}
	if alias != "" {
		exists, err := s.Q.AliasExists(alias)
		if err != nil {
			writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
			return
		}
		if exists {
			writeErr(w, 409, "Slug sudah digunakan, coba yang lain.")
			return
		}
	}
	shortCode := alias
	if shortCode == "" {
		// generate unik (coba hingga 5x, lalu 500)
		for i := 0; i < 5; i++ {
			cand := generateCode(7)
			exists, err := s.Q.AliasExists(cand)
			if err != nil {
				writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
				return
			}
			if !exists {
				shortCode = cand
				break
			}
		}
		if shortCode == "" {
			writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
			return
		}
	}
	var pwHash *string
	if password != "" {
		h, err := auth.HashPassword(password)
		if err != nil {
			writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
			return
		}
		pwHash = &h
	}
	var expPtr *string
	if expiresAt != "" {
		expPtr = &expiresAt
	}
	var userID *int64
	if user != nil {
		uid := user.ID
		userID = &uid
	}
	if err := s.Q.InsertURL(shortCode, originalURL, pwHash, expPtr, userID, domainID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeErr(w, 409, "Slug sudah digunakan, coba yang lain.")
			return
		}
		logger.Error("api/shorten", "gagal insert", map[string]any{"error": err.Error()})
		writeErr(w, 500, "Gagal menyimpan URL. Coba lagi.")
		return
	}
	origin := meta.AppOrigin(r)
	shortOrigin := origin
	if domainName != "" {
		shortOrigin = hosts.HostOrigin(domainName)
	}
	resp := map[string]any{"shortUrl": shortOrigin + "/" + shortCode, "shortCode": shortCode, "domainId": nil}
	if domainID != nil {
		resp["domainId"] = *domainID
	}
	writeJSON(w, 201, resp)
}

// ─── GET /{code} redirect publik ───

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" || strings.Contains(code, "/") {
		http.NotFound(w, r)
		return
	}
	if _, reserved := redirectReserved[strings.ToLower(code)]; reserved {
		http.NotFound(w, r)
		return
	}
	// Hindari konflik dengan file statis / halaman yang sudah terdaftar di mux:
	// mux Go memilih pola paling spesifik, jadi handler ini hanya dipanggil
	// untuk path yang belum cocok — tidak perlu daftar tambahan di sini.
	host := hosts.RequestHost(r)
	domainID, denied, err := s.Q.ResolveDomainForHost(host, hosts.IsPrimaryHost, hosts.StrictHostRouting)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if denied {
		http.NotFound(w, r)
		return
	}
	row, err := s.Q.FindByCodeAndDomain(code, domainID)
	if err != nil || row == nil {
		http.NotFound(w, r)
		return
	}
	origin := meta.AppOrigin(r)
	if db.IsExpired(row.ExpiresAt) {
		http.Redirect(w, r, origin+"/expired", http.StatusFound)
		return
	}
	if row.PasswordHash.Valid && row.PasswordHash.String != "" {
		gate := origin + "/pw?code=" + code
		if host != "" && !hosts.IsPrimaryHost(host) {
			gate += "&host=" + host
		}
		http.Redirect(w, r, gate, http.StatusFound)
		return
	}
	m := meta.AnalyticsMeta(r)
	_ = s.Q.RecordRedirect(row, m.Country, m.Device, m.Referrer, m.IPPrefix)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, row.OriginalURL, http.StatusFound)
}

// ─── POST /api/unlock ───

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(r)
	if !ok {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	code := strField(body, "code")
	password := strField(body, "password")
	var explicitHost string
	if v, isStr := body["host"].(string); isStr {
		explicitHost = v
	}
	if code == "" || password == "" {
		writeErr(w, 400, "Kode tautan dan password wajib diisi.")
		return
	}
	// Lapis 0: per IP
	if key := ratelimit.PerIPKey("unlock-flood", r); key != "" {
		lim := ratelimit.Consume(key, ratelimit.UnlockFlood.Max, ratelimit.UnlockFlood.Window)
		if !lim.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(lim.RetryAfter))
			writeErr(w, 429, fmt.Sprintf("Terlalu banyak percobaan. Coba lagi dalam %s.", ratelimit.FormatRetryAfter(lim.RetryAfter)))
			return
		}
	}
	host := hosts.RequestHost(r)
	if explicitHost != "" {
		host = hosts.NormalizeHost(explicitHost)
	}
	domainID, denied, err := s.Q.ResolveDomainForHost(host, hosts.IsPrimaryHost, hosts.StrictHostRouting)
	if err != nil {
		writeErr(w, 500, "Gagal membuka tautan.")
		return
	}
	if denied {
		writeErr(w, 404, "Tautan tidak ditemukan.")
		return
	}
	row, err := s.Q.FindByCodeAndDomain(code, domainID)
	if err != nil {
		writeErr(w, 500, "Gagal membuka tautan.")
		return
	}
	if row == nil || !row.PasswordHash.Valid || row.PasswordHash.String == "" {
		writeErr(w, 404, "Tautan tidak ditemukan atau tidak terproteksi.")
		return
	}
	// Lapis 1: per IP + tautan
	if key := ratelimit.PerIPKey(fmt.Sprintf("unlock-link:%d", row.ID), r); key != "" {
		lim := ratelimit.Consume(key, ratelimit.UnlockIPLink.Max, ratelimit.UnlockIPLink.Window)
		if !lim.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(lim.RetryAfter))
			writeErr(w, 429, fmt.Sprintf("Terlalu banyak percobaan. Coba lagi dalam %s.", ratelimit.FormatRetryAfter(lim.RetryAfter)))
			return
		}
	}
	// Lapis 2: per tautan
	lim := ratelimit.Consume(fmt.Sprintf("unlock-code:%d", row.ID), ratelimit.UnlockLink.Max, ratelimit.UnlockLink.Window)
	if !lim.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(lim.RetryAfter))
		writeErr(w, 429, fmt.Sprintf("Terlalu banyak percobaan. Coba lagi dalam %s.", ratelimit.FormatRetryAfter(lim.RetryAfter)))
		return
	}
	if db.IsExpired(row.ExpiresAt) {
		writeErr(w, 410, "Tautan ini sudah kedaluwarsa.")
		return
	}
	if !auth.VerifyPassword(password, row.PasswordHash.String) {
		writeErr(w, 401, "Password salah. Coba lagi.")
		return
	}
	m := meta.AnalyticsMeta(r)
	_ = s.Q.RecordRedirect(row, m.Country, m.Device, m.Referrer, m.IPPrefix)
	writeJSON(w, 200, map[string]any{"ok": true, "redirect": row.OriginalURL})
}

// serializeDomain — samakan dengan JS.
func serializeDomain(d *db.Domain) map[string]any {
	var lastError, lastCheckedAt, verifiedAt any
	if d.LastError.Valid {
		lastError = d.LastError.String
	}
	if d.LastCheckedAt.Valid {
		lastCheckedAt = d.LastCheckedAt.String
	}
	if d.VerifiedAt.Valid {
		verifiedAt = d.VerifiedAt.String
	}
	return map[string]any{
		"id": d.ID, "hostname": d.Hostname, "status": d.Status,
		"verifyToken":   d.VerifyToken,
		"lastError":     lastError,
		"lastCheckedAt": lastCheckedAt,
		"verifiedAt":    verifiedAt,
		"createdAt":     d.CreatedAt,
		"linkCount":     d.LinkCount,
		"dns":           dnsutil.DNSTargets(d.Hostname, d.VerifyToken),
	}
}

var _ = time.Now
var _ = geo.DetectDevice
