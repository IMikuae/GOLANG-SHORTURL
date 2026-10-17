package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"

	dnsutil "shorturl/internal/dns"
	"shorturl/internal/logger"
	"shorturl/internal/ratelimit"
	"shorturl/internal/validate"
)

// GET /api/domains
func (s *Server) handleDomainsList(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	domains, err := s.Q.ListDomainsByUser(user.ID)
	if err != nil {
		writeErr(w, 500, "Gagal memuat domain.")
		return
	}
	out := []map[string]any{}
	for _, d := range domains {
		out = append(out, serializeDomain(d))
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"domains": out})
}

// POST /api/domains
func (s *Server) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	lim := ratelimit.Consume("domain-add:"+itoa64(user.ID), ratelimit.AddDomain.Max, ratelimit.AddDomain.Window)
	if !lim.Allowed {
		w.Header().Set("Retry-After", itoa(lim.RetryAfter))
		writeErr(w, 429, "Terlalu banyak penambahan domain. Coba lagi dalam "+ratelimit.FormatRetryAfter(lim.RetryAfter)+".")
		return
	}
	body, valid := readJSON(r)
	if !valid {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	hostname := validate.NormalizeHostname(strField(body, "hostname"))
	if msg := validate.ValidateHostname(hostname); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if existing, err := s.Q.FindDomainByHostname(hostname); err != nil {
		writeErr(w, 500, "Gagal menambahkan domain.")
		return
	} else if existing != nil {
		writeErr(w, 409, "Domain ini sudah terdaftar.")
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := "yue-verify=" + hex.EncodeToString(b)
	if _, err := s.Q.InsertDomain(user.ID, hostname, token); err != nil {
		writeErr(w, 500, "Gagal menambahkan domain.")
		return
	}
	logger.Info("api/domains", "Domain ditambahkan", map[string]any{"userId": user.ID, "hostname": hostname})
	domains, _ := s.Q.ListDomainsByUser(user.ID)
	for _, d := range domains {
		if d.Hostname == hostname {
			writeJSON(w, 201, map[string]any{"ok": true, "domain": serializeDomain(d)})
			return
		}
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

// DELETE /api/domains/{id}
func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	domainID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || domainID <= 0 {
		writeErr(w, 400, "ID domain tidak valid.")
		return
	}
	domain, err := s.Q.GetDomainByID(domainID)
	if err != nil {
		writeErr(w, 500, "Gagal menghapus domain.")
		return
	}
	if domain == nil || domain.UserID != user.ID {
		writeErr(w, 404, "Domain tidak ditemukan.")
		return
	}
	if err := s.Q.DeleteDomainWithUnlink(domain.ID); err != nil {
		writeErr(w, 500, "Gagal menghapus domain.")
		return
	}
	logger.Info("api/domains", "Domain dilepas", map[string]any{"userId": user.ID, "hostname": domain.Hostname})
	writeJSON(w, 200, map[string]any{"ok": true, "hostname": domain.Hostname})
}

// POST /api/domains/{id}/verify
func (s *Server) handleDomainVerify(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	domainID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || domainID <= 0 {
		writeErr(w, 400, "ID domain tidak valid.")
		return
	}
	lim := ratelimit.Consume("domain-verify:"+itoa64(domainID), ratelimit.VerifyDomain.Max, ratelimit.VerifyDomain.Window)
	if !lim.Allowed {
		w.Header().Set("Retry-After", itoa(lim.RetryAfter))
		writeErr(w, 429, "Tunggu "+itoa(lim.RetryAfter)+" detik sebelum memeriksa lagi.")
		return
	}
	domain, err := s.Q.GetDomainByID(domainID)
	if err != nil {
		writeErr(w, 500, "Gagal memverifikasi domain.")
		return
	}
	if domain == nil || domain.UserID != user.ID {
		writeErr(w, 404, "Domain tidak ditemukan.")
		return
	}
	result := dnsutil.VerifyDomainDNS(domain.Hostname, domain.VerifyToken, nil)
	_ = s.Q.SetDomainVerification(domain.ID, result.Status, result.Error)
	if result.Status == "verified" {
		var method string
		if result.Method != nil {
			method = *result.Method
		}
		logger.Info("api/domains/verify", "Domain terverifikasi", map[string]any{"userId": user.ID, "hostname": domain.Hostname, "method": method})
	}
	var methodAny, msgAny any
	if result.Method != nil {
		methodAny = *result.Method
	}
	if result.Status == "verified" {
		m := ""
		if result.Method != nil {
			m = *result.Method
		}
		msgAny = "Domain terverifikasi lewat record " + m + "."
	} else if result.Error != nil {
		msgAny = *result.Error
	}
	writeJSON(w, 200, map[string]any{
		"ok": result.Status == "verified", "status": result.Status,
		"method": methodAny, "message": msgAny,
		"dns": dnsutil.DNSTargets(domain.Hostname, domain.VerifyToken),
	})
}

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
