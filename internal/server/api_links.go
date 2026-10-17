package server

import (
	"net/http"
	"strconv"

	"shorturl/internal/hosts"
	"shorturl/internal/meta"
	"shorturl/internal/validate"
)

// GET /api/links
func (s *Server) handleLinksList(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	links, err := s.Q.ListLinksByUser(user.ID)
	if err != nil {
		writeErr(w, 500, "Gagal memuat tautan.")
		return
	}
	origin := meta.AppOrigin(r)
	host := hosts.RequestHost(r)
	domainID, _, _ := s.Q.ResolveDomainForHost(host, hosts.IsPrimaryHost, hosts.StrictHostRouting)
	var currentDomainID any
	if domainID != nil {
		currentDomainID = *domainID
	}
	appHosts := []string{}
	for h := range hosts.ConfiguredAppHosts() {
		appHosts = append(appHosts, h)
	}
	out := []map[string]any{}
	for _, l := range links {
		var did any
		if l.DomainID.Valid {
			did = l.DomainID.Int64
		}
		var exp, created any = nil, l.CreatedAt
		if l.ExpiresAt.Valid {
			exp = l.ExpiresAt.String
		}
		out = append(out, map[string]any{
			"id": l.ID, "shortCode": l.ShortCode,
			"shortUrl":    origin + "/" + l.ShortCode,
			"originalUrl": l.OriginalURL, "clicks": l.Clicks,
			"protected": l.PasswordHash.Valid && l.PasswordHash.String != "",
			"expiresAt": exp, "createdAt": created, "domainId": did,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	total, _ := s.Q.CountLinksByUser(user.ID)
	writeJSON(w, 200, map[string]any{
		"links": out, "totalLinks": total,
		"hostRouting": map[string]any{
			"strict": strictBool(), "currentDomainId": currentDomainID, "appHosts": appHosts,
		},
	})
}

func strictBool() bool { return hosts.StrictHostRouting() }

// POST /api/links — edit tujuan
func (s *Server) handleLinksEdit(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	body, valid := readJSON(r)
	if !valid {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	var id int64
	switch v := body["id"].(type) {
	case float64:
		id = int64(v)
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, 400, "ID tautan tidak valid.")
			return
		}
		id = parsed
	default:
		// json.Number karena UseNumber
		if n, isNum := body["id"].(interface{ Int64() (int64, error) }); isNum {
			ri, err := n.Int64()
			if err != nil {
				writeErr(w, 400, "ID tautan tidak valid.")
				return
			}
			id = ri
		} else {
			writeErr(w, 400, "ID tautan tidak valid.")
			return
		}
	}
	if id <= 0 {
		writeErr(w, 400, "ID tautan tidak valid.")
		return
	}
	rawURL := strField(body, "url")
	originalURL := validate.NormalizeURL(rawURL)
	if originalURL == "" {
		writeErr(w, 400, "URL tujuan baru tidak valid.")
		return
	}
	link, err := s.Q.GetLinkByID(id)
	if err != nil {
		writeErr(w, 500, "Gagal mengubah tautan.")
		return
	}
	if link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
		writeErr(w, 404, "Tautan tidak ditemukan.")
		return
	}
	if err := s.Q.UpdateLinkDestination(id, originalURL); err != nil {
		writeErr(w, 500, "Gagal mengubah tautan.")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "originalUrl": originalURL})
}

// GET /api/links/{id}
func (s *Server) handleLinkDetail(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	linkID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || linkID <= 0 {
		writeErr(w, 400, "ID tidak valid.")
		return
	}
	link, err := s.Q.GetLinkByID(linkID)
	if err != nil {
		writeErr(w, 500, "Gagal memuat detail.")
		return
	}
	if link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
		writeErr(w, 404, "Tautan tidak ditemukan.")
		return
	}
	clicks, err := s.Q.GetClicksByURL(linkID, 30)
	if err != nil {
		writeErr(w, 500, "Gagal memuat detail.")
		return
	}
	daily, err := s.Q.GetClicksDaily(linkID, 30)
	if err != nil {
		writeErr(w, 500, "Gagal memuat detail.")
		return
	}
	byDevice := map[string]int64{}
	byCountry := map[string]int64{}
	byReferrer := map[string]int64{}
	for _, c := range clicks {
		if c.Device.Valid && c.Device.String != "" {
			byDevice[c.Device.String]++
		}
		if c.Country.Valid && c.Country.String != "" {
			byCountry[c.Country.String]++
		}
		if c.Referrer.Valid && c.Referrer.String != "" {
			byReferrer[c.Referrer.String]++
		}
	}
	topCountry, _ := s.Q.GetTopCountryByURL(linkID)
	var topAny any
	if topCountry != "" {
		topAny = topCountry
	}
	var did, exp any
	if link.DomainID.Valid {
		did = link.DomainID.Int64
	}
	if link.ExpiresAt.Valid {
		exp = link.ExpiresAt.String
	}
	writeJSON(w, 200, map[string]any{
		"link": map[string]any{
			"id": link.ID, "shortCode": link.ShortCode, "originalUrl": link.OriginalURL,
			"clicks":    link.Clicks,
			"protected": link.PasswordHash.Valid && link.PasswordHash.String != "",
			"expiresAt": exp, "createdAt": link.CreatedAt, "domainId": did,
		},
		"analytics": map[string]any{
			"daily": daily, "devices": byDevice, "countries": byCountry,
			"referrers": byReferrer, "topCountry": topAny, "totalTracked": len(clicks),
		},
	})
}

// DELETE /api/links/{id}
func (s *Server) handleLinkDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	linkID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || linkID <= 0 {
		writeErr(w, 400, "ID tidak valid.")
		return
	}
	link, err := s.Q.GetLinkByID(linkID)
	if err != nil {
		writeErr(w, 500, "Gagal menghapus tautan.")
		return
	}
	if link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
		writeErr(w, 404, "Tautan tidak ditemukan.")
		return
	}
	if err := s.Q.DeleteLink(linkID); err != nil {
		writeErr(w, 500, "Gagal menghapus tautan.")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
