package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shorturl/internal/auth"
	"shorturl/internal/db"
	"shorturl/internal/hosts"
	"shorturl/internal/meta"
)

var idMonthsShort = []string{"", "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"}
var idMonthsLong = []string{"", "Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November", "Desember"}

// parseDBTime — SQLite "2006-01-02 15:04:05" (UTC) atau RFC3339.
func parseDBTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02T15:04:05Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func fmtDateShortID(s string) string {
	t, ok := parseDBTime(s)
	if !ok {
		return s
	}
	return strings.TrimSpace(strings.Join([]string{
		strings.TrimSpace(time.Time.Format(t, "2")),
		idMonthsShort[int(t.Month())],
		time.Time.Format(t, "2006"),
	}, " "))
}

func fmtDateLongID(s string) string {
	t, ok := parseDBTime(s)
	if !ok {
		return s
	}
	return strings.TrimSpace(strings.Join([]string{
		strings.TrimSpace(time.Time.Format(t, "2")),
		idMonthsLong[int(t.Month())],
		time.Time.Format(t, "2006"),
	}, " "))
}

func fmtNumID(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := uintStr(uint64(n))
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	out := strings.Join(append([]string{s}, parts...), ".")
	if neg {
		return "-" + out
	}
	return out
}

func uintStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

type navItem struct {
	Href   string
	Label  string
	Icon   string
	Active bool
}

func buildNav(active string) ([]navItem, []navItem) {
	nav := []navItem{
		{"/dashboard", "Dashboard", "o-squares-2x2", active == "/dashboard"},
		{"/dashboard/links", "Tautan Saya", "o-link", active == "/dashboard/links"},
		{"/dashboard/analytics", "Statistik", "o-chart-bar", active == "/dashboard/analytics"},
		{"/dashboard/qr", "QR Code", "o-qr-code", active == "/dashboard/qr"},
		{"/dashboard/api", "API Access", "o-code-bracket", active == "/dashboard/api"},
		{"/dashboard/settings", "Pengaturan", "o-cog-6-tooth", active == "/dashboard/settings"},
	}
	mobile := []navItem{
		{"/dashboard", "Home", "o-home", active == "/dashboard"},
		{"/dashboard/links", "Links", "o-link", active == "/dashboard/links"},
		{"/dashboard/analytics", "Stats", "o-chart-bar", active == "/dashboard/analytics"},
		{"/dashboard/api", "API", "o-code-bracket", active == "/dashboard/api"},
		{"/dashboard/settings", "More", "o-ellipsis-horizontal", active == "/dashboard/settings"},
	}
	return nav, mobile
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.Templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Gagal merender halaman.", 500)
	}
}

func (s *Server) pageUser(r *http.Request) map[string]any {
	u, _ := auth.AuthUser(s.Q, r)
	if u == nil {
		return nil
	}
	var name string
	if u.Name.Valid {
		name = u.Name.String
	}
	return map[string]any{"id": u.ID, "email": u.Email, "name": name}
}

func dashUser(u map[string]any) (name, email, initial string) {
	email, _ = u["email"].(string)
	name, _ = u["name"].(string)
	display := name
	if display == "" {
		display = email
	}
	if display == "" {
		display = "?"
	}
	initial = strings.ToUpper(string([]rune(display)[:1]))
	if name == "" {
		name = "Pengguna"
	}
	return name, email, initial
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index.html", map[string]any{"Title": "Yue Short — Perpendek Tautanmu"})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if u, _ := auth.AuthUser(s.Q, r); u != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	s.render(w, "login.html", map[string]any{"Title": "Masuk — Yue Short"})
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	if u, _ := auth.AuthUser(s.Q, r); u != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	s.render(w, "register.html", map[string]any{"Title": "Daftar — Yue Short"})
}

func (s *Server) handlePwPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "pw.html", map[string]any{"Title": "Tautan Terproteksi — Yue Short"})
}

func (s *Server) handleExpiredPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "expired.html", map[string]any{"Title": "Tautan Kedaluwarsa — Yue Short"})
}

func (s *Server) needLogin(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	u := s.pageUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return nil, false
	}
	return u, true
}

func (s *Server) domainHosts(uid int64) map[int64]string {
	out := map[int64]string{}
	domains, _ := s.Q.ListDomainsByUser(uid)
	for _, d := range domains {
		out[d.ID] = d.Hostname
	}
	return out
}

type linkView struct {
	ID          int64
	ShortCode   string
	ShortURL    string
	EncodedURL  string
	OriginalURL string
	Clicks      int64
	ClicksFmt   string
	Protected   bool
	ExpiresAt   string
	ExpiryShort string
	CreatedAt   string
	CreatedFmt  string
	DomainHost  string
	TopCountry  string
}

func buildLinkViews(links []*db.URLRow, origin string, hosts map[int64]string) []linkView {
	out := []linkView{}
	for _, l := range links {
		var host string
		shortURL := origin + "/" + l.ShortCode
		if l.DomainID.Valid {
			if h, ok := hosts[l.DomainID.Int64]; ok {
				host = h
				shortURL = "https://" + h + "/" + l.ShortCode
			}
		}
		var exp, expShort string
		if l.ExpiresAt.Valid {
			exp = l.ExpiresAt.String
			if t, ok := parseDBTime(exp + "T00:00:00Z"); ok {
				expShort = strings.TrimSpace(uintStr(uint64(t.Day())) + " " + idMonthsShort[int(t.Month())])
			}
		}
		out = append(out, linkView{
			ID: l.ID, ShortCode: l.ShortCode, ShortURL: shortURL,
			EncodedURL:  url.QueryEscape(shortURL),
			OriginalURL: l.OriginalURL, Clicks: l.Clicks, ClicksFmt: fmtNumID(l.Clicks),
			Protected: l.PasswordHash.Valid && l.PasswordHash.String != "",
			ExpiresAt: exp, ExpiryShort: expShort,
			CreatedAt: l.CreatedAt, CreatedFmt: fmtDateShortID(l.CreatedAt),
			DomainHost: host,
		})
	}
	return out
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	origin := meta.AppOrigin(r)
	links, _ := s.Q.ListLinksByUser(uid)
	totalClicks := int64(0)
	for _, l := range links {
		totalClicks += l.Clicks
	}
	avg := int64(0)
	if len(links) > 0 {
		avg = totalClicks / int64(len(links))
	}
	countries, _ := s.Q.CountCountriesByUser(uid)
	dh := s.domainHosts(uid)
	views := buildLinkViews(links, origin, dh)
	if len(views) > 5 {
		views = views[:5]
	}
	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard")
	s.render(w, "dashboard.html", map[string]any{
		"Title": "Dashboard — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"Greeting":   greeting(name, u),
		"TotalLinks": fmtNumID(int64(len(links))), "TotalClicks": fmtNumID(totalClicks),
		"AvgClicks": fmtNumID(avg), "CountryCount": fmtNumID(countries),
		"Links": views, "HasLinks": len(views) > 0,
	})
}

func greeting(name string, u map[string]any) string {
	if n, _ := u["name"].(string); n != "" {
		return "Halo, " + n + " 👋"
	}
	return "Dashboard"
}

func (s *Server) handleDashboardLinks(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	origin := meta.AppOrigin(r)
	links, _ := s.Q.ListLinksByUser(uid)
	views := buildLinkViews(links, origin, s.domainHosts(uid))
	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard/links")
	s.render(w, "links.html", map[string]any{
		"Title": "Tautan Saya — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"Count": fmtNumID(int64(len(links))),
		"Links": views, "HasLinks": len(views) > 0,
	})
}

type distEntry struct {
	Value  string
	Label  string
	Clicks int64
	Pct    int64
	Width  int64
}

func fillDist(entries []distEntry, total int64) []distEntry {
	var max int64 = 1
	for _, e := range entries {
		if e.Clicks > max {
			max = e.Clicks
		}
	}
	for i := range entries {
		if total > 0 {
			entries[i].Pct = (entries[i].Clicks*100 + total/2) / total
		}
		w := (entries[i].Clicks*100 + max/2) / max
		if w < 4 {
			w = 4
		}
		entries[i].Width = w
	}
	return entries
}

func (s *Server) handleDashboardAnalytics(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	links, _ := s.Q.ListLinksByUser(uid)

	type daily struct {
		Day   string `json:"day"`
		Total int64  `json:"total"`
	}
	type serie struct {
		ShortCode string  `json:"shortCode"`
		Daily     []daily `json:"daily"`
	}
	series := []serie{}
	for i, l := range links {
		if i >= 10 {
			break
		}
		rows, _ := s.Q.GetClicksDaily(l.ID, 30)
		dd := []daily{}
		for _, d := range rows {
			dd = append(dd, daily{d.Day, d.Total})
		}
		if dd == nil {
			dd = []daily{}
		}
		series = append(series, serie{l.ShortCode, dd})
	}
	seriesJSON, _ := json.Marshal(series)

	countries, _ := s.Q.GetCountryStatsByUser(uid, 30, 0)
	devices, _ := s.Q.GetDeviceStatsByUser(uid, 30)
	totalClicks, _ := s.Q.CountClicksByUser(uid, 30)

	countryEntries := []distEntry{}
	var countryTotal int64
	for _, c := range countries {
		countryEntries = append(countryEntries, distEntry{
			Value: c["country"].(string), Label: c["country"].(string), Clicks: c["clicks"].(int64),
		})
		countryTotal += c["clicks"].(int64)
	}
	countryEntries = fillDist(countryEntries, countryTotal)
	deviceLabels := map[string]string{"desktop": "Desktop", "mobile": "Mobile", "tablet": "Tablet", "unknown": "Tidak dikenal"}
	deviceEntries := []distEntry{}
	var deviceTotal int64
	for _, d := range devices {
		dv := d["device"].(string)
		label := dv
		if l, ok := deviceLabels[dv]; ok {
			label = l
		}
		deviceEntries = append(deviceEntries, distEntry{Value: dv, Label: label, Clicks: d["clicks"].(int64)})
		deviceTotal += d["clicks"].(int64)
	}
	deviceEntries = fillDist(deviceEntries, deviceTotal)

	views := buildLinkViews(links, "", s.domainHosts(uid))
	for i := range views {
		top, _ := s.Q.GetTopCountryByURL(links[i].ID)
		views[i].TopCountry = top
	}

	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard/analytics")
	s.render(w, "analytics.html", map[string]any{
		"Title": "Statistik — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"HasLinks":   len(links) > 0,
		"SeriesJSON": template.JS(seriesJSON),
		"Countries":  countryEntries, "CountryTotal": countryTotal, "HasCountries": len(countryEntries) > 0,
		"Devices": deviceEntries, "DeviceTotal": deviceTotal, "HasDevices": len(deviceEntries) > 0,
		"CountryReady": totalClicks > 0 && len(countryEntries) > 0,
		"Links":        views,
	})
}

func (s *Server) handleDashboardQR(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	origin := meta.AppOrigin(r)
	links, _ := s.Q.ListLinksByUser(uid)
	if len(links) > 12 {
		links = links[:12]
	}
	views := buildLinkViews(links, origin, s.domainHosts(uid))
	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard/qr")
	s.render(w, "qr.html", map[string]any{
		"Title": "QR Code — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"Links": views, "HasLinks": len(views) > 0,
	})
}

func (s *Server) handleDashboardAPI(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	origin := meta.AppOrigin(r)
	full, _ := s.Q.FindUserByID(uid)
	apiKey := ""
	if full != nil && full.APIKey.Valid {
		apiKey = full.APIKey.String
	}
	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard/api")
	s.render(w, "api.html", map[string]any{
		"Title": "API Access — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"Origin": origin, "APIKey": apiKey,
	})
}

func (s *Server) handleDashboardSettings(w http.ResponseWriter, r *http.Request) {
	u, ok := s.needLogin(w, r)
	if !ok {
		return
	}
	uid := u["id"].(int64)
	full, _ := s.Q.FindUserByID(uid)
	linkCount, _ := s.Q.CountLinksByUser(uid)
	domains, _ := s.Q.ListDomainsByUser(uid)
	name, email, initial := dashUser(u)
	nav, mobile := buildNav("/dashboard/settings")
	joined := ""
	userName := ""
	if full != nil {
		joined = fmtDateLongID(full.CreatedAt)
		if full.Name.Valid {
			userName = full.Name.String
		}
	}
	s.render(w, "settings.html", map[string]any{
		"Title": "Pengaturan — Yue Short",
		"Nav":   nav, "MobileNav": mobile,
		"UserName": name, "UserEmail": email, "UserInitial": initial,
		"Email": email, "DisplayName": userName, "Joined": joined,
		"LinkCount": linkCount, "LinkCountFmt": fmtNumID(linkCount),
		"DomainCount": len(domains),
	})
}

var _ = hosts.StrictHostRouting
