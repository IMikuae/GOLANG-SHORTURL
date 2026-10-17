package server

import (
	"html/template"
	"io"
	"testing"
)

func merge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func templateJS(s string) template.JS { return template.JS(s) }

func TestRenderAllPages(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	nav, mobile := buildNav("/dashboard")
	link := linkView{ID: 1, ShortCode: "abc123", ShortURL: "http://x/abc123", EncodedURL: "http%3A%2F%2Fx%2Fabc123", OriginalURL: "https://example.com/a", Clicks: 12, ClicksFmt: "12", Protected: true, ExpiresAt: "2027-01-01", ExpiryShort: "1 Jan", CreatedAt: "2026-01-01", CreatedFmt: "1 Jan 2026", DomainHost: "go.x.com", TopCountry: "ID"}
	base := map[string]any{"Title": "x", "Nav": nav, "MobileNav": mobile, "UserName": "Uji", "UserEmail": "u@x.com", "UserInitial": "U"}
	cases := map[string]map[string]any{
		"index.html":     {"Title": "x"},
		"login.html":     {"Title": "x"},
		"register.html":  {"Title": "x"},
		"pw.html":        {"Title": "x"},
		"expired.html":   {"Title": "x"},
		"notfound.html":  {"Title": "x"},
		"dashboard.html": merge(base, map[string]any{"Greeting": "Halo", "TotalLinks": "1", "TotalClicks": "12", "AvgClicks": "12", "CountryCount": "1", "Links": []linkView{link}, "HasLinks": true}),
		"links.html":     merge(base, map[string]any{"Count": "1", "Links": []linkView{link}, "HasLinks": true}),
		"analytics.html": merge(base, map[string]any{"HasLinks": true, "SeriesJSON": templateJS(`[{"shortCode":"abc123","daily":[{"day":"2026-01-01","total":2}]}]`), "Countries": []distEntry{{Value: "ID", Label: "ID", Clicks: 2, Pct: 100, Width: 100}}, "CountryTotal": int64(2), "HasCountries": true, "Devices": []distEntry{{Value: "desktop", Label: "Desktop", Clicks: 2, Pct: 100, Width: 100}}, "DeviceTotal": int64(2), "HasDevices": true, "CountryReady": true, "Links": []linkView{link}}),
		"qr.html":        merge(base, map[string]any{"Links": []linkView{link}, "HasLinks": true}),
		"api.html":       merge(base, map[string]any{"Origin": "http://x", "APIKey": "ys_live_abc"}),
		"settings.html":  merge(base, map[string]any{"Email": "u@x.com", "DisplayName": "Uji", "Joined": "1 Jan 2026", "LinkCount": int64(1), "LinkCountFmt": "1", "DomainCount": 0}),
	}
	for name, data := range cases {
		if err := s.Templates.ExecuteTemplate(io.Discard, name, data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
