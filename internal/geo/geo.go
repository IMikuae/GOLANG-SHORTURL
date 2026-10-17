// Package geo — port dari NEXTJS-SHORTURL/src/lib/geo.js.
package geo

import (
	"net/http"
	"os"
	"regexp"
	"strings"
)

var CountryHeaders = []string{
	"cf-ipcountry",
	"x-vercel-ip-country",
	"x-country-code",
	"x-geo-country",
	"x-appengine-country",
	"x-country",
}

func NormalizeCountry(raw string) string {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if len(value) != 2 {
		return ""
	}
	if ok, _ := regexp.MatchString(`^[A-Z]{2}$`, value); !ok {
		return ""
	}
	if value == "XX" {
		return ""
	}
	return value
}

func customCountryHeader() string {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("GEO_COUNTRY_HEADER")))
	if name == "" {
		return ""
	}
	if ok, _ := regexp.MatchString(`^[a-z0-9-]{1,64}$`, name); !ok {
		return ""
	}
	return name
}

// ResolveCountry — rantai prioritas header → kode ISO atau "".
func ResolveCountry(r *http.Request) string {
	if r == nil {
		return ""
	}
	if custom := customCountryHeader(); custom != "" {
		if v := NormalizeCountry(r.Header.Get(custom)); v != "" {
			return v
		}
	}
	for _, name := range CountryHeaders {
		if v := NormalizeCountry(r.Header.Get(name)); v != "" {
			return v
		}
	}
	return ""
}

// SanitizeIP — bersihkan IP mentah, return "" bila bukan IP.
func SanitizeIP(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 45 {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end == -1 {
			value = value[1:]
		} else {
			value = value[1:end]
		}
	} else if ok, _ := regexp.MatchString(`^[\d.]+:\d+$`, value); ok {
		value = value[:strings.LastIndex(value, ":")]
	}
	if ok, _ := regexp.MatchString(`^[0-9a-f:.]+$`, value); !ok {
		return ""
	}
	if len(strings.Split(value, ".")) > 4 && !strings.Contains(value, ":") {
		return ""
	}
	if strings.Contains(value, ":") {
		if len(strings.Split(value, ":")) > 9 {
			return ""
		}
	} else {
		if ok, _ := regexp.MatchString(`^\d{1,3}(\.\d{1,3}){3}$`, value); !ok {
			return ""
		}
		for _, p := range strings.Split(value, ".") {
			n := 0
			for _, c := range p {
				n = n*10 + int(c-'0')
			}
			if n > 255 {
				return ""
			}
		}
	}
	return value
}

// ClientIP — dari header proxy; "" bila TRUST_PROXY=0 atau tak ada.
func ClientIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY") == "0" {
		return ""
	}
	if r == nil {
		return ""
	}
	if v := SanitizeIP(r.Header.Get("cf-connecting-ip")); v != "" {
		return v
	}
	if fwd := r.Header.Get("x-forwarded-for"); fwd != "" {
		if v := SanitizeIP(strings.Split(fwd, ",")[0]); v != "" {
			return v
		}
	}
	if v := SanitizeIP(r.Header.Get("x-real-ip")); v != "" {
		return v
	}
	return ""
}

func expandIPv6(address string) []string {
	var head, tail []string
	var groups []string
	hasDouble := strings.Contains(address, "::")
	if hasDouble {
		sp := strings.SplitN(address, "::", 2)
		if sp[0] != "" {
			head = strings.Split(sp[0], ":")
			var h []string
			for _, g := range head {
				if g != "" {
					h = append(h, g)
				}
			}
			head = h
		}
		if sp[1] != "" {
			tail = strings.Split(sp[1], ":")
			var t []string
			for _, g := range tail {
				if g != "" {
					t = append(t, g)
				}
			}
			tail = t
		}
		groups = append(append([]string{}, head...), tail...)
		missing := 8 - len(groups)
		if missing < 1 {
			return nil
		}
		merged := append([]string{}, head...)
		for i := 0; i < missing; i++ {
			merged = append(merged, "0")
		}
		merged = append(merged, tail...)
		if len(merged) != 8 {
			return nil
		}
		for _, g := range merged {
			if ok, _ := regexp.MatchString(`^[0-9a-f]{1,4}$`, g); !ok {
				return nil
			}
		}
		out := make([]string, 8)
		for i, g := range merged {
			out[i] = strings.Repeat("0", 4-len(g)) + g
		}
		return out
	}
	groups = strings.Split(address, ":")
	if len(groups) != 8 {
		return nil
	}
	for _, g := range groups {
		if ok, _ := regexp.MatchString(`^[0-9a-f]{1,4}$`, g); !ok {
			return nil
		}
	}
	out := make([]string, 8)
	for i, g := range groups {
		out[i] = strings.Repeat("0", 4-len(g)) + g
	}
	return out
}

// IPPrefix — IPv4 → a.b.c.x, IPv6 → g1:g2:g3:g4:: ("" bila invalid).
func IPPrefix(ip string) string {
	value := SanitizeIP(ip)
	if value == "" {
		return ""
	}
	if strings.Contains(value, ":") {
		if m := regexp.MustCompile(`^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$`).FindStringSubmatch(value); m != nil {
			return ipv4Prefix(m[1])
		}
		groups := expandIPv6(value)
		if groups == nil {
			return ""
		}
		return strings.Join(groups[:4], ":") + "::"
	}
	return ipv4Prefix(value)
}

func ipv4Prefix(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".x"
}

// DetectDevice — mobile/tablet/desktop/unknown dari User-Agent.
func DetectDevice(ua string) string {
	if ua == "" {
		return "unknown"
	}
	lower := strings.ToLower(ua)
	if strings.Contains(lower, "tablet") || strings.Contains(lower, "ipad") {
		return "tablet"
	}
	if strings.Contains(lower, "mobile") || strings.Contains(lower, "iphone") || strings.Contains(lower, "android") {
		return "mobile"
	}
	return "desktop"
}
