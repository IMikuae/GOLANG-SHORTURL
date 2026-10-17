// Package hosts — port dari NEXTJS-SHORTURL/src/lib/hosts.js.
package hosts

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var localHosts = map[string]struct{}{
	"localhost": {}, "127.0.0.1": {}, "::1": {}, "0.0.0.0": {},
}

// NormalizeHost — buang skema/port/path, lowercase. Nil="" bila invalid.
func NormalizeHost(value string) string {
	if value == "" {
		return ""
	}
	host := strings.TrimSpace(strings.ToLower(value))
	if host == "" {
		return ""
	}
	host = strings.TrimSpace(strings.Split(host, ",")[0])
	host = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`).ReplaceAllString(host, "")
	host = strings.Split(host, "/")[0]
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end == -1 {
			host = host[1:]
		} else {
			host = host[1:end]
		}
	} else if ok, _ := regexp.MatchString(`^[^:]+:\d+$`, host); ok {
		host = host[:strings.LastIndex(host, ":")]
	} else if strings.HasSuffix(host, ":") && !strings.Contains(host, "::") {
		host = host[:len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return ""
	}
	if ok, _ := regexp.MatchString(`^[a-z0-9.-]+$`, host); !ok {
		if ok2, _ := regexp.MatchString(`^[0-9a-f:]+$`, host); !ok2 {
			return ""
		}
	}
	return host
}

// ConfiguredAppHosts — dari APP_DOMAIN + NEXT_PUBLIC_APP_URL.
func ConfiguredAppHosts() map[string]struct{} {
	hosts := map[string]struct{}{}
	for _, raw := range []string{os.Getenv("APP_DOMAIN"), os.Getenv("NEXT_PUBLIC_APP_URL")} {
		if raw == "" {
			continue
		}
		// NEXT_PUBLIC_APP_URL bisa berupa URL penuh — ambil host-nya.
		if strings.Contains(raw, "://") {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				raw = u.Hostname()
			}
		}
		if h := NormalizeHost(raw); h != "" {
			hosts[h] = struct{}{}
		}
	}
	return hosts
}

// StrictHostRouting — true bila operator sudah menyetel APP_DOMAIN/NEXT_PUBLIC_APP_URL.
func StrictHostRouting() bool { return len(ConfiguredAppHosts()) > 0 }

// PrimaryHosts — localhost + configured.
func PrimaryHosts() map[string]struct{} {
	out := map[string]struct{}{}
	for h := range localHosts {
		out[h] = struct{}{}
	}
	for h := range ConfiguredAppHosts() {
		out[h] = struct{}{}
	}
	return out
}

// IsPrimaryHost — true bila host adalah domain utama aplikasi.
func IsPrimaryHost(value string) bool {
	host := NormalizeHost(value)
	if host == "" {
		return false
	}
	if _, ok := PrimaryHosts()[host]; ok {
		return true
	}
	return !StrictHostRouting()
}

// RequestHost — x-forwarded-host dulu, lalu Host.
func RequestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	var raw string
	if fwd := r.Header.Get("x-forwarded-host"); fwd != "" {
		raw = strings.TrimSpace(strings.Split(fwd, ",")[0])
	} else if r.Host != "" {
		raw = r.Host
	} else if r.URL != nil {
		raw = r.URL.Host
	}
	return NormalizeHost(raw)
}

// HostOrigin — http untuk lokal, https selainnya.
func HostOrigin(value string) string {
	host := NormalizeHost(value)
	if host == "" {
		return ""
	}
	if _, ok := localHosts[host]; ok {
		return "http://" + host
	}
	return "https://" + host
}
