// Package meta — port dari NEXTJS-SHORTURL/src/lib/request-meta.js.
package meta

import (
	"net/http"
	"strings"

	"shorturl/internal/geo"
)

type Analytics struct {
	Country  *string
	Device   *string
	Referrer *string
	IPPrefix *string
}

func strptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// AnalyticsMeta — negara/perangkat/referrer/prefix IP dari request.
func AnalyticsMeta(r *http.Request) Analytics {
	var referrer *string
	if r != nil {
		if v := r.Header.Get("referer"); v != "" {
			if len(v) > 512 {
				v = v[:512]
			}
			referrer = &v
		}
	}
	country := geo.ResolveCountry(r)
	device := "unknown"
	if r != nil {
		device = geo.DetectDevice(r.Header.Get("user-agent"))
	}
	ipPrefix := geo.IPPrefix(geo.ClientIP(r))
	return Analytics{
		Country:  strptr(country),
		Device:   strptr(device),
		Referrer: referrer,
		IPPrefix: strptr(ipPrefix),
	}
}

// AppOrigin — NEXT_PUBLIC_APP_URL → skema+host request → localhost.
func AppOrigin(r *http.Request) string {
	_ = strings.TrimSpace
	if v := envPublicAppURL(); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	if r != nil {
		host := r.Header.Get("x-forwarded-host")
		if host == "" {
			host = r.Host
		}
		if host != "" {
			proto := r.Header.Get("x-forwarded-proto")
			if proto == "" {
				if strings.HasPrefix(host, "localhost") {
					proto = "http"
				} else {
					proto = "https"
				}
			}
			return proto + "://" + host
		}
	}
	return "http://localhost:3000"
}
