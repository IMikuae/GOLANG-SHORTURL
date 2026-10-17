// Package validate — port 1:1 dari NEXTJS-SHORTURL/src/lib/validate.js.
// Validasi URL + anti-SSRF + alias + password + expiry + email + hostname.
package validate

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ReservedCodes = map[string]struct{}{
	"api": {}, "admin": {}, "dashboard": {}, "login": {}, "register": {},
	"settings": {}, "pw": {}, "expired": {}, "static": {}, "assets": {},
	"favicon.ico": {}, "robots.txt": {}, "sitemap.xml": {},
}

var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+\-.]*://`)

// NormalizeUrl: trim, default https://, hanya http/https, tolak SSRF literal,
// wajib ada titik di hostname. Return "" bila tidak valid.
func NormalizeURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	withScheme := value
	if !schemeRe.MatchString(value) {
		withScheme = "https://" + value
	}
	parsed, err := url.Parse(withScheme)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if IsBlockedHostname(parsed.Hostname()) {
		return ""
	}
	if !strings.Contains(parsed.Hostname(), ".") {
		return ""
	}
	return parsed.String()
}

var blockedSuffixes = []string{".local", ".internal", ".localhost", ".home.arpa"}

// IsBlockedHostname — true bila hostname tidak boleh jadi tujuan tautan.
func IsBlockedHostname(hostname string) bool {
	host := strings.ToLower(strings.TrimSpace(hostname))
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, s := range blockedSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	if v4, ok := ParseIPv4(host); ok {
		return IsPrivateIPv4(v4)
	}
	if strings.Contains(host, ":") {
		groups := ExpandIPv6(host)
		if groups == nil {
			return true
		}
		return IsPrivateIPv6(groups)
	}
	return false
}

// ParseIPv4 — semantik inet_aton: desimal/oktal/hex, bagian terakhir menampung sisa.
// Return (nilai32, true) bila valid.
func ParseIPv4(host string) (uint32, bool) {
	okChars := true
	for _, c := range host {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == 'x' || c == 'X' || c == '.') {
			okChars = false
		}
	}
	if !okChars {
		return 0, false
	}
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return 0, false
	}
	parsed := make([]uint64, 0, len(parts))
	hexRe := regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
	octRe := regexp.MustCompile(`^0[0-7]+$`)
	decRe := regexp.MustCompile(`^\d+$`)
	for _, part := range parts {
		if part == "" {
			return 0, false
		}
		var v uint64
		var err error
		switch {
		case hexRe.MatchString(part):
			_, err = parseBase(part[2:], 16, &v)
		case octRe.MatchString(part):
			_, err = parseBase(part[1:], 8, &v)
			if part == "0" {
				v = 0
			}
		case decRe.MatchString(part):
			_, err = parseBase(part, 10, &v)
		default:
			return 0, false
		}
		if err != nil {
			return 0, false
		}
		parsed = append(parsed, v)
	}
	n := len(parsed)
	for i := 0; i < n-1; i++ {
		if parsed[i] > 255 {
			return 0, false
		}
	}
	lastMax := uint64(1)
	for i := 0; i < 4-(n-1); i++ {
		lastMax *= 256
	}
	if parsed[n-1] >= lastMax {
		return 0, false
	}
	var value uint64
	for i := 0; i < n-1; i++ {
		value = value*256 + parsed[i]
	}
	value = value*lastMax + parsed[n-1]
	return uint32(value), true
}

func parseBase(s string, base int, out *uint64) (uint64, error) {
	var v uint64
	digits := "0123456789abcdef"
	if s == "" {
		// oktal "0" yang dipotong → s kosong berarti 0
		*out = 0
		return 0, nil
	}
	for _, c := range strings.ToLower(s) {
		d := strings.IndexRune(digits, c)
		if d < 0 || d >= base {
			return 0, errors.New("digit tidak valid")
		}
		v = v*uint64(base) + uint64(d)
	}
	*out = v
	return v, nil
}

// IsPrivateIPv4 — ruang privat/loopback/link-local/dst.
func IsPrivateIPv4(v uint32) bool {
	a := byte(v >> 24)
	b := byte(v >> 16)
	switch {
	case a == 0:
		return true
	case a == 10:
		return true
	case a == 127:
		return true
	case a == 169 && b == 254:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 192 && b == 0:
		return true
	case a == 198 && (b == 18 || b == 19):
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true
	case a >= 224:
		return true
	}
	return false
}

// ExpandIPv6 — "::" → 8 grup hex lowercase 4-digit. Nil bila invalid.
func ExpandIPv6(address string) []string {
	addr := address
	if i := strings.Index(addr, "%"); i != -1 {
		addr = addr[:i]
	}
	if strings.Count(addr, "::") > 1 {
		return nil
	}
	hexGrp := regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)
	var head, tail []string
	if strings.Contains(addr, "::") {
		sp := strings.SplitN(addr, "::", 2)
		if sp[0] != "" {
			head = strings.Split(sp[0], ":")
		}
		if sp[1] != "" {
			tail = strings.Split(sp[1], ":")
		}
		groups := append(append([]string{}, head...), tail...)
		if len(groups) > 7 {
			return nil
		}
		missing := 8 - len(groups)
		merged := append([]string{}, head...)
		for i := 0; i < missing; i++ {
			merged = append(merged, "0")
		}
		merged = append(merged, tail...)
		if len(merged) != 8 {
			return nil
		}
		for _, g := range merged {
			if !hexGrp.MatchString(g) {
				// grup kosong tidak boleh ada di sini
				return nil
			}
		}
		out := make([]string, 8)
		for i, g := range merged {
			out[i] = strings.ToLower(strings.Repeat("0", 4-len(g)) + g)
		}
		return out
	}
	groups := strings.Split(addr, ":")
	if len(groups) != 8 {
		return nil
	}
	for _, g := range groups {
		if !hexGrp.MatchString(g) {
			return nil
		}
	}
	out := make([]string, 8)
	for i, g := range groups {
		out[i] = strings.ToLower(strings.Repeat("0", 4-len(g)) + g)
	}
	return out
}

// IsPrivateIPv6 — ::, ::1, fc00::/7, fe80::/10, ff00::/8, 6to4, mapped.
func IsPrivateIPv6(groups []string) bool {
	if len(groups) != 8 {
		return true
	}
	allZero := true
	for _, g := range groups {
		if g != "0000" {
			allZero = false
		}
	}
	if allZero {
		return true
	}
	first := parseHex16(groups[0])
	if first&0xfe00 == 0xfc00 {
		return true
	}
	if first&0xffc0 == 0xfe80 {
		return true
	}
	if first&0xff00 == 0xff00 {
		return true
	}
	if first == 0x2002 {
		return true
	}
	// ::ffff:a.b.c.d (mapped) — cek IPv4-nya
	mapped := true
	for i := 0; i < 5; i++ {
		if groups[i] != "0000" {
			mapped = false
		}
	}
	if mapped && groups[5] == "ffff" {
		o := []int{
			hexByte(groups[6][:2]), hexByte(groups[6][2:]),
			hexByte(groups[7][:2]), hexByte(groups[7][2:]),
		}
		v := uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3])
		return IsPrivateIPv4(v)
	}
	// ::1 tertangkap allZero? tidak — cek eksplisit
	if first == 0 {
		zero7 := true
		for i := 0; i < 7; i++ {
			if groups[i] != "0000" {
				zero7 = false
			}
		}
		if zero7 {
			return true
		}
	}
	_ = net.ParseIP // jaga import net bila tak terpakai di masa depan
	return false
}

func parseHex16(s string) int {
	v := 0
	for _, c := range strings.ToLower(s) {
		v *= 16
		switch {
		case c >= '0' && c <= '9':
			v += int(c - '0')
		case c >= 'a' && c <= 'f':
			v += int(c-'a') + 10
		}
	}
	return v
}

func hexByte(s string) int { return parseHex16(s) }

// ValidateAliasFormat — return pesan error atau "" bila sah.
func ValidateAliasFormat(alias string) string {
	value := strings.TrimSpace(alias)
	if value == "" {
		return "Slug wajib diisi bila dipakai."
	}
	if len(value) > 32 {
		return "Slug maksimal 32 karakter."
	}
	if ok, _ := regexp.MatchString(`^[a-zA-Z0-9-]+$`, value); !ok {
		return "Gunakan huruf, angka, dan tanda hubung saja."
	}
	if strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return "Slug tidak boleh diawali/diakhiri tanda hubung."
	}
	if _, reserved := ReservedCodes[strings.ToLower(value)]; reserved {
		return "Slug ini dipakai sistem, pilih yang lain."
	}
	return ""
}

// ValidatePassword — password tautan 4–64 char.
func ValidatePassword(password string) string {
	if len(password) < 4 {
		return "Password minimal 4 karakter."
	}
	if len(password) > 64 {
		return "Password maksimal 64 karakter."
	}
	return ""
}

// TodayStr — tanggal lokal YYYY-MM-DD.
func TodayStr() string { return time.Now().Format("2006-01-02") }

// ValidateExpiresAt — YYYY-MM-DD, tidak boleh masa lalu.
func ValidateExpiresAt(expiresAt string) string {
	if ok, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, expiresAt); !ok {
		return "Format tanggal tidak valid."
	}
	if expiresAt < TodayStr() {
		return "Tanggal kedaluwarsa tidak boleh di masa lalu."
	}
	return ""
}

// ValidateEmail — mirror validate.js.
func ValidateEmail(email string) string {
	if email == "" {
		return "Email wajib diisi."
	}
	if len(email) > 254 {
		return "Email terlalu panjang."
	}
	if ok, _ := regexp.MatchString(`^[^\s@]+@[^\s@]+\.[^\s@]+$`, email); !ok {
		return "Format email tidak valid."
	}
	return ""
}

// ValidateRegisterPassword — 8–72 char, harus huruf+angka.
func ValidateRegisterPassword(password string) string {
	if password == "" {
		return "Password wajib diisi."
	}
	if len(password) < 8 {
		return "Password minimal 8 karakter."
	}
	if len(password) > 72 {
		return "Password maksimal 72 karakter."
	}
	hasLetter, _ := regexp.MatchString(`[a-zA-Z]`, password)
	hasDigit, _ := regexp.MatchString(`\d`, password)
	if !hasLetter || !hasDigit {
		return "Password harus mengandung huruf dan angka."
	}
	return ""
}

// NormalizeHostname — lowercase, buang skema/path/port/titik akhir.
func NormalizeHostname(raw string) string {
	if raw == "" {
		return ""
	}
	value := strings.TrimSpace(strings.ToLower(raw))
	value = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`).ReplaceAllString(value, "")
	for _, cut := range []string{"/", "?", "#"} {
		if i := strings.Index(value, cut); i != -1 {
			value = value[:i]
		}
	}
	if parts := strings.Split(value, "@"); len(parts) > 1 {
		value = parts[len(parts)-1]
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end != -1 {
			value = value[1:end]
		} else {
			value = value[1:]
		}
	} else if ok, _ := regexp.MatchString(`^[^:]+:\d+$`, value); ok {
		value = value[:strings.LastIndex(value, ":")]
	}
	return strings.TrimSuffix(value, ".")
}

// ValidateHostname — mirror validate.js.
func ValidateHostname(hostname string) string {
	value := NormalizeHostname(hostname)
	if value == "" {
		return "Domain wajib diisi."
	}
	if len(value) > 253 {
		return "Domain maksimal 253 karakter."
	}
	if strings.Contains(value, "_") {
		return "Domain tidak boleh mengandung garis bawah."
	}
	if strings.Contains(value, " ") || regexp.MustCompile(`\s`).MatchString(value) {
		return "Domain tidak boleh mengandung spasi."
	}
	if strings.HasPrefix(value, "-") {
		return "Domain tidak boleh diawali tanda hubung."
	}
	if ok, _ := regexp.MatchString(`^[0-9.]+$`, value); ok {
		return "Alamat IP tidak bisa dipakai sebagai domain."
	}
	if strings.Contains(value, ":") || strings.Contains(value, "[") {
		return "Alamat IP tidak bisa dipakai sebagai domain."
	}
	if value == "localhost" || strings.HasSuffix(value, ".local") || strings.HasSuffix(value, ".internal") {
		return "Domain lokal/internal tidak bisa dipakai."
	}
	if IsBlockedHostname(value) {
		return "Domain lokal/internal tidak bisa dipakai."
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "Domain harus memuat minimal satu titik, mis. go.contoh.com."
	}
	for _, l := range labels {
		if l == "" {
			return "Domain tidak boleh punya titik ganda."
		}
		if len(l) > 63 {
			return "Setiap bagian domain maksimal 63 karakter."
		}
		if ok, _ := regexp.MatchString(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, l); !ok {
			return "Gunakan huruf, angka, dan tanda hubung (tidak di awal/akhir bagian)."
		}
	}
	tld := labels[len(labels)-1]
	if ok, _ := regexp.MatchString(`^[a-z]{2,}$`, tld); !ok {
		if ok2, _ := regexp.MatchString(`^xn--[a-z0-9-]{2,}$`, tld); !ok2 {
			return "Akhiran domain (TLD) minimal 2 huruf."
		}
	}
	return ""
}
