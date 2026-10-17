// Package dnsutil — port dari NEXTJS-SHORTURL/src/lib/dns.js.
// Verifikasi TXT _yue-verify.<host> ATAU CNAME → host aplikasi.
package dnsutil

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"shorturl/internal/hosts"
)

const DNSTimeout = 5 * time.Second

// DNSTargets — target yang harus dipasang pengguna.
func DNSTargets(hostname, verifyToken string) map[string]any {
	var cname any
	var cnameRecord any
	first := ""
	for h := range hosts.ConfiguredAppHosts() {
		first = h
		break
	}
	if first != "" {
		cname = first
		cnameRecord = map[string]string{"type": "CNAME", "name": hostname, "value": first}
	}
	return map[string]any{
		"cname":       cname,
		"txt":         map[string]string{"type": "TXT", "name": "_yue-verify." + hostname, "value": verifyToken},
		"cnameRecord": cnameRecord,
	}
}

// EvaluateTxt — murni, tanpa jaringan.
func EvaluateTxt(values []string, verifyToken string) (bool, string) {
	cleaned := []string{}
	for _, v := range values {
		cleaned = append(cleaned, strings.TrimSpace(v))
	}
	for _, v := range cleaned {
		if v == verifyToken {
			return true, "Record TXT cocok."
		}
	}
	nonEmpty := []string{}
	for _, v := range cleaned {
		if v != "" {
			nonEmpty = append(nonEmpty, v)
		}
	}
	if len(nonEmpty) == 0 {
		return false, fmt.Sprintf(`Record TXT ditemukan tetapi kosong. Nilai yang diharapkan: "%s".`, verifyToken)
	}
	return false, fmt.Sprintf(`TXT ditemukan, tetapi nilainya belum cocok (ditemukan: %s). Nilai yang diharapkan: "%s".`,
		strings.Join(nonEmpty, ", "), verifyToken)
}

// EvaluateCname — murni, tanpa jaringan.
func EvaluateCname(records []string, expectedHosts map[string]struct{}) (bool, string) {
	normalized := []string{}
	for _, r := range records {
		normalized = append(normalized, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), ".")))
	}
	for _, r := range normalized {
		if _, ok := expectedHosts[r]; ok {
			return true, "CNAME sudah mengarah ke host aplikasi."
		}
	}
	expected := []string{}
	for h := range expectedHosts {
		expected = append(expected, h)
	}
	if len(expected) == 0 {
		return false, "CNAME belum bisa dipakai: APP_DOMAIN / NEXT_PUBLIC_APP_URL belum disetel di server, jadi targetnya tidak diketahui."
	}
	joined := strings.Join(normalized, ", ")
	if joined == "" {
		joined = "(kosong)"
	}
	return false, fmt.Sprintf(`CNAME mengarah ke %s, bukan ke %s.`, joined, strings.Join(expected, " atau "))
}

func customResolver() *net.Resolver {
	configured := []string{}
	for _, s := range strings.Split(os.Getenv("DNS_RESOLVER"), ",") {
		if t := strings.TrimSpace(s); t != "" {
			configured = append(configured, t)
		}
	}
	if len(configured) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: DNSTimeout}
			// Pakai server pertama yang dikonfigurasi.
			return d.DialContext(ctx, "udp", net.JoinHostPort(configured[0], "53"))
		},
	}
}

func describeDNSError(err error, kind, name string) string {
	code := "kesalahan DNS"
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.Err != "" {
		code = dnsErr.Err
	} else if err != nil {
		code = err.Error()
	}
	upper := strings.ToUpper(code)
	notFound := []string{"NOT FOUND", "NO SUCH", "NODATA", "SERVFAIL", "REFUSED", "TIMEOUT", "DEADLINE", "NO ANSWERS"}
	for _, n := range notFound {
		if strings.Contains(upper, n) {
			return fmt.Sprintf("%s %s belum ada di DNS.", kind, name)
		}
	}
	for _, n := range []string{"REFUSED", "RESET", "UNREACHABLE"} {
		if strings.Contains(upper, n) {
			return fmt.Sprintf("Server tidak bisa menghubungi resolver DNS (%s) — periksa konfigurasi DNS server.", code)
		}
	}
	return fmt.Sprintf("Gagal membaca %s %s (%s).", kind, name, code)
}

// CheckTxtRecord — cek TXT _yue-verify.<host>.
func CheckTxtRecord(hostname, verifyToken string) (bool, string, []string) {
	name := "_yue-verify." + hostname
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()
	records, err := customResolver().LookupTXT(ctx, name)
	if err != nil {
		return false, fmt.Sprintf(`%s Nilai yang diharapkan: "%s".`, describeDNSError(err, "TXT", name), verifyToken), nil
	}
	ok, msg := EvaluateTxt(records, verifyToken)
	if !ok {
		return false, fmt.Sprintf("TXT %s: %s", name, msg), records
	}
	return true, msg, records
}

// CheckCnameRecord — cek CNAME <host>.
func CheckCnameRecord(hostname string, expectedHosts map[string]struct{}) (bool, string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()
	target, err := customResolver().LookupCNAME(ctx, hostname)
	if err != nil {
		first := ""
		for h := range expectedHosts {
			first = h
			break
		}
		hint := " Setel APP_DOMAIN di server agar target CNAME diketahui."
		if first != "" {
			hint = fmt.Sprintf(` Arahkan CNAME "%s" ke "%s".`, hostname, first)
		}
		return false, describeDNSError(err, "CNAME", hostname) + hint, nil
	}
	// LookupCNAME mengembalikan satu target; perlakukan sebagai satu record.
	records := []string{target}
	ok, msg := EvaluateCname(records, expectedHosts)
	if !ok {
		return false, fmt.Sprintf("CNAME %s: %s", hostname, msg), records
	}
	return true, msg, records
}

type VerifyResult struct {
	Status string
	Error  *string
	Method *string
}

// VerifyDomainDNS — TXT ATAU CNAME. Tidak pernah melempar error jaringan.
func VerifyDomainDNS(hostname, verifyToken string, expectedHosts map[string]struct{}) VerifyResult {
	if expectedHosts == nil {
		expectedHosts = hosts.ConfiguredAppHosts()
	}
	type r struct {
		ok      bool
		message string
	}
	txtCh := make(chan r, 1)
	cnameCh := make(chan r, 1)
	go func() {
		ok, msg, _ := CheckTxtRecord(hostname, verifyToken)
		txtCh <- r{ok, msg}
	}()
	go func() {
		ok, msg, _ := CheckCnameRecord(hostname, expectedHosts)
		cnameCh <- r{ok, msg}
	}()
	txt := <-txtCh
	cname := <-cnameCh
	if txt.ok {
		m := "TXT"
		return VerifyResult{Status: "verified", Method: &m}
	}
	if cname.ok {
		m := "CNAME"
		return VerifyResult{Status: "verified", Method: &m}
	}
	joined := strings.TrimSpace(txt.message + " " + cname.message)
	return VerifyResult{Status: "failed", Error: &joined}
}
