// Package ratelimit — port dari NEXTJS-SHORTURL/src/lib/rate-limit.js.
// Fixed-window in-memory.
package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"shorturl/internal/geo"
)

type bucket struct {
	count   int
	resetAt time.Time
}

var (
	mu        sync.Mutex
	buckets   = map[string]*bucket{}
	lastSweep time.Time
)

const sweepInterval = time.Minute

func sweep(now time.Time) {
	if now.Sub(lastSweep) < sweepInterval {
		return
	}
	lastSweep = now
	for k, e := range buckets {
		if !now.Before(e.resetAt) {
			delete(buckets, k)
		}
	}
}

type Result struct {
	Allowed    bool
	RetryAfter int
	Remaining  int
}

// Consume — konsumsi satu jatah untuk key.
func Consume(key string, max int, window time.Duration) Result {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	sweep(now)
	e, ok := buckets[key]
	if !ok || !now.Before(e.resetAt) {
		buckets[key] = &bucket{count: 1, resetAt: now.Add(window)}
		return Result{Allowed: true, RetryAfter: 0, Remaining: max - 1}
	}
	if e.count >= max {
		ra := int((e.resetAt.Sub(now) + time.Second - 1) / time.Second)
		if ra < 1 {
			ra = 1
		}
		return Result{Allowed: false, RetryAfter: ra, Remaining: 0}
	}
	e.count++
	return Result{Allowed: true, RetryAfter: 0, Remaining: max - e.count}
}

// Reset — hapus jatah sebuah key (dipakai setelah aksi berhasil).
func Reset(key string) {
	mu.Lock()
	defer mu.Unlock()
	delete(buckets, key)
}

// PerIPKey — "scope:ip" atau "" bila IP tak diketahui (pemanggil wajib skip limit).
func PerIPKey(scope string, r *http.Request) string {
	ip := geo.ClientIP(r)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", scope, ip)
}

// FormatRetryAfter — kalimat Indonesia.
func FormatRetryAfter(seconds int) string {
	if seconds >= 3600 {
		h := (seconds + 3599) / 3600
		return fmt.Sprintf("%d jam", h)
	}
	if seconds >= 60 {
		m := (seconds + 59) / 60
		return fmt.Sprintf("%d menit", m)
	}
	return fmt.Sprintf("%d detik", seconds)
}

const (
	Minute = time.Minute
	Hour   = time.Hour
)

// LIMITS — sama seperti JS.
var (
	AuthIPEmail = struct {
		Max    int
		Window time.Duration
	}{5, 15 * Minute}
	AuthIP = struct {
		Max    int
		Window time.Duration
	}{50, 15 * Minute}
	ChangePassword = struct {
		Max    int
		Window time.Duration
	}{5, 15 * Minute}
	AddDomain = struct {
		Max    int
		Window time.Duration
	}{10, Hour}
	VerifyDomain = struct {
		Max    int
		Window time.Duration
	}{1, 5 * time.Second}
	UnlockFlood = struct {
		Max    int
		Window time.Duration
	}{100, 15 * Minute}
	UnlockIPLink = struct {
		Max    int
		Window time.Duration
	}{10, 15 * Minute}
	UnlockLink = struct {
		Max    int
		Window time.Duration
	}{40, 15 * Minute}
)
