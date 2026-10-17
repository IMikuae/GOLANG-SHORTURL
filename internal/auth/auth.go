// Package auth — port dari NEXTJS-SHORTURL/src/lib/auth.js.
// scrypt N=16384 r=8 p=1 keyLen=64 (sama dengan default Node crypto.scryptSync).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"shorturl/internal/db"
)

const AuthCookie = "ys_session"
const SessionTTLDays = 30

// HashPassword — "saltHex:hashHex" (salt = 16 byte acak).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	dk, err := scrypt.Key([]byte(password), []byte(saltHex), 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return saltHex + ":" + hex.EncodeToString(dk), nil
}

// VerifyPassword — scrypt + perbandingan konstan-waktu.
func VerifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	dk, err := scrypt.Key([]byte(password), []byte(parts[0]), 16384, 8, 1, 64)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil || len(dk) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(dk, expected) == 1
}

// GenerateToken — 32 byte hex.
func GenerateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateAPIKey — "ys_live_" + 24 byte hex.
func GenerateAPIKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "ys_live_" + hex.EncodeToString(b)
}

// CreateSession — insert sesi +30 hari, return token.
func CreateSession(q *db.Queries, userID int64) (string, error) {
	token := GenerateToken()
	if err := q.CreateSession(token, userID, time.Now().AddDate(0, 0, SessionTTLDays)); err != nil {
		return "", err
	}
	return token, nil
}

// SessionUser — user dari token sesi (null-safe).
func SessionUser(q *db.Queries, token string) (*db.User, error) {
	if token == "" {
		return nil, nil
	}
	return q.GetSessionUser(token)
}

// AuthToken — token dari cookie request.
func AuthToken(r *http.Request) string {
	c, err := r.Cookie(AuthCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// AuthUser — user dari cookie request.
func AuthUser(q *db.Queries, r *http.Request) (*db.User, error) {
	return SessionUser(q, AuthToken(r))
}

// SessionCookie — atribut cookie sesi.
func SessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     AuthCookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 60 * 24 * SessionTTLDays,
		Secure:   sessionSecure(),
	}
}

// ExpiredCookie — cookie penghapus sesi (atribut sama, MaxAge<0).
func ExpiredCookie() *http.Cookie {
	c := SessionCookie()
	c.Value = ""
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0)
	return c
}

func sessionSecure() bool {
	switch os.Getenv("COOKIE_SECURE") {
	case "1":
		return true
	case "0":
		return false
	default:
		return os.Getenv("APP_ENV") == "production"
	}
}
