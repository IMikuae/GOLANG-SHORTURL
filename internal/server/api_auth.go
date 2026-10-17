package server

import (
	"net/http"
	"strings"

	"shorturl/internal/auth"
	"shorturl/internal/geo"
	"shorturl/internal/logger"
	"shorturl/internal/ratelimit"
	"shorturl/internal/validate"
)

// POST /api/auth/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(r)
	if !ok {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	email := strings.TrimSpace(strings.ToLower(strField(body, "email")))
	password := strField(body, "password")
	name := strings.TrimSpace(strField(body, "name"))
	if msg := validate.ValidateEmail(email); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validate.ValidateRegisterPassword(password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if len(name) > 60 {
		writeErr(w, 400, "Nama maksimal 60 karakter.")
		return
	}
	ip := geo.ClientIP(r)
	accountKey := "register:" + email
	if ip != "" {
		accountKey = "register:" + ip + ":" + email
	}
	perAccount := ratelimit.Consume(accountKey, ratelimit.AuthIPEmail.Max, ratelimit.AuthIPEmail.Window)
	var blocked *ratelimit.Result
	if !perAccount.Allowed {
		blocked = &perAccount
	} else if ip != "" {
		perIP := ratelimit.Consume("register-ip:"+ip, ratelimit.AuthIP.Max, ratelimit.AuthIP.Window)
		if !perIP.Allowed {
			blocked = &perIP
		}
	}
	if blocked != nil {
		logger.Warn("api/auth/register", "Rate limit tercapai", map[string]any{"ip": ip})
		w.Header().Set("Retry-After", itoa(blocked.RetryAfter))
		writeErr(w, 429, "Terlalu banyak percobaan. Coba lagi dalam "+ratelimit.FormatRetryAfter(blocked.RetryAfter)+".")
		return
	}
	if existing, err := s.Q.FindUserByEmail(email); err != nil {
		writeErr(w, 500, "Gagal mendaftar. Coba lagi.")
		return
	} else if existing != nil {
		writeErr(w, 409, "Email sudah terdaftar. Silakan masuk.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		writeErr(w, 500, "Gagal mendaftar. Coba lagi.")
		return
	}
	var namePtr *string
	if name != "" {
		namePtr = &name
	}
	userID, err := s.Q.CreateUser(email, hash, namePtr)
	if err != nil {
		writeErr(w, 500, "Gagal mendaftar. Coba lagi.")
		return
	}
	_ = s.Q.SetUserAPIKey(userID, auth.GenerateAPIKey())
	ratelimit.Reset(accountKey)
	token, err := auth.CreateSession(s.Q, userID)
	if err != nil {
		writeErr(w, 500, "Gagal mendaftar. Coba lagi.")
		return
	}
	setSessionCookie(w, token)
	writeJSON(w, 201, map[string]any{"ok": true})
}

// POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(r)
	if !ok {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	email := strings.TrimSpace(strings.ToLower(strField(body, "email")))
	password := strField(body, "password")
	if msg := validate.ValidateEmail(email); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if password == "" {
		writeErr(w, 400, "Password wajib diisi.")
		return
	}
	ip := geo.ClientIP(r)
	accountKey := "login:" + email
	if ip != "" {
		accountKey = "login:" + ip + ":" + email
	}
	perAccount := ratelimit.Consume(accountKey, ratelimit.AuthIPEmail.Max, ratelimit.AuthIPEmail.Window)
	var blocked *ratelimit.Result
	if !perAccount.Allowed {
		blocked = &perAccount
	} else if ip != "" {
		perIP := ratelimit.Consume("login-ip:"+ip, ratelimit.AuthIP.Max, ratelimit.AuthIP.Window)
		if !perIP.Allowed {
			blocked = &perIP
		}
	}
	if blocked != nil {
		logger.Warn("api/auth/login", "Rate limit tercapai", map[string]any{"ip": ip})
		w.Header().Set("Retry-After", itoa(blocked.RetryAfter))
		writeErr(w, 429, "Terlalu banyak percobaan masuk. Coba lagi dalam "+ratelimit.FormatRetryAfter(blocked.RetryAfter)+".")
		return
	}
	user, err := s.Q.FindUserByEmail(email)
	if err != nil {
		writeErr(w, 500, "Gagal masuk. Coba lagi.")
		return
	}
	if user == nil || !auth.VerifyPassword(password, user.PasswordHash) {
		writeErr(w, 401, "Email atau password salah.")
		return
	}
	ratelimit.Reset(accountKey)
	token, err := auth.CreateSession(s.Q, user.ID)
	if err != nil {
		writeErr(w, 500, "Gagal masuk. Coba lagi.")
		return
	}
	setSessionCookie(w, token)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_ = s.Q.DestroySession(auth.AuthToken(r))
	clearSessionCookie(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/account
func (s *Server) handleAccountGet(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	full, err := s.Q.FindUserByID(user.ID)
	if err != nil || full == nil {
		writeErr(w, 404, "User tidak ditemukan.")
		return
	}
	apiKey := ""
	if full.APIKey.Valid {
		apiKey = full.APIKey.String
	}
	if apiKey == "" {
		apiKey = auth.GenerateAPIKey()
		_ = s.Q.SetUserAPIKey(full.ID, apiKey)
	}
	linkCount, _ := s.Q.CountLinksByUser(full.ID)
	var name any
	if full.Name.Valid {
		name = full.Name.String
	}
	writeJSON(w, 200, map[string]any{
		"id": full.ID, "email": full.Email, "name": name,
		"apiKey": apiKey, "createdAt": full.CreatedAt, "linkCount": linkCount,
	})
}

// PATCH /api/account
func (s *Server) handleAccountPatch(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	body, valid := readJSON(r)
	if !valid {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	raw, isStr := body["name"].(string)
	if !isStr {
		writeErr(w, 400, "Nama wajib berupa teks.")
		return
	}
	name := strings.TrimSpace(raw)
	if len([]rune(name)) < 2 {
		writeErr(w, 400, "Nama minimal 2 karakter.")
		return
	}
	if len([]rune(name)) > 60 {
		writeErr(w, 400, "Nama maksimal 60 karakter.")
		return
	}
	full, err := s.Q.FindUserByID(user.ID)
	if err != nil || full == nil {
		writeErr(w, 404, "User tidak ditemukan.")
		return
	}
	if err := s.Q.SetUserName(full.ID, name); err != nil {
		writeErr(w, 500, "Gagal menyimpan nama.")
		return
	}
	logger.Info("api/account", "Nama diperbarui", map[string]any{"userId": full.ID})
	writeJSON(w, 200, map[string]any{"ok": true, "name": name})
}

// DELETE /api/account
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	body, valid := readJSON(r)
	if !valid {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	password := strField(body, "password")
	if password == "" {
		writeErr(w, 400, "Password wajib diisi untuk menghapus akun.")
		return
	}
	full, err := s.Q.FindUserByID(user.ID)
	if err != nil || full == nil {
		writeErr(w, 404, "User tidak ditemukan.")
		return
	}
	if !auth.VerifyPassword(password, full.PasswordHash) {
		logger.Warn("api/account", "Konfirmasi hapus akun gagal", map[string]any{"userId": full.ID})
		writeErr(w, 401, "Password salah. Akun tidak dihapus.")
		return
	}
	linkCount, _ := s.Q.CountLinksByUser(full.ID)
	if err := s.Q.DeleteUserWithData(full.ID); err != nil {
		writeErr(w, 500, "Gagal menghapus akun.")
		return
	}
	logger.Info("api/account", "Akun dihapus", map[string]any{"userId": full.ID, "linkCount": linkCount})
	clearSessionCookie(w)
	writeJSON(w, 200, map[string]any{"ok": true, "linksDeleted": linkCount})
}

// POST /api/account/password
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	bucketKey := "password:" + itoa64(user.ID)
	lim := ratelimit.Consume(bucketKey, ratelimit.ChangePassword.Max, ratelimit.ChangePassword.Window)
	if !lim.Allowed {
		w.Header().Set("Retry-After", itoa(lim.RetryAfter))
		writeErr(w, 429, "Terlalu banyak percobaan ganti password. Coba lagi dalam "+ratelimit.FormatRetryAfter(lim.RetryAfter)+".")
		return
	}
	body, valid := readJSON(r)
	if !valid {
		writeErr(w, 400, "Body harus berupa JSON.")
		return
	}
	currentPassword := strField(body, "currentPassword")
	newPassword := strField(body, "newPassword")
	if currentPassword == "" {
		writeErr(w, 400, "Password lama wajib diisi.")
		return
	}
	if msg := validate.ValidateRegisterPassword(newPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	full, err := s.Q.FindUserByID(user.ID)
	if err != nil || full == nil {
		writeErr(w, 404, "User tidak ditemukan.")
		return
	}
	if !auth.VerifyPassword(currentPassword, full.PasswordHash) {
		logger.Warn("api/account/password", "Password lama salah", map[string]any{"userId": user.ID})
		writeErr(w, 401, "Password lama salah.")
		return
	}
	if auth.VerifyPassword(newPassword, full.PasswordHash) {
		writeErr(w, 400, "Password baru tidak boleh sama dengan password lama.")
		return
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		writeErr(w, 500, "Gagal mengganti password.")
		return
	}
	if err := s.Q.SetUserPassword(full.ID, hash); err != nil {
		writeErr(w, 500, "Gagal mengganti password.")
		return
	}
	_ = s.Q.DeleteOtherSessions(full.ID, auth.AuthToken(r))
	ratelimit.Reset(bucketKey)
	logger.Info("api/account/password", "Password diganti", map[string]any{"userId": full.ID})
	if token := auth.AuthToken(r); token != "" {
		setSessionCookie(w, token)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/account/api-key
func (s *Server) handleAPIKeyRegen(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	full, err := s.Q.FindUserByID(user.ID)
	if err != nil || full == nil {
		writeErr(w, 404, "User tidak ditemukan.")
		return
	}
	newKey := auth.GenerateAPIKey()
	if err := s.Q.SetUserAPIKey(full.ID, newKey); err != nil {
		writeErr(w, 500, "Gagal regenerasi API key.")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "apiKey": newKey})
}
