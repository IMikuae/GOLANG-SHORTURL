// Package logger — port dari NEXTJS-SHORTURL/src/lib/logger.js.
package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var sensitive = []string{
	"password", "passwordhash", "password_hash", "token", "secret",
	"apikey", "api_key", "authorization", "cookie", "x-api-key", "email",
}

var levelNum = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

func configLevel() int {
	env := os.Getenv("LOG_LEVEL")
	if env == "" {
		if os.Getenv("APP_ENV") == "production" {
			env = "info"
		} else {
			env = "debug"
		}
	}
	if n, ok := levelNum[strings.ToLower(env)]; ok {
		return n
	}
	return 1
}

func redact(obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		lk := strings.ToLower(k)
		hit := false
		for _, sk := range sensitive {
			if strings.Contains(lk, sk) {
				hit = true
				break
			}
		}
		if hit {
			out[k] = "[REDACTED]"
			continue
		}
		if m, ok := v.(map[string]any); ok {
			out[k] = redact(m)
			continue
		}
		out[k] = v
	}
	return out
}

func log(level, context, message string, detail map[string]any) {
	if levelNum[level] < configLevel() {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	prefix := fmt.Sprintf("[%s] [%s] [%s]", ts, strings.ToUpper(level), context)
	if detail != nil {
		fmt.Printf("%s %s %+v\n", prefix, message, redact(detail))
		return
	}
	fmt.Printf("%s %s\n", prefix, message)
}

func Debug(c, m string, d ...map[string]any) { log("debug", c, m, first(d)) }
func Info(c, m string, d ...map[string]any)  { log("info", c, m, first(d)) }
func Warn(c, m string, d ...map[string]any)  { log("warn", c, m, first(d)) }
func Error(c, m string, d ...map[string]any) { log("error", c, m, first(d)) }

func first(d []map[string]any) map[string]any {
	if len(d) == 0 {
		return nil
	}
	return d[0]
}
