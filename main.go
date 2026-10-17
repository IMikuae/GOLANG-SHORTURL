// Yue Short — port Go dari NEXTJS-SHORTURL (Next.js 16 + SQLite).
// Perilaku API + halaman + DB sama 1:1 dengan versi Next.js.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shorturl/internal/db"
	"shorturl/internal/server"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	port := env("PORT", "3000")
	dataDir := env("DATA_DIR", "./data")

	database, err := db.Open(dataDir)
	if err != nil {
		log.Fatalf("gagal membuka DB: %v", err)
	}
	defer database.SQL.Close()

	srv, err := server.New(database.Q())
	if err != nil {
		log.Fatalf("gagal memuat template: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		fmt.Printf("Yue Short (Go) jalan di http://localhost:%s (data: %s)\n", port, dataDir)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
