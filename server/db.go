package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// connectDB opens a Postgres connection (Render or local) and runs migrations.
func connectDB() *sql.DB {
	// Prefer DATABASE_URL (Render)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// fallback for local dev / docker-compose
		dsn = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=disable",
			env("DB_USER", "vault"),
			env("DB_PASSWORD", "vaultpass"),
			env("DB_HOST", "db"),
			env("DB_PORT", "5432"),
			env("DB_NAME", "vaultdb"),
		)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("cannot open db: %v", err)
	}

	// tune pool settings (adjust for your Render plan)
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("cannot connect db: %v", err)
	}
	log.Println("✅ connected to Postgres")

	// Run migrations on startup
	if err := runMigrations(db, "migrations"); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	return db
}

// runMigrations applies SQL files in order and tracks them in schema_migrations.
func runMigrations(db *sql.DB, dir string) error {
	// ensure tracking table exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id SERIAL PRIMARY KEY,
			filename TEXT UNIQUE NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// read migrations dir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	// collect .sql files and sort
	files := []string{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// apply each migration if not yet applied
	for _, fname := range files {
		var exists bool
		err := db.QueryRow(
			`SELECT true FROM schema_migrations WHERE filename=$1`,
			fname,
		).Scan(&exists)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("check migration %s: %w", fname, err)
		}
		if exists {
			continue // already applied
		}

		b, err := ioutil.ReadFile(filepath.Join(dir, fname))
		if err != nil {
			return fmt.Errorf("read %s: %w", fname, err)
		}

		if _, err := db.Exec(string(b)); err != nil {
			return fmt.Errorf("exec %s: %w", fname, err)
		}

		if _, err := db.Exec(
			`INSERT INTO schema_migrations (filename) VALUES ($1)`,
			fname,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", fname, err)
		}

		fmt.Printf("✅ Applied migration: %s\n", fname)
	}

	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
