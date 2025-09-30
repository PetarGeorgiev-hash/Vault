package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	// connect DB
	db := connectDB()
	defer db.Close()

	// wrap DB in a store (handy later)
	store := &Store{DB: db}

	// routes
	mux := http.NewServeMux()
	registerRoutes(mux, store)

	addr := "0.0.0.0:8787"
	log.Println("server listening on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
