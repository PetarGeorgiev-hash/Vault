package main

import "database/sql"

// Store is a thin wrapper, so handlers can use db methods.
type Store struct {
	DB *sql.DB
}
