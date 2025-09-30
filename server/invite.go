package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// generateInviteToken creates a random token and its SHA256 hash.
func generateInviteToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	return token, hash[:], nil
}
