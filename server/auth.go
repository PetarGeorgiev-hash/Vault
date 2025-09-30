package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"database/sql"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

var jwtSecret = []byte(getEnv("JWT_SECRET", "dev-secret"))

// --- JWT helpers (access tokens) ---

func issueJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func parseJWT(tokenStr string) (string, error) {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("bad signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !tok.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("missing subject")
	}

	// enforce expiration
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() >= int64(exp) {
		return "", errors.New("token expired")
	}

	return sub, nil
}

// --- Refresh tokens (DB-backed, hashed, rotating) ---

// issueRefreshToken generates a random token, stores its hash in DB, and returns the raw token to the client.
func issueRefreshToken(db *sql.DB, userID, deviceID string) (string, error) {
	// generate random 32-byte token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	// hash it with HMAC(jwtSecret) → what we store
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(token))
	tokenHash := h.Sum(nil)

	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	_, err := db.Exec(`
        INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
    `, userID, deviceID, tokenHash, expiresAt)
	if err != nil {
		return "", err
	}

	return token, nil // return raw token to client
}

// verifyAndRotateRefreshToken validates a refresh token, revokes it, and issues a new one
// preserving the original device_id.
func verifyAndRotateRefreshToken(db *sql.DB, userID, provided string) (string, error) {
	// hash the provided token
	h := hmac.New(sha256.New, jwtSecret) // or rtkSecret if you added a separate key
	h.Write([]byte(provided))
	hash := h.Sum(nil)

	var tokenID, deviceID string
	var expiresAt time.Time
	var revokedAt sql.NullTime

	err := db.QueryRow(`
        SELECT id, device_id, expires_at, revoked_at
        FROM refresh_tokens
        WHERE user_id = $1 AND token_hash = $2
    `, userID, hash).Scan(&tokenID, &deviceID, &expiresAt, &revokedAt)
	if err != nil {
		return "", errors.New("invalid refresh token")
	}

	if revokedAt.Valid || time.Now().After(expiresAt) {
		return "", errors.New("refresh token expired or revoked")
	}

	// revoke old
	_, _ = db.Exec(`UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, tokenID)

	// issue new with the SAME deviceID
	return issueRefreshToken(db, userID, deviceID)
}

// --- Password hashing ---

func newSalt() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate salt: " + err.Error())
	}
	return b
}

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
}

// --- Keys ---

// deriveMasterKey derives a key from the login password + mkSalt
func deriveMasterKey(password string, mkSalt []byte) []byte {
	return argon2.IDKey([]byte(password), mkSalt, 3, 64*1024, 2, 32)
}

func generateRootKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate root key: " + err.Error())
	}
	return b
}

func encryptRootKey(rootKey, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, rootKey, nil)
	return ciphertext, nil
}

func generateSecretKey() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate secret key: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// --- utils ---

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
