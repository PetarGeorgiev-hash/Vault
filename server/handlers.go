package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgconn"
)

// ---- helpers ----

func isOrgAdmin(db *sql.DB, userID, orgID string) bool {
	var role string
	err := db.QueryRow(`SELECT role FROM org_memberships WHERE org_id=$1 AND user_id=$2`, orgID, userID).Scan(&role)
	if err != nil {
		return false
	}
	return role == "owner" || role == "admin"
}

// auth: extract user id from Authorization header using JWT
func requireUser(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("missing bearer token")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid auth header")
	}
	userID, err := parseJWT(parts[1])
	if err != nil {
		return "", errors.New("invalid token")
	}
	return userID, nil
}

func hashInviteToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// ---- request/response DTOs ----

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"device_id,omitempty"` // "web" (default) or "desktop"
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"device_id,omitempty"` // "web" (default) or "desktop"
}

// ---- routes ----

func registerRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// --- register ---
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req registerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		if len(req.Password) < 8 {
			http.Error(w, "password too short", http.StatusBadRequest)
			return
		}
		deviceID := strings.TrimSpace(req.DeviceID)
		if deviceID == "" {
			deviceID = "web"
		}

		// 1) password hash
		pwSalt := newSalt()
		pwHash := hashPassword(req.Password, pwSalt)

		// 2) master key
		mkSalt := newSalt()
		mk := deriveMasterKey(req.Password, mkSalt)

		// 3) root key + encryption
		rk := generateRootKey()
		encRK, err := encryptRootKey(rk, mk)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// 4) secret key
		secretKey := generateSecretKey()

		tx, err := store.DB.Begin()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var userID string
		err = tx.QueryRow(`
			INSERT INTO users (email, pw_salt, pw_params, pw_hash, mk_salt, mk_params, enc_root_key, secret_key)
			VALUES ($1,$2,'{"algo":"argon2id"}',$3,$4,'{"algo":"argon2id"}',$5,$6)
			RETURNING id
		`, req.Email, pwSalt, pwHash, mkSalt, encRK, secretKey).Scan(&userID)
		if err != nil {
			// surface duplicate email as 409
			if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
				http.Error(w, "email already registered", http.StatusConflict)
				return
			}
			log.Println("register insert error:", err)
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}

		// personal org
		orgName := req.Email + "'s personal org"
		var orgID string
		err = tx.QueryRow(`
			INSERT INTO organizations (name, kind)
			VALUES ($1,'personal')
			RETURNING id
		`, orgName).Scan(&orgID)
		if err != nil {
			log.Println("register org insert error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// org membership (owner)
		if _, err := tx.Exec(`
			INSERT INTO org_memberships (org_id, user_id, role)
			VALUES ($1,$2,'owner')
		`, orgID, userID); err != nil {
			log.Println("register membership insert error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// personal vault
		var vaultID string
		const vaultName = "Personal Vault"
		err = tx.QueryRow(`
			INSERT INTO vaults (org_id, name)
			VALUES ($1,$2)
			RETURNING id
		`, orgID, vaultName).Scan(&vaultID)
		if err != nil {
			log.Println("register vault insert error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// vault access (binary ACL)
		if _, err := tx.Exec(`
			INSERT INTO vault_access (vault_id, user_id)
			VALUES ($1,$2)
		`, vaultID, userID); err != nil {
			log.Println("register vault access insert error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// single active refresh per device
		_, _ = store.DB.Exec(`
		  UPDATE refresh_tokens
		  SET revoked_at = now()
		  WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL
		`, userID, deviceID)

		// tokens
		access, _ := issueJWT(userID)
		refresh, _ := issueRefreshToken(store.DB, userID, deviceID)

		type vaultOut struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			OrgID   string `json:"org_id"`
			OrgName string `json:"org_name"`
			OrgKind string `json:"org_kind"`
		}
		vaults := []vaultOut{{
			ID: vaultID, Name: vaultName,
			OrgID: orgID, OrgName: orgName, OrgKind: "personal",
		}}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  access,
			"refresh_token": refresh,
			"secret_key":    secretKey,
			"vaults":        vaults,
		})
	})

	// --- login ---
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req loginReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		deviceID := strings.TrimSpace(req.DeviceID)
		if deviceID == "" {
			deviceID = "web"
		}

		var userID string
		var salt, pwHash []byte
		err := store.DB.QueryRow(`SELECT id, pw_salt, pw_hash FROM users WHERE email=$1`, strings.ToLower(req.Email)).
			Scan(&userID, &salt, &pwHash)
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		pwTry := hashPassword(req.Password, salt)
		if subtle.ConstantTimeCompare(pwTry, pwHash) != 1 {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		// single active refresh per device
		_, _ = store.DB.Exec(`
		  UPDATE refresh_tokens
		  SET revoked_at = now()
		  WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL
		`, userID, deviceID)

		// issue new tokens
		access, _ := issueJWT(userID)
		refresh, _ := issueRefreshToken(store.DB, userID, deviceID)

		// fetch vaults the user can access
		type vaultOut struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			OrgID   string `json:"org_id"`
			OrgName string `json:"org_name"`
			OrgKind string `json:"org_kind"`
		}

		rows, err := store.DB.Query(`
		  SELECT v.id, v.name, v.org_id, o.name, o.kind
		  FROM vaults v
		  JOIN vault_access a ON a.vault_id = v.id
		  JOIN organizations o ON o.id = v.org_id
		  WHERE a.user_id = $1
		  ORDER BY v.created_at DESC
		`, userID)
		if err != nil {
			log.Println("login list vaults:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var vaults []vaultOut
		for rows.Next() {
			var vo vaultOut
			if err := rows.Scan(&vo.ID, &vo.Name, &vo.OrgID, &vo.OrgName, &vo.OrgKind); err != nil {
				log.Println("scan vault:", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			vaults = append(vaults, vo)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  access,
			"refresh_token": refresh,
			"vaults":        vaults,
			"device_id":     deviceID,
		})
	})

	// --- refresh ---
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		auth := r.Header.Get("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid auth header", http.StatusUnauthorized)
			return
		}
		userID, err := parseJWT(parts[1])
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		newRefresh, err := verifyAndRotateRefreshToken(store.DB, userID, body.RefreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}

		newAccess, _ := issueJWT(userID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
		})
	})

	// --- me ---
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid auth header", http.StatusUnauthorized)
			return
		}
		userID, err := parseJWT(parts[1])
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": userID})
	})

	// --- create business org ---
	// POST /orgs  { "name": "Acme Inc" }
	mux.HandleFunc("/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		uid, err := requireUser(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		tx, err := store.DB.Begin()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var orgID string
		if err := tx.QueryRow(`INSERT INTO organizations (name, kind) VALUES ($1,'business') RETURNING id`, body.Name).Scan(&orgID); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1,$2,'owner')`, orgID, uid); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"org_id": orgID})
	})

	// --- accept invite ---
	// POST /orgs/accept-invite  { "token": "..." }
	mux.HandleFunc("/orgs/accept-invite", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		uid, err := requireUser(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		hash := hashInviteToken(body.Token)

		var orgID, inviteEmail, role string
		var expires time.Time
		var accepted bool
		err = store.DB.QueryRow(`
		  SELECT org_id, email, role, expires_at, (accepted_at IS NOT NULL) AS accepted
		  FROM org_invites
		  WHERE token_hash=$1
		`, hash).Scan(&orgID, &inviteEmail, &role, &expires, &accepted)
		if err != nil || accepted || time.Now().After(expires) {
			http.Error(w, "invalid or expired invite", http.StatusUnauthorized)
			return
		}

		// email must match logged-in user
		var userEmail string
		if err := store.DB.QueryRow(`SELECT email FROM users WHERE id=$1`, uid).Scan(&userEmail); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.EqualFold(userEmail, inviteEmail) {
			http.Error(w, "invite email mismatch", http.StatusForbidden)
			return
		}

		tx, err := store.DB.Begin()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// add/upgrade membership
		if _, err := tx.Exec(`
		  INSERT INTO org_memberships (org_id, user_id, role)
		  VALUES ($1,$2,$3)
		  ON CONFLICT (org_id, user_id) DO UPDATE SET role=EXCLUDED.role
		`, orgID, uid, role); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// mark invite accepted
		if _, err := tx.Exec(`UPDATE org_invites SET accepted_at=now() WHERE token_hash=$1`, hash); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"org_id": orgID, "role": role})
	})

	// --- org subroutes: invite + create vault ---
	// POST /orgs/{orgID}/invite
	// POST /orgs/{orgID}/vaults
	mux.HandleFunc("/orgs/", func(w http.ResponseWriter, r *http.Request) {
		// Accept only POST for the supported subpaths
		if r.Method != http.MethodPost {
			return
		}

		uid, err := requireUser(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(r.URL.Path, "/")
		// Expect at least: "", "orgs", "{orgID}", "subpath"
		if len(parts) < 4 {
			return
		}
		orgID := parts[2]

		switch {
		case strings.HasSuffix(r.URL.Path, "/invite"):
			// Only org owner/admin can invite
			if !isOrgAdmin(store.DB, uid, orgID) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			var body struct {
				Email string `json:"email"`
				Role  string `json:"role"` // "member" | "admin"
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			body.Email = strings.ToLower(strings.TrimSpace(body.Email))
			if body.Email == "" || (body.Role != "member" && body.Role != "admin") {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			// create/replace pending invite
			raw, hash, err := generateInviteToken()
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			_, err = store.DB.Exec(`
			  INSERT INTO org_invites (org_id, email, role, token_hash, invited_by, expires_at)
			  VALUES ($1,$2,$3,$4,$5,$6)
			  ON CONFLICT (org_id, email) WHERE accepted_at IS NULL DO UPDATE
			  SET role=EXCLUDED.role, token_hash=EXCLUDED.token_hash, invited_by=EXCLUDED.invited_by,
			      expires_at=EXCLUDED.expires_at, created_at=now()
			`, orgID, body.Email, body.Role, hash, uid, time.Now().Add((14 * 24 * time.Hour)))
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			// For dev: return token (in prod, email it)
			_ = json.NewEncoder(w).Encode(map[string]string{"invite_token": raw})

		case strings.HasSuffix(r.URL.Path, "/vaults"):
			// Only org owner/admin can create vaults
			if !isOrgAdmin(store.DB, uid, orgID) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			tx, err := store.DB.Begin()
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			defer tx.Rollback()

			var vaultID string
			if err := tx.QueryRow(`
				INSERT INTO vaults (org_id, name)
				VALUES ($1,$2)
				RETURNING id
			`, orgID, body.Name).Scan(&vaultID); err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			// Grant creator access (idempotent)
			if _, err := tx.Exec(`
					INSERT INTO vault_access (vault_id, user_id)
					VALUES ($1,$2)
					ON CONFLICT (vault_id, user_id) DO NOTHING
				`, vaultID, uid); err != nil {
				log.Println("create vault_access error:", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			if err := tx.Commit(); err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]string{"vault_id": vaultID})
		}
	})

	// --- vault subroutes: share + items (collection & single) ---
	// POST /vaults/{vaultID}/share
	// POST /vaults/{vaultID}/items
	// GET  /vaults/{vaultID}/items
	// GET  /vaults/{vaultID}/items/{itemID}
	// PUT  /vaults/{vaultID}/items/{itemID}
	// DELETE /vaults/{vaultID}/items/{itemID}
	mux.HandleFunc("/vaults/", func(w http.ResponseWriter, r *http.Request) {
		uid, err := requireUser(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(r.URL.Path, "/")
		// Expect at least: "", "vaults", "{vaultID}", ...
		if len(parts) < 3 {
			http.Error(w, "bad vault id", http.StatusBadRequest)
			return
		}
		vaultID := parts[2]

		// SHARE: /vaults/{vaultID}/share
		if len(parts) == 4 && parts[3] == "share" {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Find org for this vault
			var orgID string
			if err := store.DB.QueryRow(`SELECT org_id FROM vaults WHERE id=$1`, vaultID).Scan(&orgID); err != nil {
				http.Error(w, "vault not found", http.StatusNotFound)
				return
			}

			// Only org admin/owner can manage sharing
			if !isOrgAdmin(store.DB, uid, orgID) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			var body struct {
				UserID string `json:"user_id"`
				Action string `json:"action"` // "grant" or "revoke"
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if body.UserID == "" || (body.Action != "grant" && body.Action != "revoke") {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			if body.Action == "grant" {
				_, err = store.DB.Exec(`INSERT INTO vault_access (vault_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, vaultID, body.UserID)
			} else {
				_, err = store.DB.Exec(`DELETE FROM vault_access WHERE vault_id=$1 AND user_id=$2`, vaultID, body.UserID)
			}
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		// ITEMS: must have access
		// Check access for any /items path
		if len(parts) >= 4 && parts[3] == "items" {
			var exists bool
			err = store.DB.QueryRow(`SELECT true FROM vault_access WHERE vault_id=$1 AND user_id=$2`, vaultID, uid).Scan(&exists)
			if err != nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			// Single item: /vaults/{vaultID}/items/{itemID}
			if len(parts) == 5 {
				itemID := parts[4]
				switch r.Method {
				case http.MethodGet:
					var id string
					var version int
					var nonce, aad, ciphertext []byte
					var created, updated time.Time

					err := store.DB.QueryRow(`
						SELECT id, version, nonce, aad, ciphertext, created_at, updated_at
						FROM items WHERE vault_id=$1 AND id=$2
					`, vaultID, itemID).Scan(&id, &version, &nonce, &aad, &ciphertext, &created, &updated)
					if err != nil {
						http.Error(w, "not found", http.StatusNotFound)
						return
					}

					out := map[string]any{
						"id":         id,
						"version":    version,
						"nonce":      base64.StdEncoding.EncodeToString(nonce),
						"aad":        base64.StdEncoding.EncodeToString(aad),
						"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
						"created_at": created,
						"updated_at": updated,
					}
					_ = json.NewEncoder(w).Encode(out)

				case http.MethodPut:
					var body struct {
						Nonce      string `json:"nonce"`
						AAD        string `json:"aad"`
						Ciphertext string `json:"ciphertext"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						http.Error(w, "bad json", http.StatusBadRequest)
						return
					}
					nonce, _ := base64.StdEncoding.DecodeString(body.Nonce)
					var aad []byte
					if body.AAD != "" {
						aad, _ = base64.StdEncoding.DecodeString(body.AAD)
					}
					ciphertext, _ := base64.StdEncoding.DecodeString(body.Ciphertext)

					var newVersion int
					err = store.DB.QueryRow(`
						UPDATE items
						SET version = version+1, nonce=$1, aad=$2, ciphertext=$3, updated_at=now()
						WHERE id=$4 AND vault_id=$5
						RETURNING version
					`, nonce, aad, ciphertext, itemID, vaultID).Scan(&newVersion)
					if err != nil {
						http.Error(w, "not found", http.StatusNotFound)
						return
					}

					_ = json.NewEncoder(w).Encode(map[string]any{
						"item_id": itemID,
						"version": newVersion,
					})

				case http.MethodDelete:
					res, err := store.DB.Exec(`DELETE FROM items WHERE id=$1 AND vault_id=$2`, itemID, vaultID)
					if err != nil {
						http.Error(w, "server error", http.StatusInternalServerError)
						return
					}
					n, _ := res.RowsAffected()
					if n == 0 {
						http.Error(w, "not found", http.StatusNotFound)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
				return
			}

			// Collection: /vaults/{vaultID}/items
			if len(parts) == 4 {
				switch r.Method {
				case http.MethodPost: // create
					var body struct {
						Nonce      string `json:"nonce"`
						AAD        string `json:"aad"`
						Ciphertext string `json:"ciphertext"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						http.Error(w, "bad json", http.StatusBadRequest)
						return
					}
					nonce, _ := base64.StdEncoding.DecodeString(body.Nonce)
					var aad []byte
					if body.AAD != "" {
						aad, _ = base64.StdEncoding.DecodeString(body.AAD)
					}
					ciphertext, _ := base64.StdEncoding.DecodeString(body.Ciphertext)

					var itemID string
					err = store.DB.QueryRow(`
						INSERT INTO items (vault_id, version, nonce, aad, ciphertext)
						VALUES ($1, 1, $2, $3, $4)
						RETURNING id
					`, vaultID, nonce, aad, ciphertext).Scan(&itemID)
					if err != nil {
						http.Error(w, "server error", http.StatusInternalServerError)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"item_id": itemID})

				case http.MethodGet: // list + optional search
					query := r.URL.Query().Get("query")
					var rows *sql.Rows
					if query != "" {
						rows, err = store.DB.Query(`
							SELECT id, version, nonce, aad, ciphertext, created_at
							FROM items
							WHERE vault_id=$1 AND encode(aad,'escape') ILIKE '%' || $2 || '%'
							ORDER BY created_at DESC
						`, vaultID, query)
					} else {
						rows, err = store.DB.Query(`
							SELECT id, version, nonce, aad, ciphertext, created_at
							FROM items
							WHERE vault_id=$1
							ORDER BY created_at DESC
						`, vaultID)
					}
					if err != nil {
						http.Error(w, "server error", http.StatusInternalServerError)
						return
					}
					defer rows.Close()

					var items []map[string]any
					for rows.Next() {
						var id string
						var version int
						var nonce, aad, ciphertext []byte
						var created time.Time
						if err := rows.Scan(&id, &version, &nonce, &aad, &ciphertext, &created); err != nil {
							http.Error(w, "server error", http.StatusInternalServerError)
							return
						}
						items = append(items, map[string]any{
							"id":         id,
							"version":    version,
							"nonce":      base64.StdEncoding.EncodeToString(nonce),
							"aad":        base64.StdEncoding.EncodeToString(aad),
							"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
							"created_at": created,
						})
					}
					_ = json.NewEncoder(w).Encode(items)

				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
				return
			}
		}

		// If not share/items, ignore for this handler
	})
}
