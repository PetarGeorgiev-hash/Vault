// crypto.js - client-side cryptography helpers (Option A: direct rootKey)

// --- utilities ---
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

async function randomBytes(len) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf.buffer;
}

// --- derive MUK (Master Unlock Key) ---
export async function deriveMUK(password, secretKeyBase64, saltBase64) {
  const secretKey = base64ToBuf(secretKeyBase64);
  const salt = base64ToBuf(saltBase64);

  // combine password + secretKey
  const pwBytes = new TextEncoder().encode(password);
  const combined = new Uint8Array(pwBytes.length + secretKey.byteLength);
  combined.set(pwBytes, 0);
  combined.set(new Uint8Array(secretKey), pwBytes.length);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    combined,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const muk = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 200_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return muk;
}

// --- item encryption/decryption (direct rootKey) ---
export async function encryptItem(rootKey, itemObj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(itemObj));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    rootKey,
    plaintext
  );
  return {
    nonce: bufToBase64(iv.buffer),
    ciphertext: bufToBase64(ciphertext),
  };
}

export async function decryptItem(enc, rootKey) {
  const iv = base64ToBuf(enc.nonce);
  const ct = base64ToBuf(enc.ciphertext);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    rootKey,
    ct
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}
