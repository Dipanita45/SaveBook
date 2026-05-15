"use client";
// Runs only in the browser (Web Crypto API)

if (typeof window === 'undefined') {
  throw new Error('clientCrypto must only be used in the browser');
}

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 256;

// Derive an AES-GCM key from a password + salt using PBKDF2
export async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

// Generate a random master key (AES-GCM 256-bit), returned as CryptoKey
export async function generateMasterKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: KEY_LENGTH }, true, ["encrypt", "decrypt"]);
}

// Export a CryptoKey to raw hex string
export async function exportKey(cryptoKey) {
  const raw = await crypto.subtle.exportKey("raw", cryptoKey);
  return Array.from(new Uint8Array(raw)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Import a raw hex string back to CryptoKey
export async function importKey(hex) {
  const raw = new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: KEY_LENGTH }, true, ["encrypt", "decrypt"]);
}

// Encrypt a plaintext string with a CryptoKey, returns hex string "{iv}:{ciphertext}"
export async function encryptWithKey(plaintext, cryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, enc.encode(plaintext));
  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join("");
  const ctHex = Array.from(new Uint8Array(ciphertext)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${ivHex}:${ctHex}`;
}

// Decrypt a "{iv}:{ciphertext}" hex string with a CryptoKey
export async function decryptWithKey(payload, cryptoKey) {
  const [ivHex, ctHex] = payload.split(":");
  const iv = new Uint8Array(ivHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  const ct = new Uint8Array(ctHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
  return new TextDecoder().decode(plainBuffer);
}

// Encrypt the master key (raw hex) with a password-derived key, returns "{iv}:{ciphertext}"
export async function encryptMasterKey(masterKey, password, userId) {
  const rawHex = await exportKey(masterKey);
  const wrapKey = await deriveKeyFromPassword(password, userId);
  return encryptWithKey(rawHex, wrapKey);
}

// Decrypt the encrypted master key blob, returns a CryptoKey ready for use
export async function decryptMasterKey(encryptedBlob, password, userId) {
  const wrapKey = await deriveKeyFromPassword(password, userId);
  const rawHex = await decryptWithKey(encryptedBlob, wrapKey);
  return importKey(rawHex);
}

// Re-wrap the master key with a new password (used during password reset with recovery code)
// encryptedBlob: current encrypted master key, oldSecret: recovery code, newPassword + userId for new wrap
export async function rewrapMasterKey(encryptedBlob, oldSecret, userId, newPassword) {
  const wrapKey = await deriveKeyFromPassword(oldSecret, userId);
  const rawHex = await decryptWithKey(encryptedBlob, wrapKey);
  const masterKey = await importKey(rawHex);
  return encryptMasterKey(masterKey, newPassword, userId);
}

// Generate a random share key as hex string (not a CryptoKey, so it can live in a URL fragment)
export function generateShareKeyHex() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Import a share key hex string to a CryptoKey
export async function importShareKey(hex) {
  return importKey(hex);
}
