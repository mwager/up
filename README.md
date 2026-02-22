# up.php – Secure Transfer

`up.php` is a minimal, single-file, zero-knowledge secure transfer tool written in PHP and JavaScript.

It allows two parties to securely transfer text or files using client-side encryption, without the server ever seeing plaintext.

---

## How It Works

### Alice
Alice opens:

```
https://example.com/up.php?p=Your32CharacterTokenHere
```

She pastes text or uploads a file.  
The browser:

1. Derives an AES‑256 key from the `p` token using PBKDF2  
2. Encrypts the data locally (AES‑GCM)  
3. Sends only ciphertext to the server  

The server stores encrypted data for **60 seconds only**.

---

### Bob

Bob opens the same URL with the same token.

The browser:

1. Downloads the ciphertext  
2. Derives the same key from the token  
3. Decrypts locally  
4. Automatically deletes the data from the server (single-use)

---

### Eve (Attacker)

Eve may:

- Read server storage  
- Access backups  
- Inspect traffic  

But Eve only sees ciphertext.

Without the token, decryption is computationally infeasible.

---

## Security Properties

- Client-side AES‑256‑GCM encryption
- Key derived from 32-character token
- No plaintext stored on server
- 60-second TTL
- Single-use retrieval
- No database required
- Single-file deployment

---

## Important Notes

- Token entropy is critical. Use random 32-character tokens.
- Anyone with the URL can decrypt the data.
- Designed for short-lived secure transfers, not long-term storage.
- Not audited. Use at your own risk.

---

## Deployment

Place `up.php` on a PHP-enabled HTTPS server.

Ensure:

- HTTPS is enforced
- Storage directory permissions are restricted
- Error display is disabled

---

Minimal. Auditable. Zero-knowledge.