# VaultCore

A completely local-first, zero-knowledge secure password vault running entirely in your browser. It features native Web Crypto API AES-GCM encryption and HaveIBeenPwned API auditing using k-Anonymity.

## Features
- **Zero-Knowledge Architecture:** Your Master Password is never saved anywhere. The vault is encrypted client-side using native `SubtleCrypto` PBKDF2 key derivation and AES-GCM symmetric encryption.
- **k-Anonymity Auditing:** Check your passwords against known data breaches without ever transmitting your actual password. Only the first 5 characters of your password's SHA-1 hash are sent to the HaveIBeenPwned API.
- **Local Persistence:** Your encrypted vault blob is stored exclusively in your browser's `localStorage`.
- **Secure Password Generator:** Generate strong, random 16-character passwords instantly using `crypto.getRandomValues()`.
- **Beautiful UI:** A premium, fully responsive dark-themed interface built entirely with HTML, CSS, and Vanilla JS—no bloated frameworks.

## Tech Stack
- HTML5, CSS3, Vanilla JavaScript
- **Web Crypto API:** Native browser cryptography without external libraries.
- **HaveIBeenPwned API:** Security audits.

## How to Run Locally
Since the application relies on native ES Modules and modern Web APIs, you must serve it over an HTTP server (or HTTPS).

### Using Python:
```bash
# Start a local HTTP server on port 8000
python -m http.server 8000
```
Then navigate to `http://localhost:8000` in your web browser.

### Using Node.js:
```bash
npx serve .
```

## Security Warning
> **IMPORTANT:** Because this is a zero-knowledge local vault, there is absolutely no password reset feature. If you forget your Master Password, your encrypted vault data is permanently unrecoverable.

## License
MIT License
