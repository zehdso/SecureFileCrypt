# SecureFileCrypt

<p align="center">
  <strong>Private file encryption — directly in your browser.</strong>
</p>

<p align="center">
  Encrypt and decrypt files locally with a password.
  Your files never need to be uploaded to a server.
</p>

## Try SecureFileCrypt

<p align="center">
  <a href="https://zehdso.github.io/SecureFileCrypt/">
    <img src="https://img.shields.io/badge/Visit%20SecureFileCrypt-18181B?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Visit SecureFileCrypt">
  </a>
</p>

<p align="center">
  https://zehdso.github.io/SecureFileCrypt/
</p>

---

## Overview

SecureFileCrypt is a browser-based file encryption tool designed to make strong file encryption simple and accessible.

It can encrypt almost any type of file — videos, photos, documents, archives, backups, and more — and produce an extensionless encrypted file that can later be restored with the correct password.

All cryptographic operations happen locally in the browser.

**No account. No file upload. No password database.**

---

## Features

| Feature | SecureFileCrypt |
|---|---|
| File types | Almost any file |
| Encryption | AES-256-GCM |
| Password protection | Argon2id |
| Processing | Chunk-based |
| File upload | Not required |
| Password storage | None |
| Account | Not required |
| Output extension | None |
| Browser-based | Yes |
| Large-file support | Chunked processing |
| Older encrypted files | Supported |

---

## How It Works

### 1. Select a file

Choose any file from your device.

Examples:

`photo.jpg`  
`video.mp4`  
`document.pdf`  
`archive.zip`  
`backup.dat`

SecureFileCrypt does not require a specific file format.

### 2. Enter a password

The password is entered locally in your browser.

SecureFileCrypt does not send your password to a server or store it in a password database.

### 3. Generate a random salt

A cryptographically secure random salt is generated for every encryption operation.

This means that encrypting two files with the same password does not produce the same derived key.

### 4. Derive the encryption key

For new encrypted files, SecureFileCrypt uses **Argon2id** to derive a 256-bit encryption key from the password and random salt.

Argon2id is designed to make large-scale password-guessing attacks significantly more expensive.

### 5. Encrypt the file

The file is processed in chunks.

Each chunk is encrypted and authenticated using **AES-256-GCM**.

Authentication also allows the application to detect incorrect passwords or modified encrypted data.

### 6. Download the encrypted file

The result is an extensionless encrypted file.

For example:

```text
video.mp4
    ↓
video
```

The original file is not modified.

### 7. Decrypt it later

Select the encrypted file, enter the same password, and SecureFileCrypt restores the original filename and file contents.

```text
video
    ↓
video.mp4
```

---

## Security Architecture

```text
                 User Password
                       │
                       ▼
              Random 128-bit Salt
                       │
                       ▼
                    Argon2id
                       │
                       ▼
                256-bit AES Key
                       │
                       ▼
                 File Chunks
                       │
                       ▼
                 AES-256-GCM
                       │
                       ▼
              Encrypted File
```

### Argon2id

Argon2id is used for password-based key derivation in the current SFC3 format.

It is specifically designed to make password guessing more expensive than using a normal cryptographic hash.

### AES-256-GCM

AES-256-GCM provides both confidentiality and authentication.

A correct password is required to recover the plaintext, and tampering with encrypted data can be detected.

### Random Salt

Every encrypted file receives a new random salt.

The salt is stored in the encrypted file because it is not secret.

### Random Initialization Data

Encryption uses randomly generated initialization data, with separate per-chunk values derived from the base value.

### Local Processing

The application performs encryption and decryption inside the browser.

The project does not require a backend server to process the user's files.

---

## Privacy Model

SecureFileCrypt is intentionally designed without a file-upload backend.

```text
Your device
    │
    ├── File
    ├── Password
    └── Encryption
          │
          ▼
     Your browser
          │
          ▼
   Encrypted file
          │
          ▼
     Your device
```

GitHub Pages only serves the website.

The encryption operation does not require sending the selected file to GitHub or to a SecureFileCrypt server.

---

## Password Security

The password is the most important part of the security model.

Use a strong, unique password. A long passphrase is generally preferable to a short password.

**There is no password recovery mechanism.**

If the password is lost, SecureFileCrypt cannot recover the encrypted contents.

---

## Extensionless Files

SecureFileCrypt intentionally removes the normal file extension from the encrypted output.

For example:

```text
document.pdf
      ↓
document
```

Some newer operating systems, device security systems, file scanners, or storage applications may treat extensionless files as unknown files.

They may scan, block, quarantine, or remove such files.

**Keep backups of important encrypted files.**

---

## File Format Versions

SecureFileCrypt supports multiple internal formats.

### SFC1

Original SecureFileCrypt encryption format.

### SFC2

Chunk-based encryption format using PBKDF2 and AES-256-GCM.

### SFC3

Current encryption format using:

- Argon2id
- AES-256-GCM
- Random salt
- Chunk-based processing

New files use SFC3.

Older supported SecureFileCrypt files remain decryptable.

---

## No Password Database

SecureFileCrypt does not maintain a central password database.

There is no account system required to encrypt or decrypt a file.

Your password stays with you.

---

## Technology

SecureFileCrypt is built with:

- HTML
- CSS
- JavaScript
- Web Crypto API
- AES-256-GCM
- Argon2id
- GitHub Pages

---

## Project Structure

```text
SecureFileCrypt/
├── index.html
├── style.css
├── app.js
├── lib/
│   └── argon2-bundled.min.js
├── README.md
└── LICENSE
```

---

## Running Locally

Clone the repository:

```bash
git clone https://github.com/zehdso/SecureFileCrypt.git
cd SecureFileCrypt
```

Start a local web server:

```bash
python -m http.server 8080
```

Then open:

```text
http://localhost:8080
```

---

## Live Version

Use SecureFileCrypt directly in your browser:

**https://zehdso.github.io/SecureFileCrypt/**

---

## Source Available

The source code is publicly available so users can inspect how the application works.

The project is licensed under the custom **SecureFileCrypt Non-Commercial Source-Available License**.

Commercial use, commercial redistribution, paid hosting, and selling the software require permission from the copyright holder.

See [`LICENSE`](LICENSE) for the complete terms.

---

## Security Disclaimer

SecureFileCrypt is designed using established cryptographic primitives, but no software can guarantee absolute security.

Security also depends on:

- Password strength
- Device security
- Browser security
- Operating-system security
- Keeping backups
- Protecting the encrypted file

Do not rely on SecureFileCrypt as the only copy of important data.

---

## License

**SecureFileCrypt Non-Commercial Source-Available License**

Copyright © 2026 Zehdso.

See the [`LICENSE`](LICENSE) file for the complete license terms.

---

<p align="center">
  <strong>Secure your files. Keep control of your data.</strong>
</p>