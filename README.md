# SecureFileCrypt

SecureFileCrypt is a free, open-source, browser-based file encryption tool that lets you encrypt and decrypt files locally using a password.

**Live website:** https://zehdso.github.io/SecureFileCrypt/

## Features

- Encrypt almost any file type
- Decrypt encrypted files with the correct password
- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Random salt for every encrypted file
- Chunk-based processing for large files
- No password storage
- No account required
- No file upload to a server
- Runs entirely in the browser
- Extensionless encrypted output
- Manual download after encryption/decryption
- Show/hide password controls
- Backward compatibility with earlier SecureFileCrypt formats

## How It Works

1. Select a file.
2. Enter a password.
3. SecureFileCrypt generates a random salt.
4. Argon2id derives a 256-bit encryption key from the password and salt.
5. The file is processed in chunks.
6. AES-256-GCM encrypts and authenticates each chunk.
7. The encrypted result can be downloaded as an extensionless file.
8. To restore it, select the encrypted file and enter the same password.

## Security

### Argon2id

New encrypted files use Argon2id to derive the encryption key from the user's password, making password-guessing attacks significantly more expensive.

### AES-256-GCM

File contents are encrypted using AES with a 256-bit key, while GCM authentication helps detect incorrect passwords and tampering.

### Random Salt

Every encryption operation generates a fresh random salt, so using the same password for different files does not produce the same derived key.

### Local Processing

Files and passwords are processed locally inside the browser. SecureFileCrypt does not require uploading files to a server.

### No Password Storage

SecureFileCrypt does not store the user's password.

## Important

**Your password is critical.**

If you forget the password, SecureFileCrypt cannot recover the encrypted file for you.

Use a long, unique password for important files.

The encrypted file has no extension. Some devices or security software may treat extensionless files as unknown files and may scan, block, or remove them, so keep backups of important encrypted files.

## File Formats

SecureFileCrypt currently supports multiple internal formats:

- **SFC1** — original encryption format
- **SFC2** — chunked encryption format using PBKDF2
- **SFC3** — current format using Argon2id and chunked AES-256-GCM

Older SecureFileCrypt encrypted files remain decryptable when their format is supported.

## Privacy

SecureFileCrypt is designed around local processing.

GitHub Pages hosts the website, while encryption and decryption happen inside the user's browser. The application does not need to receive the user's files or passwords.

## Technology

- HTML
- CSS
- JavaScript
- Web Crypto API
- AES-256-GCM
- Argon2id
- GitHub Pages

## Open Source

SecureFileCrypt is open source and can be inspected, modified, and self-hosted.

## Disclaimer

SecureFileCrypt is provided as an open-source privacy tool. Keep independent backups of important files and passwords.

Encryption cannot protect a weak password or a compromised device.

## License

See the repository license for the terms under which SecureFileCrypt may be used, modified, and distributed.
