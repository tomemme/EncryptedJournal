# Security Policy

## Supported Versions

Security fixes are currently applied to the active development branch:

- `omarchy-version`

Older commits, forks, and unmaintained branches may not receive security patches.

## Threat Model

Encrypted Journal is designed to protect journal contents at rest on a local machine.

In scope:
- Local file disclosure risk for `journal.json.gz`
- Journal entry confidentiality and integrity using AES-GCM + Scrypt key derivation
- Restrictive file permissions where the platform supports them

Out of scope:
- Compromised OS, malware, keyloggers, or hostile local admin/root access
- Physical attacks against RAM, swap, or disk forensic imaging on a live compromised host
- Cloud sync/provider compromise if users store journal files in third-party locations
- Shoulder surfing or weak/reused passwords

## Security Limitations

- Password recovery is not possible. If the password is lost, encrypted entries cannot be decrypted.
- Keyring storage is optional and increases convenience, but security depends on the host keyring backend.
- Journal metadata (for example date fields and file timestamps) may still reveal usage patterns.
- Decryption errors are treated as wrong password or corrupted ciphertext and may not distinguish root cause.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before public disclosure.

- Contact: `tomemme@outlook.com`
- Subject line: `EncryptedJournal Security Report`
- Include:
  - A clear description of impact
  - Reproduction steps or proof-of-concept
  - Affected version/commit
  - Suggested mitigation (if available)

I will acknowledge receipt as soon as possible and coordinate a fix/release timeline.

## Disclosure Process

After a fix is available, a coordinated disclosure is preferred:

1. Validate the patch.
2. Publish the fix.
3. Share advisory details and upgrade guidance.
