# Changelog

All notable changes to this project will be documented in this file.

---

## [1.3.0] — 2025-12-19

### Added
- Optional TPM protection added.
- Ability to export vault in portable mode. Removes TPM protection from the export.
- Ability to import a portable mode encrypted vault. 

### Migration Notes
- Existing vaults can be migrated using the provided import tools.

---

## [1.2.0] — 2025-12-17

### Changed
- Replaced legacy token-based encryption with modern AEAD.
- Vault entries are now bound to their identifiers during encryption.

### Migration Notes
- Existing vaults must be migrated using the provided import/export tools.
- Old encrypted vaults are not compatible with this release.

---

## [1.1.4] — 2025-10-16

### Added
- Built-in password security auditing (strength, reuse, breach exposure).
- Optional CSV export for audit results.

---

## [1.1.3] — 2025-10-13

### Changed
- Updated import/export 

---

## [1.1.2] — 2025-10-11

### Added
- Added 2FA code generator

---

## [1.1.1] — 2025-10-05

### Changed
- Switched to Argon2id KDF

---

## [1.1.0] — 2025-10-04

### Added
- Password history tracking with configurable limits.
- Full-text search across all entry fields.

---

## [1.0.0] — 2025-11-29

### Added
- Initial public release.
- Encrypted password storage with master password protection.

