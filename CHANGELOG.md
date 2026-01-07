# Changelog

All notable changes to this project will be documented in this file.
---

## [2.0.0] — 2026-01-07
### Changed
- Introduced a hierarchical key structure for the vault.
- Entry secrets remain encrypted at rest and are decrypted only on explicit user request.

### Added
- csv_export command that exports the vault to plaintext csv

### Migration Notes
- See [1.4.1] for required export steps prior to upgrading.

---

## [1.4.1] — 2026-01-07
### Changed
- Updated vault handling to support exporting legacy vaults to CSV.

### Added
- csv_export command that works for legacy vault migration.

### Migration Notes
- This release prepares for v2.0.0, which introduces a new encryption model.
- Vaults encrypted with versions prior to 2.0.0 are not compatible.
- Export the existing vault using csv_export and append "_fields." to sensitive headers (password, rec_keys, totp) before importing into v2.0.0.

---

## [1.4.0] — 2025-12-29
### Changed
- The codebase was refactored to operate on Entry objects, centralizing encryption, serialization, and validation logic and eliminating ad-hoc field handling.

### Added
- Diceware passphrase generator
- CSV import schema detection added

### Migration Notes
- Existing vaults must be exported with plaintext and password history must be deleted from export before importing or in list[tuple] format [(pendulum datetime, password(str))]

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

