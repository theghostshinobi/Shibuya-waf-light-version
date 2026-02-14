# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-02-05

### Fixed
- **[Frontend]** Removed deprecated `toggleRule()` API method that caused 404 errors.
  - Aligns frontend with backend API contract (`PUT /api/rules/:id`).
  - Replaces dead code with standard `updateRule` calls.

### Added
- **[Core]** Git Auto-Reload for Policy-as-Code (Fix #3).
  - Enables polling a Git repository for configuration and rule updates.
  - Supports SSH and HTTPS authentication with environment variable secrets.
  - Implements seamless hot-reloading of policies.

### Breaking Changes
- `api.toggleRule()` method removed from frontend client.
  - **Migration**: Replace `api.toggleRule(id, enabled)` with `api.updateRule(id, { enabled })`.
