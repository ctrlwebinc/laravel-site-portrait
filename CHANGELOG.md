# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the package follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Site Portrait protocol version 1 for Laravel 11–13: pairing (authorization
  code + PKCE, Ed25519 key exchange), signed API (`/status`, `/portrait`,
  `/revoke`), replay protection, rate limits, IP allow-list, access log, key
  rotation through endorsements, revocation in both directions.
- Scopes `laravel`, `packages`, `server`, `database`, `storage` and
  `users_counts` (portrait schema 1.1.0).
- Artisan commands: install, pair, status, scopes, show, log, rotate-key,
  disconnect, forget, prune.
- Extension point `SitePortrait::extend()`.
