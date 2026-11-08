# Site Portrait for Laravel

`ctrlweb/laravel-site-portrait` implements the open **Site Portrait** protocol
for Laravel applications. It lets a service chosen by the site owner (for
example a hosting provider) securely read a **read-only, privacy-minimised
technical portrait** of the application: Laravel and PHP versions, drivers,
queues, server capacity, database size, Composer packages, storage volumes…

It is the Laravel counterpart of the WordPress plugin *ctrlweb Site Portrait*
and speaks the same protocol: a service that supports one supports the other.

- **No shared secret.** Pairing exchanges Ed25519 public keys (OAuth 2.0
  authorization code + PKCE). Every request and every response is signed
  (RFC 9421 HTTP Message Signatures), with replay protection.
- **Opt-in and scoped.** Nothing is sent until you pair; you choose which
  categories of data the service may read, and can change it at any time.
- **Read-only and minimised.** Never `.env` values, credentials, hosts, IP
  addresses, absolute paths, user data, queue names, route URIs or scheduled
  commands. Run `php artisan site-portrait:show` to see exactly what is shared.

## Requirements

- PHP 8.2+ (the `sodium` extension is recommended; a polyfill is bundled)
- Laravel 11, 12 or 13
- HTTPS in production

Laravel 11 is end of life and every 11.x release has open security advisories,
which recent Composer versions refuse to resolve by default. In an existing
Laravel 11 application, `composer require ctrlweb/laravel-site-portrait` works
as is: only the new package is resolved, and the locked framework is kept. A
full `composer update` of such an application fails with or without this
package, unless the advisories are explicitly accepted (`policy.advisories`
in `composer.json`). Upgrading to Laravel 12 or 13 is the real fix.

## Installation

```sh
composer require ctrlweb/laravel-site-portrait
php artisan site-portrait:install
```

`site-portrait:install` publishes `config/site-portrait.php` and runs the
migrations (three tables: `site_portrait_pairings`, `site_portrait_nonces`,
`site_portrait_access_log`).

Check before pairing:

- `APP_URL` (or `SITE_PORTRAIT_URL`) is the public HTTPS URL of the application.
  It is the identity of the site and the host requests must be signed for.
- Behind a proxy or load balancer, `TrustProxies` is configured so HTTPS and the
  client IP are detected correctly.
- The endpoints are reachable **without redirection** (no trailing-slash,
  `www` or HTTP→HTTPS redirects) and must not move after pairing: a service
  treats a 404 as "pairing gone".
- `php artisan site-portrait:prune` is scheduled (e.g. daily).

## Pairing

```sh
php artisan site-portrait:pair https://service.example
```

The command reads the service's discovery document, shows its name and privacy
policy, lets you choose the scopes, then prints an authorization URL. Open it in
a browser, sign in to the service and approve: you are sent back to
`/site-portrait/callback`, which completes the key exchange. The service then
confirms the pairing by calling `/status`.

The callback is protected by a single-use token and the OAuth `state`. To also
require a signed-in user of your application, set for example:

```php
// config/site-portrait.php
'callback_middleware' => ['web', 'auth', 'can:manageSitePortrait'],
```

Non-interactive pairing (deployment scripts): `--scopes=server,database --yes`.

## Commands

| Command | Purpose |
|---|---|
| `site-portrait:install` | Publish the config, run the migrations, print the checklist. |
| `site-portrait:pair {url}` | Connect to a service. |
| `site-portrait:status` | Show the connection, scopes, keys and recent activity. |
| `site-portrait:scopes --grant= --deny=` | Change the granted scopes without re-pairing. |
| `site-portrait:show --scopes=` | Print the portrait exactly as the service would receive it. |
| `site-portrait:log` | Access log of the endpoints. |
| `site-portrait:rotate-key` | Rotate the site signing key (old key published 7 days). |
| `site-portrait:disconnect` | Revoke locally, then notify the service. |
| `site-portrait:forget` | Delete the pairing locally without notifying anyone. |
| `site-portrait:prune` | Delete expired nonces, old log entries and stale authorizations. |

When uninstalling the package, run
`php artisan site-portrait:disconnect --reason=plugin_uninstalled` first.

## Scopes

| Scope | Contents |
|---|---|
| `laravel` | Framework version, environment type, debug and maintenance flags, timezone and locale, optimisation caches, **driver names** (cache, session, queue, mail, broadcasting, filesystem, log), Octane, detected ecosystem packages (Horizon, Livewire, Filament…), pending and failed jobs, batches, scheduled tasks per cron expression, number of routes and commands. |
| `packages` | Installed Composer packages (name, version, type, direct, dev), counts, PHP and extension requirements. Never repository URLs. Hide private packages by name with `hidden_packages` (they are still counted). |
| `server` | OS family, architecture, container detection, web server, PHP version/SAPI/extensions/limits, OPcache, CPU and memory (including cgroup limits), disk space of the storage volume, library versions. |
| `database` | Engine and version, charset, total size, table count and the ten largest tables (prefix stripped), a few server variables. |
| `storage` | Sizes of `storage/app`, `storage/app/public`, logs, framework caches, `public`, `vendor`, `node_modules`, and of local filesystem disks (remote disks are never listed); number of files in `storage/app`, `storage/app/public` and `public`. Computed in one walk with a time budget and cached for an hour. |
| `users_counts` | Number of users of the default auth provider, per role with spatie/laravel-permission. Counts only. |

The WordPress-only scopes (`core`, `plugins`, `themes`, `content`) are not
offered; scopes a service supports for other platforms are ignored.

### Extending the portrait

Add your own data under `data.<scope>.extensions.<slug>` (it cannot alter the
core members, and you are responsible for keeping it free of secrets):

```php
use Ctrlweb\SitePortrait\Facades\SitePortrait;

SitePortrait::extend('laravel', 'acme-billing', fn () => [
    'invoices_count' => Invoice::count(),
]);
```

Collectors can also be replaced through the `scopes` map of the configuration.

## Security

- Every endpoint requires a valid signature from a pinned service key; session,
  cookie and token authentication are ignored. Responses (errors included) are
  signed with the site key and bound to the request.
- Requests are accepted within a 300-second window and each nonce only once.
- Rate limits: 60 authenticated requests per hour (sliding window), and 30
  failed requests per IP and hour; valid requests are never blocked by the latter.
- Optional IP allow-list (`SITE_PORTRAIT_IP_ALLOWLIST`, IPs or CIDR ranges).
- The site private key is stored encrypted with `APP_KEY`. If you rotate
  `APP_KEY`, keep the old key in `APP_PREVIOUS_KEYS` or pair again.
- Outbound calls (discovery, code exchange, revocation notice) only happen on
  an administrator's action, require HTTPS, follow no redirects, are size-capped
  and refuse private or reserved addresses (the resolved address is pinned).
- A proxy that rewrites the path or the host, or that alters the response body,
  breaks signature verification by design.

Development mode (`SITE_PORTRAIT_DEV_MODE=true`) accepts plain HTTP and local
hosts, only when `APP_ENV` is `local` or `development` and the hosts are
`localhost`, `127.0.0.1`, `[::1]`, `*.test` or `*.localhost`. Never enable it in
production.

## Testing

```sh
composer test            # PHPUnit (Orchestra Testbench), protocol test vectors included
composer analyse         # Larastan
composer lint            # Pint
composer test:e2e        # interoperability with the reference service
```

The end-to-end test serves a workbench application (`testbench.yaml`) and pairs
it with the reference service of the specification (`bin/reference-client.mjs`
in the [site-portrait-protocol](https://github.com/ctrlwebinc/site-portrait-protocol)
repository, which needs `npm install` for schema validation). It looks for that
repository in `../site-portrait-protocol`; set `SP_REFERENCE_DIR` to use
another checkout.

## License

The package is released under the [MIT license](LICENSE). The protocol
specification and the JSON schemas in `resources/schema/` are licensed under
CC-BY-4.0.
