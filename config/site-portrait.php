<?php

use Ctrlweb\SitePortrait\Collectors;

return [

    /*
    |--------------------------------------------------------------------------
    | Enable the Site Portrait endpoints
    |--------------------------------------------------------------------------
    |
    | When false, no route is registered at all. Pairing stays stored, so the
    | service will see 404 responses (and treat the pairing as gone).
    |
    */

    'enabled' => env('SITE_PORTRAIT_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Public URL of the site
    |--------------------------------------------------------------------------
    |
    | Used as the OAuth client_id (its origin), to build the endpoint URLs
    | given to the service, and as the expected @authority of signed requests.
    | Never derived from the Host header. Defaults to APP_URL.
    |
    */

    'site_url' => env('SITE_PORTRAIT_URL'),

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | The endpoint URLs are given to the service at pairing time and must not
    | change afterwards: a 404 makes the service drop the pairing.
    |
    | The callback is opened in the administrator's browser at the end of the
    | authorization. It is protected by a single-use token and the OAuth state;
    | add middleware (e.g. ['web', 'auth', 'can:manageSitePortrait']) to also
    | require an authenticated user of the application.
    |
    */

    'route_prefix' => env('SITE_PORTRAIT_ROUTE_PREFIX', 'site-portrait/v1'),

    'route_domain' => env('SITE_PORTRAIT_ROUTE_DOMAIN'),

    'callback_path' => env('SITE_PORTRAIT_CALLBACK_PATH', 'site-portrait/callback'),

    'callback_middleware' => [],

    /*
    |--------------------------------------------------------------------------
    | Scopes and their collectors
    |--------------------------------------------------------------------------
    |
    | Scope name => collector class. Only these scopes are offered to the
    | service; scopes of other platforms in its discovery document are ignored.
    |
    */

    'scopes' => [
        'laravel' => Collectors\LaravelCollector::class,
        'packages' => Collectors\PackagesCollector::class,
        'server' => Collectors\ServerCollector::class,
        'database' => Collectors\DatabaseCollector::class,
        'storage' => Collectors\StorageCollector::class,
        'users_counts' => Collectors\UsersCountsCollector::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Site-side policies (PROTOCOL.md §12)
    |--------------------------------------------------------------------------
    */

    // Authenticated requests per pairing and sliding hour.
    'rate_limit' => (int) env('SITE_PORTRAIT_RATE_LIMIT', 60),

    // Failed requests per source IP and hour.
    'failure_limit' => (int) env('SITE_PORTRAIT_FAILURE_LIMIT', 30),

    // IPs or CIDR ranges allowed to call the endpoints (empty: any).
    // The client IP is Request::ip(): configure TrustProxies behind a proxy.
    'ip_allowlist' => array_values(array_filter(array_map('trim', explode(',', (string) env('SITE_PORTRAIT_IP_ALLOWLIST', ''))))),

    'access_log' => [
        'retention_days' => 90,
        'max_entries' => 10000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Collection
    |--------------------------------------------------------------------------
    */

    // Database connection described by the "database" scope (null: default).
    'database_connection' => env('SITE_PORTRAIT_DB_CONNECTION'),

    // Time budget (seconds) for directory sizes, and cache lifetime of the result.
    'size_budget' => 10,
    'size_cache_ttl' => 3600,

    // Composer packages never listed by name (wildcards allowed, e.g. "acme/*").
    // They are still counted.
    'hidden_packages' => [],

    /*
    |--------------------------------------------------------------------------
    | Package storage
    |--------------------------------------------------------------------------
    |
    | Connection holding the package tables (pairing, nonces, access log).
    |
    */

    'storage_connection' => env('SITE_PORTRAIT_STORAGE_CONNECTION'),

    /*
    |--------------------------------------------------------------------------
    | Outbound HTTP (discovery, code exchange, revocation notice)
    |--------------------------------------------------------------------------
    */

    'http_timeout' => 15,

    // Minimum seconds between two discovery refreshes when the service signs
    // with an unknown key (service key rotation, PROTOCOL.md §11.1).
    'key_refresh_interval' => (int) env('SITE_PORTRAIT_KEY_REFRESH_INTERVAL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Development mode (PROTOCOL.md §14.6)
    |--------------------------------------------------------------------------
    |
    | Allows plain HTTP and local hosts. Only effective when the application
    | environment is "local" or "development" AND the site and service hosts
    | are localhost, 127.0.0.1, [::1] or end in .test / .localhost.
    | Never enable in production.
    |
    */

    'dev_mode' => env('SITE_PORTRAIT_DEV_MODE', false),

];
