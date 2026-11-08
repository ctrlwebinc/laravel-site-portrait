<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait;

use Closure;
use Composer\InstalledVersions;
use Ctrlweb\SitePortrait\Collectors\CollectContext;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;

/**
 * Environment of the site implementation: URLs, scopes, development mode,
 * client IP resolution and third-party extensions.
 */
class SitePortrait
{
    public const PACKAGE = 'ctrlweb/laravel-site-portrait';

    public const PROTOCOL_VERSION = '1';

    public const SCHEMA_VERSION = '1.1.0';

    public const SCOPE_RE = '/^[a-z][a-z0-9_]{1,31}$/';

    /** @var (Closure(Request): ?string)|null */
    protected ?Closure $clientIpResolver = null;

    /** @var array<string, array<string, Closure(CollectContext): array<string, mixed>>> */
    protected array $extensions = [];

    public function __construct(protected Application $app) {}

    /** Version of this package, sent as plugin_version. */
    public function version(): string
    {
        try {
            $version = InstalledVersions::isInstalled(self::PACKAGE) ? InstalledVersions::getPrettyVersion(self::PACKAGE) : null;
        } catch (\Throwable) {
            $version = null;
        }

        return substr($version ?? 'dev', 0, 32);
    }

    /**
     * @return array{name: string, version: string}
     */
    public function platform(): array
    {
        return ['name' => 'laravel', 'version' => $this->app->version()];
    }

    /**
     * Scopes this site implements, in display order.
     *
     * @return list<string>
     */
    public function scopes(): array
    {
        $scopes = array_keys((array) config('site-portrait.scopes', []));

        return array_values(array_filter($scopes, fn ($s) => is_string($s) && preg_match(self::SCOPE_RE, $s)));
    }

    /**
     * Keeps only scopes implemented here, in canonical order.
     *
     * @return list<string>
     */
    public function sanitizeScopes(mixed $scopes): array
    {
        $scopes = is_array($scopes) ? $scopes : [];

        return array_values(array_intersect($this->scopes(), $scopes));
    }

    public function siteUrl(): string
    {
        $url = config('site-portrait.site_url') ?: config('app.url');

        return rtrim((string) $url, '/');
    }

    /** Origin of the site URL: the OAuth client_id. */
    public function origin(): string
    {
        return (string) HttpSignature::origin($this->siteUrl());
    }

    /** Authority the service must sign for incoming requests. */
    public function expectedAuthority(): string
    {
        $parts = parse_url($this->siteUrl()) ?: [];

        return HttpSignature::authority($parts['scheme'] ?? 'https', $parts['host'] ?? '', $parts['port'] ?? null);
    }

    public function siteName(): string
    {
        return mb_substr(trim(strip_tags((string) config('app.name', ''))), 0, 100);
    }

    /**
     * Absolute URL of an endpoint, as given to the service.
     */
    public function endpointUrl(string $endpoint): string
    {
        return $this->siteUrl().'/'.trim((string) config('site-portrait.route_prefix'), '/').'/'.$endpoint;
    }

    /**
     * @return array{status: string, portrait: string, revoke: string}
     */
    public function endpoints(): array
    {
        return [
            'status' => $this->endpointUrl('status'),
            'portrait' => $this->endpointUrl('portrait'),
            'revoke' => $this->endpointUrl('revoke'),
        ];
    }

    public function callbackUrl(string $token): string
    {
        return $this->siteUrl().'/'.trim((string) config('site-portrait.callback_path'), '/').'?token='.rawurlencode($token);
    }

    /** Development mode (PROTOCOL.md §14.6). */
    public function isDevMode(): bool
    {
        return filter_var(config('site-portrait.dev_mode'), FILTER_VALIDATE_BOOL)
            && $this->app->environment(['local', 'development'])
            && self::isDevHost((string) parse_url($this->siteUrl(), PHP_URL_HOST));
    }

    public static function isDevHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return true;
        }

        return (bool) preg_match('/\.(test|localhost)$/', $host);
    }

    /** Whether a URL may be used to talk to a service: HTTPS, or a dev host in dev mode. */
    public function isAllowedServiceUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme === 'https') {
            return true;
        }

        return $scheme === 'http' && $this->isDevMode() && self::isDevHost($parts['host']);
    }

    /**
     * Resolves the client IP (default: Request::ip(), which honours TrustProxies).
     *
     * @param  Closure(Request): ?string  $resolver
     */
    public function resolveClientIpUsing(Closure $resolver): static
    {
        $this->clientIpResolver = $resolver;

        return $this;
    }

    public function clientIp(Request $request): string
    {
        $ip = $this->clientIpResolver !== null ? ($this->clientIpResolver)($request) : $request->ip();

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
    }

    /**
     * Adds data under data.<scope>.extensions.<slug> (equivalent of the
     * site_portrait_scope_data filter). The callback may not alter core members.
     *
     * @param  Closure(CollectContext): array<string, mixed>  $callback
     */
    public function extend(string $scope, string $slug, Closure $callback): static
    {
        if (! preg_match('/^[a-z0-9][a-z0-9_.\/-]{0,63}$/', $slug)) {
            throw new \InvalidArgumentException('Invalid extension slug.');
        }
        $this->extensions[$scope][$slug] = $callback;

        return $this;
    }

    /**
     * @return array<string, Closure(CollectContext): array<string, mixed>>
     */
    public function extensions(string $scope): array
    {
        return $this->extensions[$scope] ?? [];
    }
}
