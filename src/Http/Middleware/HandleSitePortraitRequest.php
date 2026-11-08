<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Http\Middleware;

use Closure;
use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Models\Nonce;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\Protocol\IpAllowlist;
use Ctrlweb\SitePortrait\Protocol\ProtocolError;
use Ctrlweb\SitePortrait\Protocol\SignatureException;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates requests of the site API (IP, HTTPS, digest, signature,
 * replay, rate limits) and serialises, signs and logs every response,
 * errors included (PROTOCOL.md §5, §6, §9, §12).
 */
class HandleSitePortraitRequest
{
    public const CONTENT_TYPE = 'application/json; charset=UTF-8';

    public const AUTH_ATTRIBUTE = 'site_portrait.auth';

    public const SCOPES_ATTRIBUTE = 'site_portrait.log_scopes';

    public function __construct(
        protected SitePortrait $sitePortrait,
        protected PairingManager $pairings,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $pairing = $this->pairings->active();

        // Without a pairing the API does not exist (rest_no_route, unsigned).
        if ($pairing === null) {
            return new JsonResponse(
                ['code' => 'rest_no_route', 'message' => 'No route was found matching the URL and request method.', 'data' => ['status' => 404]],
                404,
                ['Cache-Control' => 'no-store'],
            );
        }

        // Kept for the response, even if /revoke deletes the pairing.
        $signer = ['secret' => $pairing->siteSecretKey(), 'kid' => $pairing->site_key_kid];
        $ip = $this->sitePortrait->clientIp($request);
        $auth = null;
        $retryAfter = null;

        try {
            $auth = $this->authenticate($request, $ip);
            $request->attributes->set(self::AUTH_ATTRIBUTE, $auth);
            $response = $next($request);
            [$status, $data] = $this->extract($response);
        } catch (ProtocolError $e) {
            [$status, $data, $retryAfter] = [$e->status, $e->toArray(), $e->retryAfter];
        }

        return $this->respond($request, $status, $data, $signer, $auth, $ip, $retryAfter);
    }

    /**
     * @return array{kid: string, nonce: string, created: int, expires: int, signature: string}
     */
    protected function authenticate(Request $request, string $ip): array
    {
        $allowlist = array_values(array_filter((array) config('site-portrait.ip_allowlist', []), 'is_string'));
        if ($allowlist !== [] && ! IpAllowlist::matches($ip, $allowlist)) {
            throw new ProtocolError('site_portrait_ip_not_allowed', 'Source IP address not allowed.', 403);
        }
        if (! $request->isSecure() && ! $this->sitePortrait->isDevMode()) {
            throw new ProtocolError('site_portrait_https_required', 'HTTPS is required.', 403);
        }

        $target = $this->requestTarget($request);
        if ($target === null) {
            $this->failure($ip, new ProtocolError('site_portrait_signature_malformed', 'Invalid request target.', 401));
        }

        $headers = [];
        foreach (['signature-input', 'signature', 'content-type', 'content-digest'] as $name) {
            $value = $request->headers->get($name);
            if ($value !== null) {
                $headers[$name] = $value;
            }
        }

        if ($request->getMethod() !== 'GET' && $request->getMethod() !== 'HEAD') {
            if (! isset($headers['content-digest']) || ! hash_equals(Crypto::contentDigest((string) $request->getContent()), trim($headers['content-digest']))) {
                $this->failure($ip, new ProtocolError('site_portrait_digest_mismatch', 'Content-Digest does not match the body.', 400));
            }
        }

        try {
            $auth = HttpSignature::verifyRequest(
                [
                    'method' => $request->getMethod(),
                    'authority' => $this->sitePortrait->expectedAuthority(),
                    'path' => $target['path'],
                    'query' => $target['query'],
                    'headers' => $headers,
                ],
                fn (string $kid) => $this->pairings->serviceKey($kid),
                Carbon::now()->getTimestamp(),
            );
        } catch (SignatureException $e) {
            $this->failure($ip, ProtocolError::fromSignature($e));
        }

        if (! Nonce::consume($auth['kid'], $auth['nonce'], $auth['expires'])) {
            $this->failure($ip, new ProtocolError('site_portrait_replay', 'Nonce already used.', 401));
        }

        $limit = max(1, (int) config('site-portrait.rate_limit', 60));
        if (AccessLogEntry::authenticatedLastHour() >= $limit) {
            $oldest = AccessLogEntry::oldestAuthenticatedInWindow();
            $now = Carbon::now()->getTimestamp();
            $retry = max(1, ($oldest?->getTimestamp() ?? $now) + 3600 - $now);
            throw new ProtocolError('site_portrait_rate_limited', 'Rate limit exceeded.', 429, $retry);
        }

        return $auth;
    }

    /**
     * Path and query exactly as received on the wire.
     *
     * @return array{path: string, query: string}|null
     */
    protected function requestTarget(Request $request): ?array
    {
        $uri = $request->server->get('REQUEST_URI');
        if (! is_string($uri) || $uri === '' || ! preg_match('/^[\x21-\x7e]+$/', $uri)) {
            return null;
        }
        // Absolute-form request targets (proxies) carry scheme and host.
        if (preg_match('#^[a-z][a-z0-9+.-]*://[^/]*(/.*)?$#i', $uri, $m)) {
            $uri = $m[1] ?? '/';
        }
        $parts = explode('?', $uri, 2);

        return ['path' => $parts[0], 'query' => '?'.($parts[1] ?? '')];
    }

    /**
     * Returns the authentication error, or 429 once an IP has failed too often.
     * Only failed requests count: a valid signature is never blocked.
     */
    protected function failure(string $ip, ProtocolError $error): never
    {
        $limit = (int) config('site-portrait.failure_limit', 30);
        if (AccessLogEntry::failuresLastHour($ip) >= $limit) {
            throw new ProtocolError('site_portrait_rate_limited', 'Too many failed requests.', 429, 3600);
        }

        throw $error;
    }

    /**
     * Status and data of the controller response. Exceptions rendered by the
     * framework never leak: they become protocol errors.
     *
     * @return array{0: int, 1: mixed}
     */
    protected function extract(Response $response): array
    {
        $exception = property_exists($response, 'exception') ? $response->exception : null;
        if ($exception instanceof ProtocolError) {
            if ($exception->retryAfter !== null) {
                throw $exception;
            }

            return [$exception->status, $exception->toArray()];
        }
        if ($exception !== null || ! $response instanceof JsonResponse) {
            report_if($exception === null, new \RuntimeException('Site Portrait endpoint returned a non-JSON response.'));

            return [500, (new ProtocolError('site_portrait_internal_error', 'Unexpected failure.', 500))->toArray()];
        }

        // Decoded as objects so that empty JSON objects ({}) stay objects.
        return [$response->getStatusCode(), $response->getData()];
    }

    /**
     * @param  array{secret: string, kid: string}  $signer
     * @param  array{kid: string, nonce: string, created: int, expires: int, signature: string}|null  $auth
     */
    protected function respond(Request $request, int $status, mixed $data, array $signer, ?array $auth, string $ip, ?int $retryAfter): Response
    {
        $body = (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        $digest = Crypto::contentDigest($body);

        $headers = [
            'Content-Type' => self::CONTENT_TYPE,
            'Cache-Control' => 'no-store',
            'Site-Portrait-Protocol' => SitePortrait::PROTOCOL_VERSION,
            'Content-Digest' => $digest,
        ];
        if ($retryAfter !== null) {
            $headers['Retry-After'] = (string) $retryAfter;
        }
        $headers += HttpSignature::signResponse(
            $status,
            self::CONTENT_TYPE,
            $digest,
            $auth['signature'] ?? null,
            $signer['secret'],
            $signer['kid'],
            Carbon::now()->getTimestamp(),
        );

        $prefix = '/'.trim((string) config('site-portrait.route_prefix'), '/');
        $path = '/'.ltrim($request->path(), '/');
        $endpoint = str_contains($path, $prefix) ? substr($path, strpos($path, $prefix) + strlen($prefix)) : $path;
        $code = is_array($data) ? ($data['code'] ?? null) : (is_object($data) ? ($data->code ?? null) : null);

        AccessLogEntry::record([
            'ip' => $ip !== '' ? $ip : null,
            'method' => substr($request->getMethod(), 0, 8),
            'endpoint' => substr($endpoint, 0, 32),
            'key_id' => $auth['kid'] ?? null,
            'scopes' => $request->attributes->get(self::SCOPES_ATTRIBUTE, []),
            'status' => $status,
            'error_code' => is_string($code) ? substr($code, 0, 64) : null,
            'authenticated' => $auth !== null,
        ]);

        return new Response($request->isMethod('HEAD') ? '' : $body, $status, $headers);
    }
}
