<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Pairing;

use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\SitePortrait;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Psr\Http\Message\ResponseInterface;

/**
 * Outbound calls to the service: discovery, code exchange and revocation
 * notice (PROTOCOL.md §3, §4.4, §10.1). Only triggered by an administrator.
 */
class ServiceClient
{
    public const DISCOVERY_PATH = '/.well-known/site-portrait';

    public const MAX_DISCOVERY_SIZE = 65536;

    public function __construct(
        protected SitePortrait $sitePortrait,
        protected HttpFactory $http,
        protected HostResolver $resolver,
    ) {}

    /**
     * Fetches and validates a discovery document.
     *
     * @return array<string, mixed> Normalised discovery data.
     */
    public function discover(string $input): array
    {
        $input = trim($input);
        if ($input !== '' && ! preg_match('#^[a-z][a-z0-9+.-]*://#i', $input)) {
            $input = 'https://'.$input;
        }
        $origin = HttpSignature::origin($input);
        if ($origin === null || ! $this->sitePortrait->isAllowedServiceUrl($origin)) {
            throw new PairingException('invalid_service_url', 'Enter the HTTPS address of the service, for example https://service.example.');
        }

        $response = $this->request('GET', $origin.self::DISCOVERY_PATH, null, null, 10, self::MAX_DISCOVERY_SIZE);
        if ($response['status'] !== 200) {
            throw new PairingException('discovery_failed', sprintf('The service did not publish a Site Portrait discovery document (HTTP status %d).', $response['status']));
        }
        $document = json_decode($response['body'], true);
        if (! is_array($document)) {
            throw new PairingException('discovery_invalid', 'The service discovery document is not valid JSON.');
        }

        return $this->validateDiscovery($document, $origin);
    }

    /**
     * @param  array<string, mixed>  $doc
     * @return array<string, mixed>
     */
    public function validateDiscovery(array $doc, string $origin): array
    {
        $invalid = fn (string $what) => new PairingException('discovery_invalid', sprintf('The service discovery document is invalid (%s).', $what));

        if (($doc['protocol'] ?? null) !== 'site-portrait') {
            throw $invalid('protocol');
        }
        if (! is_array($doc['protocol_versions'] ?? null) || ! in_array(SitePortrait::PROTOCOL_VERSION, $doc['protocol_versions'], true)) {
            throw new PairingException('discovery_version', 'The service does not support version 1 of the Site Portrait protocol.');
        }

        $service = is_array($doc['service'] ?? null) ? $doc['service'] : [];
        $name = isset($service['name']) && is_string($service['name']) ? self::text($service['name'], 100) : '';
        if ($name === '') {
            throw $invalid('service.name');
        }

        $anyUrl = fn ($url) => is_string($url) && $this->sitePortrait->isAllowedServiceUrl($url);
        $sameOrigin = fn ($url) => $anyUrl($url) && HttpSignature::origin($url) === $origin;

        if (! $anyUrl($service['privacy_policy_url'] ?? null)) {
            throw $invalid('service.privacy_policy_url');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'revocation_endpoint'] as $endpoint) {
            if (! $sameOrigin($doc[$endpoint] ?? null)) {
                throw $invalid($endpoint);
            }
        }

        $keys = self::parseJwks($doc['jwks'] ?? null);
        if ($keys === []) {
            throw $invalid('jwks');
        }

        // Scopes of other platforms are ignored.
        $supported = $this->sitePortrait->sanitizeScopes($doc['scopes_supported'] ?? []);
        if ($supported === []) {
            throw new PairingException('discovery_no_scope', 'The service does not support any scope implemented by this application ('.implode(', ', $this->sitePortrait->scopes()).').');
        }
        $requested = isset($doc['scopes_requested']) ? $this->sitePortrait->sanitizeScopes($doc['scopes_requested']) : $supported;

        $reasons = [];
        if (is_array($doc['scope_reasons'] ?? null)) {
            foreach ($supported as $scope) {
                if (isset($doc['scope_reasons'][$scope]) && is_string($doc['scope_reasons'][$scope])) {
                    $reasons[$scope] = self::text($doc['scope_reasons'][$scope], 300);
                }
            }
        }

        $optionalUrl = fn ($url) => $anyUrl($url) ? (string) $url : '';

        return [
            'origin' => $origin,
            'name' => $name,
            'description' => isset($service['description']) && is_string($service['description']) ? self::text($service['description'], 500) : '',
            'homepage' => $optionalUrl($service['homepage'] ?? null),
            'privacy_policy_url' => (string) $service['privacy_policy_url'],
            'terms_url' => $optionalUrl($service['terms_url'] ?? null),
            'contact' => isset($service['contact']) && is_string($service['contact']) ? self::text($service['contact'], 200) : '',
            'authorization_endpoint' => (string) $doc['authorization_endpoint'],
            'token_endpoint' => (string) $doc['token_endpoint'],
            'revocation_endpoint' => (string) $doc['revocation_endpoint'],
            'scopes_supported' => $supported,
            'scopes_requested' => $requested,
            'scope_reasons' => $reasons,
            'keys' => $keys,
        ];
    }

    /**
     * Valid Ed25519 keys of a JWKS (at most 10).
     *
     * @return array<string, array<string, mixed>> kid => JWK
     */
    public static function parseJwks(mixed $jwks): array
    {
        $keys = [];
        if (! is_array($jwks) || ! is_array($jwks['keys'] ?? null)) {
            return $keys;
        }
        foreach (array_slice($jwks['keys'], 0, 10) as $jwk) {
            $public = Crypto::publicKeyFromJwk($jwk);
            if ($public === null) {
                continue;
            }
            $clean = Crypto::publicJwk($public);
            if (isset($jwk['endorsements']) && is_array($jwk['endorsements'])) {
                $clean['endorsements'] = $jwk['endorsements'];
            }
            $keys[$clean['kid']] = $clean;
        }

        return $keys;
    }

    /**
     * Performs an HTTP request, optionally signed (§5.1). No redirects, size-capped,
     * and restricted to public addresses outside development mode.
     *
     * @param  array<string, mixed>|null  $body
     * @param  array{secret: string, kid: string}|null  $signer
     * @return array{status: int, body: string, headers: array<string, string>}
     */
    public function request(string $method, string $url, ?array $body = null, ?array $signer = null, ?int $timeout = null, int $maxSize = 1048576): array
    {
        if (! $this->sitePortrait->isAllowedServiceUrl($url)) {
            throw new PairingException('invalid_service_url', 'The service address must use HTTPS.');
        }

        $headers = [
            'Accept' => 'application/json',
            'User-Agent' => 'SitePortrait-Laravel/'.$this->sitePortrait->version().'; '.$this->sitePortrait->origin(),
        ];
        $payload = null;
        if ($body !== null) {
            $payload = (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $headers['Content-Type'] = 'application/json';
            $headers['Content-Digest'] = Crypto::contentDigest($payload);
        }
        if ($signer !== null) {
            $headers += HttpSignature::signRequest($method, $url, array_change_key_case($headers, CASE_LOWER), $signer['secret'], $signer['kid']);
        }

        // No 'stream' option: Guzzle would switch to its stream handler and
        // ignore the cURL options below (address pinning). The size is capped
        // from the headers and while downloading instead.
        $options = [
            'on_headers' => function (ResponseInterface $response) use ($maxSize) {
                $length = $response->getHeaderLine('Content-Length');
                if ($length !== '' && ctype_digit($length) && (int) $length > $maxSize) {
                    throw new PairingException('response_too_large', 'The service response is too large.');
                }
            },
            'progress' => function (int|float $downloadTotal, int|float $downloaded) use ($maxSize) {
                if ($downloaded > $maxSize) {
                    throw new PairingException('response_too_large', 'The service response is too large.');
                }
            },
        ];
        if (! $this->sitePortrait->isDevMode()) {
            $options['curl'] = [CURLOPT_RESOLVE => [$this->pinnedAddress($url)]];
        }

        $pending = $this->http->withHeaders($headers)
            ->withoutRedirecting()
            ->timeout($timeout ?? (int) config('site-portrait.http_timeout', 15))
            ->withOptions($options);
        if ($payload !== null) {
            $pending = $pending->withBody($payload, 'application/json');
        }

        try {
            $response = $pending->send($method, $url);
        } catch (PairingException $e) {
            throw $e;
        } catch (\Throwable $e) {
            // Size limits raised in Guzzle callbacks come back wrapped.
            for ($previous = $e->getPrevious(); $previous !== null; $previous = $previous->getPrevious()) {
                if ($previous instanceof PairingException) {
                    throw $previous;
                }
            }
            if (! $e instanceof ConnectionException && ! $e instanceof TransferException) {
                throw $e;
            }
            throw new PairingException('http_error', 'Could not reach the service: '.$e->getMessage());
        }

        $content = $response->body();
        if (strlen($content) > $maxSize) {
            throw new PairingException('response_too_large', 'The service response is too large.');
        }

        $responseHeaders = [];
        foreach ($response->headers() as $name => $values) {
            $responseHeaders[strtolower($name)] = implode(', ', $values);
        }

        return ['status' => $response->status(), 'body' => $content, 'headers' => $responseHeaders];
    }

    /**
     * Builds an exception from an OAuth-style error response.
     *
     * @param  array{status: int, body: string}  $response
     */
    public static function errorFromResponse(array $response, string $context): PairingException
    {
        $data = json_decode($response['body'], true);
        $detail = '';
        if (is_array($data) && isset($data['error']) && is_string($data['error'])) {
            $detail = self::text($data['error'], 64);
            if (isset($data['error_description']) && is_string($data['error_description'])) {
                $detail .= ': '.self::text($data['error_description'], 300);
            }
        }

        return new PairingException('service_error', trim(sprintf('%s failed (HTTP %d). %s', $context, $response['status'], $detail)));
    }

    /** Normalises untrusted plain text from the service. */
    public static function text(string $text, int $length): string
    {
        $text = strip_tags($text);
        $text = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $text);
        $text = trim((string) preg_replace('/\s+/u', ' ', $text));

        return mb_substr($text, 0, $length);
    }

    /**
     * Resolves the host once, rejects private and reserved addresses, and
     * returns a CURLOPT_RESOLVE entry pinning the checked address (no DNS rebinding).
     */
    protected function pinnedAddress(string $url): string
    {
        $parts = parse_url($url) ?: [];
        $host = (string) ($parts['host'] ?? '');
        $port = (int) ($parts['port'] ?? (strtolower((string) ($parts['scheme'] ?? 'https')) === 'http' ? 80 : 443));

        $ips = $this->resolver->resolve($host);
        if ($ips === []) {
            throw new PairingException('http_error', 'Could not resolve the service host name.');
        }
        foreach ($ips as $ip) {
            if (! HostResolver::isPublic($ip)) {
                throw new PairingException('invalid_service_url', 'The service host resolves to a private or reserved address.');
            }
        }
        $ip = str_contains($ips[0], ':') ? '['.$ips[0].']' : $ips[0];

        return trim($host, '[]').':'.$port.':'.$ip;
    }
}
