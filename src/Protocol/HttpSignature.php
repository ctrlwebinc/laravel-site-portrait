<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * RFC 9421 HTTP Message Signatures with Ed25519, restricted to the profile
 * defined in PROTOCOL.md §5. Free of Laravel dependencies.
 */
final class HttpSignature
{
    public const LABEL = 'sp';

    public const TAG = 'site-portrait/1';

    public const ALG = 'ed25519';

    public const MAX_SKEW = 300;

    public const MAX_TTL = 300;

    public const NONCE_RE = '/^[A-Za-z0-9_-]{16,64}$/';

    public const GET_LIST = ['@method', '@authority', '@path', '@query'];

    public const POST_LIST = ['@method', '@authority', '@path', '@query', 'content-type', 'content-digest'];

    public const RESP_LIST = ['@status', 'content-type', 'content-digest'];

    /**
     * Signs an outgoing request.
     *
     * @param  array<string, string>  $headers  Lower-case name => value; must contain
     *                                          content-type and content-digest when a body is sent.
     * @return array{Signature-Input: string, Signature: string}
     */
    public static function signRequest(string $method, string $url, array $headers, string $secretKey, string $kid, ?int $now = null, ?string $nonce = null): array
    {
        $now ??= time();
        $method = strtoupper($method);
        $context = self::requestContextFromUrl($method, $url, $headers);
        $list = self::hasBody($method) ? self::POST_LIST : self::GET_LIST;

        $params = [
            'created' => ['type' => 'integer', 'value' => $now],
            'expires' => ['type' => 'integer', 'value' => $now + self::MAX_TTL],
            'nonce' => ['type' => 'string', 'value' => $nonce ?? Crypto::randomToken(24)],
            'keyid' => ['type' => 'string', 'value' => $kid],
            'alg' => ['type' => 'string', 'value' => self::ALG],
            'tag' => ['type' => 'string', 'value' => self::TAG],
        ];

        $items = array_map(static fn (string $c) => StructuredFields::stringItem($c), $list);

        return self::signItems($items, $params, $context, null, $secretKey);
    }

    /**
     * Signs a response, optionally bound to the request signature (§5.2).
     *
     * @return array{Signature-Input: string, Signature: string}
     */
    public static function signResponse(int $status, string $contentType, string $contentDigest, ?string $requestSignature, string $secretKey, string $kid, ?int $now = null): array
    {
        $now ??= time();
        $context = [
            '@status' => (string) $status,
            'headers' => ['content-type' => $contentType, 'content-digest' => $contentDigest],
        ];
        $items = array_map(static fn (string $c) => StructuredFields::stringItem($c), self::RESP_LIST);

        $requestContext = null;
        if ($requestSignature !== null) {
            $items[] = self::requestBindingItem();
            $requestContext = ['signature' => [self::LABEL => $requestSignature]];
        }

        $params = [
            'created' => ['type' => 'integer', 'value' => $now],
            'keyid' => ['type' => 'string', 'value' => $kid],
            'alg' => ['type' => 'string', 'value' => self::ALG],
            'tag' => ['type' => 'string', 'value' => self::TAG],
        ];

        return self::signItems($items, $params, $context, $requestContext, $secretKey);
    }

    /**
     * Verifies an incoming request (§5.1, §5.3 steps 1–4 and 6; the digest and
     * the nonce are checked by the caller).
     *
     * @param  array{method: string, authority: string, path: string, query: string, headers: array<string, string>}  $request
     * @param  callable(string): ?string  $keyLookup  Key id => raw public key, or null.
     * @return array{kid: string, nonce: string, created: int, expires: int, signature: string}
     *
     * @throws SignatureException
     */
    public static function verifyRequest(array $request, callable $keyLookup, ?int $now = null): array
    {
        $now ??= time();
        $headers = $request['headers'];
        $method = strtoupper($request['method']);

        if (! isset($headers['signature-input'], $headers['signature'])) {
            throw new SignatureException('site_portrait_signature_missing', 'The request is not signed.');
        }

        $inputs = StructuredFields::parseDictionary($headers['signature-input']);
        $signatures = StructuredFields::parseDictionary($headers['signature']);
        if ($inputs === null || $signatures === null) {
            throw new SignatureException('site_portrait_signature_malformed', 'The signature fields cannot be parsed.');
        }
        if (! isset($inputs[self::LABEL], $signatures[self::LABEL])) {
            throw new SignatureException('site_portrait_signature_missing', 'No signature labelled "sp".');
        }

        $input = $inputs[self::LABEL];
        $signature = $signatures[self::LABEL];
        if ($input['type'] !== 'inner_list' || $signature['type'] !== 'bytes') {
            throw new SignatureException('site_portrait_signature_malformed', 'Unexpected signature field types.');
        }

        $covered = [];
        foreach ($input['value'] as $item) {
            if ($item['type'] !== 'string' || ! empty($item['params'])) {
                throw new SignatureException('site_portrait_signature_malformed', 'Unexpected covered component.');
            }
            $covered[] = $item['value'];
        }
        $expected = self::hasBody($method) ? self::POST_LIST : self::GET_LIST;
        if ($covered !== $expected) {
            throw new SignatureException('site_portrait_signature_malformed', 'Covered components must be: '.implode(' ', $expected).'.');
        }

        $params = $input['params'];
        foreach (['created' => 'integer', 'expires' => 'integer', 'nonce' => 'string', 'keyid' => 'string', 'alg' => 'string', 'tag' => 'string'] as $name => $type) {
            if (! isset($params[$name]) || $params[$name]['type'] !== $type) {
                throw new SignatureException('site_portrait_signature_malformed', sprintf('Signature parameter "%s" is missing or invalid.', $name));
            }
        }
        if ($params['alg']['value'] !== self::ALG || $params['tag']['value'] !== self::TAG) {
            throw new SignatureException('site_portrait_signature_malformed', 'Unsupported alg or tag.');
        }
        if (! preg_match(self::NONCE_RE, $params['nonce']['value'])) {
            throw new SignatureException('site_portrait_signature_malformed', 'Invalid nonce.');
        }

        $created = $params['created']['value'];
        $expires = $params['expires']['value'];
        if (abs($now - $created) > self::MAX_SKEW || $expires <= $created || $expires > $created + self::MAX_TTL || $now >= $expires) {
            throw new SignatureException('site_portrait_signature_expired', 'The signature is outside its validity window.');
        }

        $kid = $params['keyid']['value'];
        $publicKey = $keyLookup($kid);
        if ($publicKey === null) {
            throw new SignatureException('site_portrait_unknown_key', 'Unknown key id.');
        }

        $context = [
            '@method' => $method,
            '@authority' => $request['authority'],
            '@path' => $request['path'],
            '@query' => $request['query'],
            'headers' => $headers,
        ];
        $base = self::signatureBase($input['value'], $params, $context, null);
        if ($base === null || ! Crypto::verify($signature['value'], $base, $publicKey)) {
            throw new SignatureException('site_portrait_signature_invalid', 'Signature verification failed.');
        }

        return [
            'kid' => $kid,
            'nonce' => $params['nonce']['value'],
            'created' => $created,
            'expires' => $expires,
            'signature' => $signature['value'],
        ];
    }

    /**
     * Verifies a response signature (used by clients and tests).
     *
     * @param  array<string, string>  $headers  Lower-case name => value.
     * @param  callable(string): ?string  $keyLookup
     * @return string Key id that signed the response.
     *
     * @throws SignatureException
     */
    public static function verifyResponse(int $status, array $headers, string $body, ?string $requestSignature, callable $keyLookup): string
    {
        $inputs = StructuredFields::parseDictionary($headers['signature-input'] ?? '');
        $signatures = StructuredFields::parseDictionary($headers['signature'] ?? '');
        if (empty($inputs[self::LABEL]) || empty($signatures[self::LABEL])
            || $signatures[self::LABEL]['type'] !== 'bytes' || $inputs[self::LABEL]['type'] !== 'inner_list') {
            throw new SignatureException('site_portrait_signature_missing', 'The response is not signed.');
        }

        $input = $inputs[self::LABEL];
        $unbound = array_map(static fn (string $c) => StructuredFields::stringItem($c), self::RESP_LIST);
        $bound = [...$unbound, self::requestBindingItem()];
        if ($requestSignature === null) {
            $allowed = [$unbound];
        } elseif ($status >= 200 && $status < 300) {
            $allowed = [$bound];
        } else {
            $allowed = [$bound, $unbound];
        }
        if (! in_array($input['value'], $allowed, true)) {
            throw new SignatureException('site_portrait_signature_malformed', 'Unexpected covered components in response.');
        }
        if ($input['value'] === $unbound) {
            $requestSignature = null;
        }
        if (! hash_equals(Crypto::contentDigest($body), trim($headers['content-digest'] ?? ''))) {
            throw new SignatureException('site_portrait_digest_mismatch', 'Content-Digest does not match the body.', 400);
        }
        $kid = $input['params']['keyid']['value'] ?? null;
        $key = is_string($kid) ? $keyLookup($kid) : null;
        if ($key === null) {
            throw new SignatureException('site_portrait_unknown_key', 'Unknown response key id.');
        }
        $context = ['@status' => (string) $status, 'headers' => $headers];
        $requestContext = $requestSignature === null ? null : ['signature' => [self::LABEL => $requestSignature]];
        $base = self::signatureBase($input['value'], $input['params'], $context, $requestContext);
        if ($base === null || ! Crypto::verify($signatures[self::LABEL]['value'], $base, $key)) {
            throw new SignatureException('site_portrait_signature_invalid', 'Response signature verification failed.');
        }

        return $kid;
    }

    /**
     * @param  array<string, string>  $headers
     * @return array{'@method': string, '@authority': string, '@path': string, '@query': string, headers: array<string, string>}
     */
    public static function requestContextFromUrl(string $method, string $url, array $headers): array
    {
        $parts = parse_url($url) ?: [];

        return [
            '@method' => strtoupper($method),
            '@authority' => self::authority($parts['scheme'] ?? 'https', $parts['host'] ?? '', $parts['port'] ?? null),
            '@path' => isset($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/',
            '@query' => '?'.($parts['query'] ?? ''),
            'headers' => $headers,
        ];
    }

    /** Lower-case host, plus the port only when not the scheme default. */
    public static function authority(string $scheme, string $host, ?int $port = null): string
    {
        $authority = strtolower($host);
        $default = strtolower($scheme) === 'http' ? 80 : 443;
        if ($port !== null && $port !== $default) {
            $authority .= ':'.$port;
        }

        return $authority;
    }

    /** Origin (scheme://authority) of a URL, or null. */
    public static function origin(string $url): ?string
    {
        $parts = parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme']);

        return $scheme.'://'.self::authority($scheme, $parts['host'], $parts['port'] ?? null);
    }

    /**
     * RFC 9421 signature base, or null when a component is missing.
     *
     * @param  list<array<string, mixed>>  $items
     * @param  array<string, array{type: string, value: mixed}>  $params
     * @param  array<string, mixed>  $context
     * @param  array<string, mixed>|null  $requestContext
     */
    public static function signatureBase(array $items, array $params, array $context, ?array $requestContext): ?string
    {
        $lines = [];
        $seen = [];
        foreach ($items as $item) {
            $identifier = StructuredFields::serializeBare('string', $item['value']).StructuredFields::serializeParams($item['params'] ?? []);
            if (isset($seen[$identifier])) {
                return null;
            }
            $seen[$identifier] = true;

            $name = strtolower($item['value']);
            if (isset($item['params']['req'])) {
                // Only "signature";req;key="<label>" is supported (§5.2).
                $label = $item['params']['key']['value'] ?? null;
                if ($name !== 'signature' || $requestContext === null || ! isset($requestContext['signature'][$label])) {
                    return null;
                }
                $value = StructuredFields::serializeBare('bytes', $requestContext['signature'][$label]);
            } elseif (str_starts_with($name, '@')) {
                if (! isset($context[$name])) {
                    return null;
                }
                $value = $context[$name];
            } else {
                if (! isset($context['headers'][$name])) {
                    return null;
                }
                $value = trim($context['headers'][$name]);
            }
            $lines[] = $identifier.': '.$value;
        }
        $lines[] = '"@signature-params": '.StructuredFields::serializeInnerList($items, $params);

        return implode("\n", $lines);
    }

    /**
     * @return array{type: string, value: string, params: array<string, array{type: string, value: mixed}>}
     */
    private static function requestBindingItem(): array
    {
        return StructuredFields::stringItem('signature', [
            'req' => ['type' => 'boolean', 'value' => true],
            'key' => ['type' => 'string', 'value' => self::LABEL],
        ]);
    }

    private static function hasBody(string $method): bool
    {
        return ! in_array(strtoupper($method), ['GET', 'HEAD'], true);
    }

    /**
     * @param  list<array<string, mixed>>  $items
     * @param  array<string, array{type: string, value: mixed}>  $params
     * @param  array<string, mixed>  $context
     * @param  array<string, mixed>|null  $requestContext
     * @return array{Signature-Input: string, Signature: string}
     */
    private static function signItems(array $items, array $params, array $context, ?array $requestContext, string $secretKey): array
    {
        $base = self::signatureBase($items, $params, $context, $requestContext);
        if ($base === null) {
            throw new \InvalidArgumentException('A covered component is missing from the message.');
        }

        return [
            'Signature-Input' => self::LABEL.'='.StructuredFields::serializeInnerList($items, $params),
            'Signature' => self::LABEL.'='.StructuredFields::serializeBare('bytes', Crypto::sign($base, $secretKey)),
        ];
    }
}
