<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Concerns;

use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\Protocol\StructuredFields;
use Illuminate\Support\Carbon;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * Plays the service: holds the test service key (seed 0x01), creates an
 * active pairing and sends signed requests.
 */
trait ActsAsService
{
    /** @var array{public: string, secret: string} */
    protected array $serviceKey;

    protected string $serviceKid;

    protected ?string $lastRequestSignature = null;

    protected function setUpService(): void
    {
        $this->serviceKey = Crypto::keypairFromSeed(str_repeat("\x01", 32));
        $this->serviceKid = Crypto::thumbprint($this->serviceKey['public']);
    }

    /**
     * @param  list<string>  $scopes
     */
    protected function createPairing(array $scopes = ['laravel', 'packages', 'server', 'database', 'storage', 'users_counts']): Pairing
    {
        $site = Crypto::keypairFromSeed(str_repeat("\x02", 32));

        return Pairing::query()->create([
            'status' => Pairing::ACTIVE,
            'pairing_id' => 'c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11',
            'service' => [
                'origin' => 'https://service.example',
                'name' => 'Example service',
                'privacy_policy_url' => 'https://service.example/privacy',
                'authorization_endpoint' => 'https://service.example/site-portrait/authorize',
                'token_endpoint' => 'https://service.example/site-portrait/token',
                'revocation_endpoint' => 'https://service.example/site-portrait/revoke',
                'scopes_supported' => ['laravel', 'packages', 'server', 'database', 'storage', 'users_counts'],
            ],
            'service_keys' => [$this->serviceKid => Crypto::b64urlEncode($this->serviceKey['public'])],
            'scopes' => $scopes,
            'site_key_kid' => Crypto::thumbprint($site['public']),
            'site_key_public' => Crypto::b64urlEncode($site['public']),
            'site_key_secret' => Crypto::b64urlEncode($site['secret']),
            'site_key_endorsements' => [],
            'previous_site_keys' => [],
            'connected_at' => Carbon::now(),
            'keys_refreshed_at' => Carbon::now(),
        ]);
    }

    /**
     * Sends a request signed with the service key.
     *
     * @param  array<string, mixed>|null  $body
     * @param  array<string, string>  $extraHeaders
     * @param  array<string, mixed>  $server
     */
    protected function signed(string $method, string $path, ?array $body = null, array $extraHeaders = [], ?string $secret = null, ?string $kid = null, ?int $now = null, array $server = [], ?string $nonce = null): TestResponse
    {
        $url = self::SITE_URL.$path;
        // Sign the request target exactly as it will be received.
        $target = SymfonyRequest::create($url, $method)->server->get('REQUEST_URI');
        $headers = [];
        $content = null;
        if ($body !== null) {
            $content = (string) json_encode($body, JSON_UNESCAPED_SLASHES);
            $headers['content-type'] = 'application/json';
            $headers['content-digest'] = Crypto::contentDigest($content);
        }
        $signature = HttpSignature::signRequest(
            $method,
            self::SITE_URL.$target,
            $headers,
            $secret ?? $this->serviceKey['secret'],
            $kid ?? $this->serviceKid,
            $now ?? Carbon::now()->getTimestamp(),
            $nonce,
        );
        $this->lastRequestSignature = StructuredFields::parseDictionary($signature['Signature'])['sp']['value'] ?? null;

        $all = array_merge(
            ['Content-Type' => $headers['content-type'] ?? null, 'Content-Digest' => $headers['content-digest'] ?? null],
            $signature,
            $extraHeaders,
        );

        // call() ignores withHeaders(): headers go in as server variables.
        $server = array_merge($this->transformHeadersToServerVars(array_filter($all, fn ($v) => $v !== null)), $server);
        $response = $this->flushHeaders()->call($method, $url, [], [], [], $server, $content);
        if (getenv('SP_DEBUG')) {
            fwrite(STDERR, $target.' => '.$response->getContent().PHP_EOL);
        }

        return $response;
    }

    /**
     * Verifies the response signature with the site key; returns the decoded body.
     *
     * @return array<string, mixed>
     */
    protected function assertSignedResponse(TestResponse $response, bool $bound = true): array
    {
        $headers = [];
        foreach ($response->headers->all() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }
        $this->assertSame('application/json; charset=UTF-8', $headers['content-type'] ?? null);
        $this->assertSame('1', $headers['site-portrait-protocol'] ?? null);
        $this->assertStringContainsString('no-store', $headers['cache-control'] ?? '');

        $pairing = Pairing::query()->withoutGlobalScopes()->first();
        $siteKeys = [];
        $site = Crypto::keypairFromSeed(str_repeat("\x02", 32));
        $siteKeys[Crypto::thumbprint($site['public'])] = $site['public'];
        if ($pairing !== null) {
            $siteKeys[$pairing->site_key_kid] = $pairing->sitePublicKey();
        }

        $kid = HttpSignature::verifyResponse(
            $response->getStatusCode(),
            $headers,
            (string) $response->getContent(),
            $bound ? $this->lastRequestSignature : null,
            fn (string $kid) => $siteKeys[$kid] ?? null,
        );
        $this->assertNotEmpty($kid);

        return json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
    }
}
