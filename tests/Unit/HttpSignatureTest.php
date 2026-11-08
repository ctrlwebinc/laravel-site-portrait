<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Unit;

use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\Protocol\SignatureException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HttpSignatureTest extends TestCase
{
    private const NOW = 1792400000;

    /** @var array{public: string, secret: string} */
    private array $key;

    private string $kid;

    protected function setUp(): void
    {
        $this->key = Crypto::keypairFromSeed(str_repeat("\x01", 32));
        $this->kid = Crypto::thumbprint($this->key['public']);
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     */
    private function request(string $method, string $url, array $headers = [], ?int $signedAt = null): array
    {
        $signature = HttpSignature::signRequest($method, $url, $headers, $this->key['secret'], $this->kid, $signedAt ?? self::NOW);
        $parts = parse_url($url);

        return [
            'method' => $method,
            'authority' => $parts['host'],
            'path' => $parts['path'],
            'query' => '?'.($parts['query'] ?? ''),
            'headers' => $headers + ['signature-input' => $signature['Signature-Input'], 'signature' => $signature['Signature']],
        ];
    }

    private function verify(array $request, int $now = self::NOW): array
    {
        return HttpSignature::verifyRequest($request, fn (string $kid) => $kid === $this->kid ? $this->key['public'] : null, $now);
    }

    public function test_get_round_trip(): void
    {
        $result = $this->verify($this->request('GET', 'https://site.test/site-portrait/v1/portrait?scopes=server,database'));
        $this->assertSame($this->kid, $result['kid']);
        $this->assertSame(self::NOW + 300, $result['expires']);
    }

    public function test_post_round_trip_covers_body_headers(): void
    {
        $body = '{"pairing_id":"x"}';
        $request = $this->request('POST', 'https://site.test/site-portrait/v1/revoke', [
            'content-type' => 'application/json',
            'content-digest' => Crypto::contentDigest($body),
        ]);
        $this->assertSame($this->kid, $this->verify($request)['kid']);

        $request['headers']['content-type'] = 'text/plain';
        $this->assertSignatureError('site_portrait_signature_invalid', $request);
    }

    /**
     * @return iterable<string, array{0: string, 1: callable(array<string, mixed>): array<string, mixed>}>
     */
    public static function tampered(): iterable
    {
        yield 'other path' => ['site_portrait_signature_invalid', fn ($r) => ['path' => '/other'] + $r];
        yield 'other query' => ['site_portrait_signature_invalid', fn ($r) => ['query' => '?scopes=server'] + $r];
        yield 'other authority' => ['site_portrait_signature_invalid', fn ($r) => ['authority' => 'evil.test'] + $r];
        yield 'other method' => ['site_portrait_signature_malformed', fn ($r) => ['method' => 'POST'] + $r];
        yield 'missing' => ['site_portrait_signature_missing', fn ($r) => ['headers' => []] + $r];
        yield 'garbage' => ['site_portrait_signature_malformed', fn ($r) => ['headers' => ['signature-input' => 'sp=(', 'signature' => 'sp=:x:']] + $r];
        yield 'other label' => ['site_portrait_signature_missing', fn ($r) => ['headers' => [
            'signature-input' => str_replace('sp=', 'xx=', $r['headers']['signature-input']),
            'signature' => str_replace('sp=', 'xx=', $r['headers']['signature']),
        ]] + $r];
        yield 'wrong tag' => ['site_portrait_signature_malformed', fn ($r) => ['headers' => [
            'signature-input' => str_replace('site-portrait/1', 'site-portrait/2', $r['headers']['signature-input']),
        ] + $r['headers']] + $r];
    }

    /**
     * @param  callable(array<string, mixed>): array<string, mixed>  $tamper
     */
    #[DataProvider('tampered')]
    public function test_tampered_requests_are_rejected(string $code, callable $tamper): void
    {
        $this->assertSignatureError($code, $tamper($this->request('GET', 'https://site.test/site-portrait/v1/portrait?scopes=server,database')));
    }

    public function test_time_window(): void
    {
        $request = $this->request('GET', 'https://site.test/site-portrait/v1/status');
        $this->verify($request, self::NOW + 299);
        $this->assertSignatureError('site_portrait_signature_expired', $request, self::NOW + 300);
        $this->assertSignatureError('site_portrait_signature_expired', $request, self::NOW - 301);
    }

    public function test_unknown_key(): void
    {
        $request = $this->request('GET', 'https://site.test/site-portrait/v1/status');
        $this->expectException(SignatureException::class);
        try {
            HttpSignature::verifyRequest($request, fn () => null, self::NOW);
        } catch (SignatureException $e) {
            $this->assertSame('site_portrait_unknown_key', $e->errorCode);
            throw $e;
        }
    }

    public function test_unbound_response_is_rejected_for_2xx_of_signed_request(): void
    {
        $site = Crypto::keypairFromSeed(str_repeat("\x02", 32));
        $kid = Crypto::thumbprint($site['public']);
        $digest = Crypto::contentDigest('{}');
        $headers = HttpSignature::signResponse(200, 'application/json; charset=UTF-8', $digest, null, $site['secret'], $kid, self::NOW);

        $this->expectException(SignatureException::class);
        HttpSignature::verifyResponse(200, [
            'content-type' => 'application/json; charset=UTF-8',
            'content-digest' => $digest,
            'signature-input' => $headers['Signature-Input'],
            'signature' => $headers['Signature'],
        ], '{}', random_bytes(64), fn () => $site['public']);
    }

    public function test_authority_and_origin(): void
    {
        $this->assertSame('example.com', HttpSignature::authority('https', 'EXAMPLE.com', 443));
        $this->assertSame('example.com:8443', HttpSignature::authority('https', 'example.com', 8443));
        $this->assertSame('127.0.0.1:8787', HttpSignature::authority('http', '127.0.0.1', 8787));
        $this->assertSame('https://example.com', HttpSignature::origin('https://Example.com:443/path?q'));
        $this->assertNull(HttpSignature::origin('not a url'));
    }

    /**
     * @param  array<string, mixed>  $request
     */
    private function assertSignatureError(string $code, array $request, int $now = self::NOW): void
    {
        try {
            $this->verify($request, $now);
            $this->fail('Expected '.$code);
        } catch (SignatureException $e) {
            $this->assertSame($code, $e->errorCode);
        }
    }
}
