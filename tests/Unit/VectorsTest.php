<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Unit;

use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\Protocol\StructuredFields;
use PHPUnit\Framework\TestCase;

/**
 * Test vectors of the specification (PROTOCOL.md §15, docs/test-vectors.json).
 */
final class VectorsTest extends TestCase
{
    /** @var array<string, mixed> */
    private static array $v;

    public static function setUpBeforeClass(): void
    {
        self::$v = json_decode((string) file_get_contents(__DIR__.'/../fixtures/test-vectors.json'), true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * @return array{public: string, secret: string}
     */
    private static function key(string $name): array
    {
        return Crypto::keypairFromSeed((string) hex2bin(self::$v['keys'][$name]['seed_hex']));
    }

    public function test_keys_and_thumbprints(): void
    {
        foreach (['service', 'site', 'new'] as $name) {
            $key = self::key($name);
            $this->assertSame(self::$v['keys'][$name]['x'], Crypto::b64urlEncode($key['public']), $name);
            $this->assertSame(self::$v['keys'][$name]['kid'], Crypto::thumbprint($key['public']), $name);
        }
    }

    public function test_pkce(): void
    {
        $this->assertSame(self::$v['pkce']['code_challenge'], Crypto::pkceChallenge(self::$v['pkce']['code_verifier']));
    }

    public function test_request_is_signed_identically(): void
    {
        $r = self::$v['request'];
        $headers = HttpSignature::signRequest($r['method'], $r['url'], [], self::key($r['key'])['secret'], self::$v['keys'][$r['key']]['kid'], $r['created'], $r['nonce']);
        $this->assertSame($r['headers']['Signature-Input'], $headers['Signature-Input']);
        $this->assertSame($r['headers']['Signature'], $headers['Signature']);
    }

    public function test_request_vector_verifies(): void
    {
        $r = self::$v['request'];
        $service = self::key($r['key']);
        $result = HttpSignature::verifyRequest(
            [
                'method' => $r['method'],
                'authority' => $r['authority'],
                'path' => $r['path'],
                'query' => $r['query'],
                'headers' => ['signature-input' => $r['headers']['Signature-Input'], 'signature' => $r['headers']['Signature']],
            ],
            fn (string $kid) => $kid === self::$v['keys'][$r['key']]['kid'] ? $service['public'] : null,
            $r['verify_at'],
        );
        $this->assertSame(self::$v['keys'][$r['key']]['kid'], $result['kid']);
        $this->assertSame($r['nonce'], $result['nonce']);
    }

    public function test_signature_base(): void
    {
        $r = self::$v['request'];
        $input = StructuredFields::parseDictionary($r['headers']['Signature-Input'])['sp'];
        $base = HttpSignature::signatureBase($input['value'], $input['params'], [
            '@method' => $r['method'], '@authority' => $r['authority'], '@path' => $r['path'], '@query' => $r['query'], 'headers' => [],
        ], null);
        $this->assertSame($r['signature_base'], $base);
    }

    public function test_response_is_signed_identically(): void
    {
        $resp = self::$v['response'];
        $requestSignature = StructuredFields::parseDictionary(self::$v['request']['headers']['Signature'])['sp']['value'];
        $digest = Crypto::contentDigest($resp['body']);
        $this->assertSame($resp['headers']['Content-Digest'], $digest);

        $headers = HttpSignature::signResponse($resp['status'], $resp['content_type'], $digest, $requestSignature, self::key($resp['key'])['secret'], self::$v['keys'][$resp['key']]['kid'], $resp['created']);
        $this->assertSame($resp['headers']['Signature-Input'], $headers['Signature-Input']);
        $this->assertSame($resp['headers']['Signature'], $headers['Signature']);

        $kid = HttpSignature::verifyResponse(
            $resp['status'],
            ['content-type' => $resp['content_type'], 'content-digest' => $digest, 'signature-input' => $headers['Signature-Input'], 'signature' => $headers['Signature']],
            $resp['body'],
            $requestSignature,
            fn (string $k) => $k === self::$v['keys'][$resp['key']]['kid'] ? self::key($resp['key'])['public'] : null,
        );
        $this->assertSame(self::$v['keys'][$resp['key']]['kid'], $kid);
    }

    public function test_endorsement(): void
    {
        $e = self::$v['endorsement'];
        $signer = self::key($e['signer']);
        $new = self::key($e['endorsed']);
        $endorsement = Crypto::endorse(self::$v['keys'][$e['endorsed']]['kid'], $signer['secret'], self::$v['keys'][$e['signer']]['kid']);
        $this->assertSame($e['sig'], $endorsement['sig']);

        $jwk = Crypto::publicJwk($new['public']) + ['endorsements' => [$endorsement]];
        $this->assertTrue(Crypto::isEndorsed($jwk, [self::$v['keys'][$e['signer']]['kid'] => $signer['public']]));
        $this->assertFalse(Crypto::isEndorsed($jwk, ['other' => $signer['public']]));
    }
}
