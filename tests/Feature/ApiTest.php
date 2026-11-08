<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Feature;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Pairing\HostResolver;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Tests\Concerns\ActsAsService;
use Ctrlweb\SitePortrait\Tests\TestCase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

final class ApiTest extends TestCase
{
    use ActsAsService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpService();
    }

    public function test_without_pairing_routes_answer_rest_no_route(): void
    {
        $response = $this->signed('GET', '/site-portrait/v1/status');
        $response->assertStatus(404)->assertJson(['code' => 'rest_no_route']);
        $this->assertFalse($response->headers->has('Signature'));
    }

    public function test_status(): void
    {
        $this->createPairing(['server', 'database']);
        $response = $this->signed('GET', '/site-portrait/v1/status');
        $response->assertOk();
        $data = $this->assertSignedResponse($response);

        $this->assertSame('1', $data['protocol_version']);
        $this->assertSame('c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11', $data['pairing_id']);
        $this->assertSame('single', $data['mode']);
        $this->assertSame('https://site.test', $data['site_url']);
        $this->assertSame(['server', 'database'], $data['scopes_granted']);
        $this->assertContains('laravel', $data['scopes_available']);
        $this->assertSame('laravel', $data['platform']['name']);
        $this->assertSame(60, $data['rate_limit']['limit']);
        $this->assertSame(Crypto::thumbprint(Crypto::keypairFromSeed(str_repeat("\x02", 32))['public']), $data['site_jwks']['keys'][0]['kid']);
        $this->assertNotNull(Pairing::query()->first()->confirmed_at);
    }

    public function test_portrait_with_granted_and_denied_scopes(): void
    {
        $this->createPairing(['server', 'database', 'users_counts']);
        $response = $this->signed('GET', '/site-portrait/v1/portrait?scopes=server,storage');
        $response->assertOk();
        $data = $this->assertSignedResponse($response);

        $this->assertSame(['server'], $data['scopes_returned']);
        $this->assertSame(['storage'], $data['scopes_denied']);
        $this->assertSame(['server'], array_keys($data['data']));
        $this->assertSame(PHP_VERSION, $data['data']['server']['php']['version']);
    }

    public function test_portrait_defaults_to_granted_scopes(): void
    {
        $this->createPairing(['server', 'users_counts']);
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/portrait')->assertOk());
        $this->assertSame(['server', 'users_counts'], $data['scopes_returned']);
    }

    public function test_portrait_scope_errors(): void
    {
        $this->createPairing(['server']);

        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/portrait?scopes=core,plugins')->assertStatus(400));
        $this->assertSame('site_portrait_invalid_scope', $data['code']);
        $this->assertSame(['status' => 400], $data['data']);

        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/portrait?scopes=database')->assertStatus(403));
        $this->assertSame('site_portrait_scope_denied', $data['code']);

        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/portrait?site_id=2')->assertStatus(400));
        $this->assertSame('site_portrait_invalid_param', $data['code']);
    }

    public function test_unsigned_request_gets_a_signed_unbound_error(): void
    {
        $this->createPairing();
        $response = $this->call('GET', self::SITE_URL.'/site-portrait/v1/status');
        $response->assertStatus(401);
        $data = $this->assertSignedResponse($response, bound: false);
        $this->assertSame('site_portrait_signature_missing', $data['code']);
    }

    public function test_replay_is_rejected(): void
    {
        $this->createPairing();
        $this->signed('GET', '/site-portrait/v1/status', nonce: 'the-same-nonce-0123456789')->assertOk();
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status', nonce: 'the-same-nonce-0123456789')->assertStatus(401), bound: false);
        $this->assertSame('site_portrait_replay', $data['code']);
    }

    public function test_expired_signature(): void
    {
        $this->createPairing();
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status', now: Carbon::now()->getTimestamp() - 400)->assertStatus(401), bound: false);
        $this->assertSame('site_portrait_signature_expired', $data['code']);
    }

    public function test_unknown_key(): void
    {
        $this->createPairing();
        $other = Crypto::keypairFromSeed(str_repeat("\x09", 32));
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status', secret: $other['secret'], kid: Crypto::thumbprint($other['public']))->assertStatus(401), bound: false);
        $this->assertSame('site_portrait_unknown_key', $data['code']);
    }

    public function test_wrong_authority(): void
    {
        $this->createPairing();
        config(['site-portrait.site_url' => 'https://other.test']);
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status')->assertStatus(401), bound: false);
        $this->assertSame('site_portrait_signature_invalid', $data['code']);
    }

    public function test_https_required(): void
    {
        $this->createPairing();
        $response = $this->flushHeaders()->call('GET', 'http://site.test/site-portrait/v1/status');
        $data = $this->assertSignedResponse($response->assertStatus(403), bound: false);
        $this->assertSame('site_portrait_https_required', $data['code']);
    }

    public function test_ip_allowlist(): void
    {
        $this->createPairing();
        config(['site-portrait.ip_allowlist' => ['192.0.2.0/24']]);
        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status', server: ['REMOTE_ADDR' => '198.51.100.1'])->assertStatus(403), bound: false);
        $this->assertSame('site_portrait_ip_not_allowed', $data['code']);

        $this->signed('GET', '/site-portrait/v1/status', server: ['REMOTE_ADDR' => '192.0.2.10'])->assertOk();
    }

    public function test_rate_limit(): void
    {
        $this->createPairing();
        config(['site-portrait.rate_limit' => 2]);
        $this->signed('GET', '/site-portrait/v1/status')->assertOk();
        $this->signed('GET', '/site-portrait/v1/status')->assertOk();
        $response = $this->signed('GET', '/site-portrait/v1/status')->assertStatus(429);
        $this->assertSame('site_portrait_rate_limited', $this->assertSignedResponse($response, bound: false)['code']);
        $this->assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
    }

    public function test_failure_limit_per_ip_never_blocks_valid_requests(): void
    {
        $this->createPairing();
        config(['site-portrait.failure_limit' => 2]);
        for ($i = 0; $i < 2; $i++) {
            $this->flushHeaders()->call('GET', self::SITE_URL.'/site-portrait/v1/status')->assertStatus(401);
        }
        $this->flushHeaders()->call('GET', self::SITE_URL.'/site-portrait/v1/status')->assertStatus(429);
        $this->signed('GET', '/site-portrait/v1/status')->assertOk();
    }

    public function test_service_revocation(): void
    {
        $this->createPairing();
        $response = $this->signed('POST', '/site-portrait/v1/revoke', ['pairing_id' => 'c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11', 'reason' => 'account_closed']);
        $response->assertOk();
        $this->assertSame(['revoked' => true], $this->assertSignedResponse($response));
        $this->assertSame(0, Pairing::query()->count());

        $this->signed('GET', '/site-portrait/v1/status')->assertStatus(404)->assertJson(['code' => 'rest_no_route']);
    }

    public function test_revocation_errors(): void
    {
        $this->createPairing();
        $data = $this->assertSignedResponse($this->signed('POST', '/site-portrait/v1/revoke', ['pairing_id' => 'nope'])->assertStatus(409));
        $this->assertSame('site_portrait_pairing_mismatch', $data['code']);

        $data = $this->assertSignedResponse($this->signed('POST', '/site-portrait/v1/revoke', ['pairing_id' => 'x'], ['Content-Digest' => Crypto::contentDigest('other')])->assertStatus(400), bound: false);
        $this->assertSame('site_portrait_digest_mismatch', $data['code']);
        $this->assertSame(1, Pairing::query()->count());
    }

    public function test_site_key_rotation_keeps_old_key_published(): void
    {
        $this->createPairing();
        $old = Pairing::query()->first()->site_key_kid;
        $pairing = app(PairingManager::class)->rotateSiteKey();

        $data = $this->assertSignedResponse($this->signed('GET', '/site-portrait/v1/status')->assertOk());
        $kids = array_column($data['site_jwks']['keys'], 'kid');
        $this->assertSame([$pairing->site_key_kid, $old], $kids);

        // The new key is endorsed by the old one.
        $oldPublic = Crypto::keypairFromSeed(str_repeat("\x02", 32))['public'];
        $this->assertTrue(Crypto::isEndorsed($data['site_jwks']['keys'][0], [$old => $oldPublic]));
    }

    public function test_service_key_rotation_through_discovery(): void
    {
        $this->createPairing();
        Pairing::query()->update(['keys_refreshed_at' => Carbon::now()->subHours(2)]);
        $new = Crypto::keypairFromSeed(str_repeat("\x03", 32));
        $newJwk = Crypto::publicJwk($new['public']) + ['endorsements' => [Crypto::endorse(Crypto::thumbprint($new['public']), $this->serviceKey['secret'], $this->serviceKid)]];
        $this->fakeService(['jwks' => ['keys' => [Crypto::publicJwk($this->serviceKey['public']), $newJwk]]]);

        $this->signed('GET', '/site-portrait/v1/status', secret: $new['secret'], kid: $newJwk['kid'])->assertOk();
        $this->assertArrayHasKey($newJwk['kid'], Pairing::query()->first()->service_keys);
    }

    public function test_access_log(): void
    {
        $this->createPairing(['server']);
        $this->signed('GET', '/site-portrait/v1/portrait?scopes=server')->assertOk();
        $entry = AccessLogEntry::query()->latest('id')->first();
        $this->assertSame('/portrait', $entry->endpoint);
        $this->assertSame(['server'], $entry->scopes);
        $this->assertTrue($entry->authenticated);
        $this->assertSame($this->serviceKid, $entry->key_id);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function fakeService(array $overrides = []): void
    {
        $this->app->instance(HostResolver::class, new class extends HostResolver
        {
            public function resolve(string $host): array
            {
                return ['93.184.215.14'];
            }
        });
        Http::fake([
            'https://service.example/.well-known/site-portrait' => Http::response(array_merge(DiscoveryDocument::make($this->serviceKey['public']), $overrides)),
        ]);
    }
}
