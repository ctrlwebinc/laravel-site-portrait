<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Feature;

use Ctrlweb\SitePortrait\Events\PairingCompleted;
use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Pairing\HostResolver;
use Ctrlweb\SitePortrait\Pairing\PairingException;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Pairing\ServiceClient;
use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\Protocol\HttpSignature;
use Ctrlweb\SitePortrait\SitePortrait;
use Ctrlweb\SitePortrait\Tests\Concerns\ActsAsService;
use Ctrlweb\SitePortrait\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\Attributes\DefineEnvironment;

final class PairingTest extends TestCase
{
    use ActsAsService;

    /** @var array<string, mixed>|null */
    private ?array $tokenRequest = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpService();
        $this->app->instance(HostResolver::class, new class extends HostResolver
        {
            public function resolve(string $host): array
            {
                return $host === 'internal.example' ? ['10.0.0.5'] : ['93.184.215.14'];
            }
        });
    }

    /**
     * @param  array<string, mixed>  $discoveryOverrides
     */
    private function fakeService(array $discoveryOverrides = [], ?callable $token = null): void
    {
        Http::fake([
            'https://service.example/.well-known/site-portrait' => Http::response(array_merge(DiscoveryDocument::make($this->serviceKey['public']), $discoveryOverrides)),
            'https://service.example/site-portrait/token' => $token ?? function (Request $request) {
                $this->tokenRequest = json_decode($request->body(), true);
                // Proof of possession: the request is signed with the site key from the body.
                $jwk = $this->tokenRequest['site_jwk'];
                HttpSignature::verifyRequest(
                    [
                        'method' => 'POST',
                        'authority' => 'service.example',
                        'path' => '/site-portrait/token',
                        'query' => '?',
                        'headers' => array_change_key_case(array_map(fn ($v) => implode(', ', $v), $request->headers()), CASE_LOWER),
                    ],
                    fn (string $kid) => $kid === $jwk['kid'] ? Crypto::publicKeyFromJwk($jwk) : null,
                );

                return Http::response([
                    'pairing_id' => 'pairing-123',
                    'scopes' => $this->tokenRequest['scopes'],
                    'jwks' => ['keys' => [Crypto::publicJwk($this->serviceKey['public'])]],
                    'account_hint' => 'Bakery <i>Inc.</i>',
                ]);
            },
            'https://service.example/site-portrait/revoke' => Http::response(['revoked' => true]),
        ]);
    }

    public function test_discovery_is_validated_and_normalised(): void
    {
        $this->fakeService();
        $discovery = app(ServiceClient::class)->discover('service.example');

        $this->assertSame('https://service.example', $discovery['origin']);
        $this->assertSame('Example Hosting', $discovery['name']);
        $this->assertSame('', $discovery['terms_url']);
        // WordPress scopes are ignored; only the Laravel implementation's scopes remain.
        $this->assertSame(['laravel', 'packages', 'server', 'database', 'storage', 'users_counts'], $discovery['scopes_supported']);
        $this->assertSame(['laravel', 'server', 'database'], $discovery['scopes_requested']);
    }

    public function test_discovery_rejections(): void
    {
        $this->fakeService(['token_endpoint' => 'https://elsewhere.example/token']);
        $this->assertPairingError('discovery_invalid', fn () => app(ServiceClient::class)->discover('https://service.example'));

        $this->assertPairingError('invalid_service_url', fn () => app(ServiceClient::class)->discover('http://service.example'));
        $this->assertPairingError('invalid_service_url', fn () => app(ServiceClient::class)->discover('https://internal.example'));
    }

    public function test_service_supporting_only_wordpress_scopes_is_refused(): void
    {
        $this->fakeService(['scopes_supported' => ['core', 'plugins'], 'scopes_requested' => ['core']]);
        $this->assertPairingError('discovery_no_scope', fn () => app(ServiceClient::class)->discover('https://service.example'));
    }

    public function test_full_pairing_flow(): void
    {
        Event::fake([PairingCompleted::class]);
        $this->fakeService();

        $this->artisan('site-portrait:pair', ['service' => 'https://service.example', '--scopes' => 'server,database,core', '--yes' => true])
            ->expectsOutputToContain('https://service.example/site-portrait/authorize?')
            ->assertSuccessful();

        $pending = Pairing::query()->where('status', Pairing::PENDING)->firstOrFail();
        $this->assertSame(['server', 'database'], $pending->scopes);
        $redirect = (string) $pending->redirect_uri;
        $this->assertStringStartsWith('https://site.test/site-portrait/callback?token=', $redirect);

        // Rebuild the authorization request the browser would make.
        $manager = app(PairingManager::class);
        Pairing::query()->delete();
        $begin = $manager->begin(app(ServiceClient::class)->discover('https://service.example'), ['server', 'database']);
        parse_str((string) parse_url($begin['authorization_url'], PHP_URL_QUERY), $params);
        $this->assertSame('code', $params['response_type']);
        $this->assertSame('https://site.test', $params['client_id']);
        $this->assertSame('S256', $params['code_challenge_method']);
        $this->assertSame('server database', $params['scope']);
        $this->assertSame('Test Bakery', $params['site_name']);
        $this->assertSame('1', $params['protocol_version']);

        // The service redirects back to redirect_uri with code and state.
        $this->get($params['redirect_uri'].'&code=SplxlOBeZQQYbYS6WxSbIA&state='.rawurlencode($params['state']))
            ->assertOk()
            ->assertSee('connected to Example Hosting');

        $pairing = Pairing::query()->active()->firstOrFail();
        $this->assertSame('pairing-123', $pairing->pairing_id);
        $this->assertSame(['server', 'database'], $pairing->scopes);
        $this->assertSame('Bakery Inc.', $pairing->account_hint);
        $this->assertSame($params['site_key_thumbprint'], $pairing->site_key_kid);
        $this->assertSame(0, Pairing::query()->where('status', Pairing::PENDING)->count());

        // Code exchange body (§4.4).
        $this->assertSame('authorization_code', $this->tokenRequest['grant_type']);
        $this->assertSame($params['code_challenge'], Crypto::pkceChallenge($this->tokenRequest['code_verifier']));
        $this->assertSame($params['redirect_uri'], $this->tokenRequest['redirect_uri']);
        $this->assertSame([
            'status' => 'https://site.test/site-portrait/v1/status',
            'portrait' => 'https://site.test/site-portrait/v1/portrait',
            'revoke' => 'https://site.test/site-portrait/v1/revoke',
        ], $this->tokenRequest['endpoints']);
        $this->assertSame('single', $this->tokenRequest['mode']);
        $this->assertSame('laravel', $this->tokenRequest['platform']['name']);

        // The private key is encrypted at rest.
        $raw = (string) \DB::table('site_portrait_pairings')->value('site_key_secret');
        $this->assertStringNotContainsString($pairing->site_key_secret, $raw);

        Event::assertDispatched(PairingCompleted::class);

        // Confirmation by the service (§4.5) with the pinned key.
        $this->signed('GET', '/site-portrait/v1/status')->assertOk()->assertJson(['pairing_id' => 'pairing-123']);
    }

    public function test_callback_rejects_wrong_state_and_reuse(): void
    {
        $this->fakeService();
        $begin = app(PairingManager::class)->begin(app(ServiceClient::class)->discover('https://service.example'), ['server']);
        parse_str((string) parse_url($begin['authorization_url'], PHP_URL_QUERY), $params);

        $this->get($params['redirect_uri'].'&code=abc&state=wrong')->assertStatus(400)->assertSee('expired or was not started');
        // The pending pairing is single use.
        $this->get($params['redirect_uri'].'&code=abc&state='.rawurlencode($params['state']))->assertStatus(400);
        $this->assertSame(0, Pairing::query()->count());
        Http::assertNotSent(fn (Request $r) => str_contains($r->url(), '/token'));
    }

    public function test_callback_handles_denial(): void
    {
        $this->fakeService();
        $begin = app(PairingManager::class)->begin(app(ServiceClient::class)->discover('https://service.example'), ['server']);
        parse_str((string) parse_url($begin['authorization_url'], PHP_URL_QUERY), $params);

        $this->get($params['redirect_uri'].'&error=access_denied&state='.rawurlencode($params['state']))->assertOk()->assertSee('did not approve');
        $this->assertSame(0, Pairing::query()->count());
    }

    public function test_token_keys_must_match_discovery(): void
    {
        $this->fakeService(token: fn () => Http::response([
            'pairing_id' => 'pairing-123',
            'jwks' => ['keys' => [Crypto::publicJwk(Crypto::keypairFromSeed(str_repeat("\x07", 32))['public'])]],
        ]));
        $begin = app(PairingManager::class)->begin(app(ServiceClient::class)->discover('https://service.example'), ['server']);
        parse_str((string) parse_url($begin['authorization_url'], PHP_URL_QUERY), $params);

        $this->get($params['redirect_uri'].'&code=abc&state='.rawurlencode($params['state']))->assertStatus(400)->assertSee('do not match');
        $this->assertSame(0, Pairing::query()->active()->count());
    }

    protected function requireAuthorizedUser($app): void
    {
        $app['config']->set('site-portrait.callback_middleware', ['can:manageSitePortrait']);
    }

    #[DefineEnvironment('requireAuthorizedUser')]
    public function test_callback_middleware_option(): void
    {
        $this->fakeService();
        $begin = app(PairingManager::class)->begin(app(ServiceClient::class)->discover('https://service.example'), ['server']);
        parse_str((string) parse_url($begin['authorization_url'], PHP_URL_QUERY), $params);

        $this->get($params['redirect_uri'].'&code=abc&state='.rawurlencode($params['state']))->assertForbidden();
        $this->assertSame(0, Pairing::query()->active()->count());
        Http::assertNotSent(fn (Request $r) => str_contains($r->url(), '/token'));
    }

    public function test_disconnect_notifies_the_service(): void
    {
        $this->fakeService();
        $this->createPairing();

        $this->artisan('site-portrait:disconnect', ['--force' => true])->assertSuccessful();

        $this->assertSame(0, Pairing::query()->count());
        Http::assertSent(function (Request $request) {
            $body = json_decode($request->body(), true);

            return $request->url() === 'https://service.example/site-portrait/revoke'
                && $body === ['pairing_id' => 'c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11', 'client_id' => 'https://site.test', 'reason' => 'revoked_by_site']
                && $request->hasHeader('Signature-Input')
                && $request->header('Content-Digest')[0] === Crypto::contentDigest($request->body());
        });
    }

    public function test_dev_mode_allows_http_local_hosts_only(): void
    {
        $sp = app(SitePortrait::class);
        $this->assertFalse($sp->isAllowedServiceUrl('http://127.0.0.1:8787'));

        config(['site-portrait.dev_mode' => true, 'app.url' => 'http://127.0.0.1:8000']);
        $this->app['env'] = 'local';
        $this->assertTrue($sp->isAllowedServiceUrl('http://127.0.0.1:8787'));
        $this->assertFalse($sp->isAllowedServiceUrl('http://service.example'));

        $this->app['env'] = 'production';
        $this->assertFalse($sp->isAllowedServiceUrl('http://127.0.0.1:8787'));
    }

    private function assertPairingError(string $reason, callable $callback): void
    {
        try {
            $callback();
            $this->fail('Expected '.$reason);
        } catch (PairingException $e) {
            $this->assertSame($reason, $e->reason, $e->getMessage());
        }
    }
}
