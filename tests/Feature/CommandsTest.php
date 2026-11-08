<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Feature;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Models\Nonce;
use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Tests\Concerns\ActsAsService;
use Ctrlweb\SitePortrait\Tests\TestCase;
use Illuminate\Support\Carbon;

final class CommandsTest extends TestCase
{
    use ActsAsService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpService();
    }

    public function test_status_when_not_connected(): void
    {
        $this->artisan('site-portrait:status')->expectsOutputToContain('Not connected')->assertSuccessful();
    }

    public function test_status_when_connected(): void
    {
        $this->createPairing(['server']);
        $this->artisan('site-portrait:status')
            ->expectsOutputToContain('Example service')
            ->expectsOutputToContain('not yet')
            ->assertSuccessful();
    }

    public function test_scopes(): void
    {
        $this->createPairing(['server']);
        $this->artisan('site-portrait:scopes', ['--grant' => 'database,core', '--deny' => 'server'])
            ->expectsOutputToContain('ignored: core')
            ->assertSuccessful();
        $this->assertSame(['database'], Pairing::query()->first()->scopes);
    }

    public function test_show_prints_the_portrait(): void
    {
        $this->artisan('site-portrait:show', ['--scopes' => 'server'])
            ->expectsOutputToContain('"scopes_returned": [')
            ->assertSuccessful();
        $this->artisan('site-portrait:show', ['--scopes' => 'core'])->assertFailed();
    }

    public function test_rotate_key_and_forget(): void
    {
        $this->artisan('site-portrait:rotate-key')->assertFailed();
        $pairing = $this->createPairing();
        $this->artisan('site-portrait:rotate-key')->expectsOutputToContain('New site key')->assertSuccessful();
        $this->assertNotSame($pairing->site_key_kid, Pairing::query()->first()->site_key_kid);

        $this->artisan('site-portrait:forget', ['--force' => true])->assertSuccessful();
        $this->assertSame(0, Pairing::query()->count());
    }

    public function test_log_and_prune(): void
    {
        $this->createPairing(['server']);
        $this->signed('GET', '/site-portrait/v1/status')->assertOk();
        $this->artisan('site-portrait:log')->expectsOutputToContain('/status')->assertSuccessful();

        Nonce::query()->update(['expires_at' => Carbon::now()->subMinute()]);
        AccessLogEntry::query()->update(['created_at' => Carbon::now()->subDays(100)]);
        $this->artisan('site-portrait:prune')->assertSuccessful();
        $this->assertSame(0, Nonce::query()->count());
        $this->assertSame(0, AccessLogEntry::query()->count());
    }

    public function test_pair_refuses_when_already_connected(): void
    {
        $this->createPairing();
        $this->artisan('site-portrait:pair', ['service' => 'https://service.example', '--yes' => true])
            ->expectsOutputToContain('already connected')
            ->assertFailed();
    }
}
