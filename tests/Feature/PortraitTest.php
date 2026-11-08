<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Feature;

use Ctrlweb\SitePortrait\Collectors\CollectContext;
use Ctrlweb\SitePortrait\Collectors\LaravelCollector;
use Ctrlweb\SitePortrait\Collectors\StorageCollector;
use Ctrlweb\SitePortrait\Facades\SitePortrait;
use Ctrlweb\SitePortrait\Portrait\PortraitBuilder;
use Ctrlweb\SitePortrait\Tests\Concerns\ActsAsService;
use Ctrlweb\SitePortrait\Tests\TestCase;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;

final class PortraitTest extends TestCase
{
    use ActsAsService;

    private const ALL = ['laravel', 'packages', 'server', 'database', 'storage', 'users_counts'];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpService();

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email');
        });
        DB::table('users')->insert([['email' => 'alice@example.com'], ['email' => 'bob@example.com']]);
        config(['auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class]]);
    }

    /**
     * @return array<string, mixed>
     */
    private function portrait(array $scopes = self::ALL): array
    {
        $portrait = app(PortraitBuilder::class)->build($scopes, [], 'pairing-1');

        return json_decode((string) json_encode($portrait), true);
    }

    public function test_portrait_validates_against_the_schema(): void
    {
        $this->app->make(Schedule::class)->command('inspire')->hourly();
        $this->app->make(Schedule::class)->command('inspire')->everyThirtySeconds();

        $portrait = app(PortraitBuilder::class)->build(self::ALL, ['core'], 'pairing-1');
        $json = (string) json_encode($portrait);

        $validator = new Validator;
        $validator->resolver()->registerFile('urn:site-portrait:portrait:1', __DIR__.'/../../resources/schema/portrait-v1.schema.json');
        $result = $validator->validate(json_decode($json), 'urn:site-portrait:portrait:1');
        $this->assertTrue($result->isValid(), $result->isValid() ? '' : (string) json_encode((new ErrorFormatter)->format($result->error()), JSON_PRETTY_PRINT));

        $data = json_decode($json, true);
        $this->assertSame(self::ALL, array_keys($data['data']));
        $this->assertSame([], array_filter($data['warnings'], fn ($w) => $w['code'] === 'collector_error'));
    }

    public function test_users_counts(): void
    {
        $data = $this->portrait(['users_counts'])['data']['users_counts'];
        $this->assertSame(2, $data['total']);
        $this->assertSame(['none' => 2], $data['by_role']);
    }

    public function test_laravel_scope(): void
    {
        $this->app->make(Schedule::class)->command('inspire')->hourly();
        $this->app->make(Schedule::class)->command('inspire')->dailyAt('03:00');
        $this->app->make(Schedule::class)->command('inspire')->everyThirtySeconds();

        $data = $this->portrait(['laravel'])['data']['laravel'];
        $this->assertSame($this->app->version(), $data['version']);
        $this->assertNull($data['environment_type']); // APP_ENV=testing
        $this->assertSame('array', $data['drivers']['cache']);
        $this->assertSame(['0 * * * *' => 1, '0 3 * * *' => 1, 'sub_minute' => 1], $data['schedule']['by_frequency']);
        $this->assertSame(3, $data['schedule']['tasks_count']);
        $this->assertGreaterThan(0, $data['routes_count']);
        $this->assertGreaterThan(0, $data['commands_count']);
    }

    public function test_environment_type_mapping(): void
    {
        foreach (['production' => 'production', 'staging' => 'staging', 'local' => 'local', 'dev' => 'development', 'qa' => null] as $env => $expected) {
            $this->app['env'] = $env;
            $this->assertSame($expected, app(LaravelCollector::class)->collect(new CollectContext('laravel'))['environment_type'], $env);
        }
    }

    public function test_packages_scope_hides_private_packages_but_counts_them(): void
    {
        $all = $this->portrait(['packages'])['data']['packages'];
        $names = array_column($all['items'], 'name');
        $this->assertContains('laravel/framework', $names);
        $this->assertNotContains('ctrlweb/laravel-site-portrait', $names);

        config(['site-portrait.hidden_packages' => ['laravel/*']]);
        $hidden = $this->portrait(['packages'])['data']['packages'];
        $this->assertNotContains('laravel/framework', array_column($hidden['items'], 'name'));
        $this->assertSame($all['counts'], $hidden['counts']);
    }

    public function test_storage_scope_counts_files_and_recomputes_old_cache_entries(): void
    {
        // An entry cached by a version without file counts.
        Cache::put(StorageCollector::CACHE_KEY, ['sizes' => ['app' => 1], 'disks' => [], 'timeout' => false]);

        $data = $this->portrait(['storage'])['data']['storage'];
        $this->assertSame(['app', 'app_public', 'public', 'computed_at'], array_keys($data['files']));
        $this->assertSame($data['sizes']['computed_at'], $data['files']['computed_at']);
        foreach (['app', 'app_public', 'public'] as $key) {
            $this->assertIsInt($data['files'][$key], $key);
        }
        $this->assertGreaterThanOrEqual($data['files']['app_public'], $data['files']['app']);
        $this->assertSame($data['files'], Cache::get(StorageCollector::CACHE_KEY)['files']);
    }

    public function test_failing_collector_yields_null_and_warning(): void
    {
        config(['site-portrait.scopes.server' => \stdClass::class]);
        $portrait = $this->portrait(['server', 'users_counts']);
        $this->assertNull($portrait['data']['server']);
        $this->assertSame(2, $portrait['data']['users_counts']['total']);
        $this->assertSame([['scope' => 'server', 'field' => null, 'code' => 'collector_error', 'message' => 'The data of this scope could not be collected.']], $portrait['warnings']);
    }

    public function test_extensions(): void
    {
        SitePortrait::extend('laravel', 'acme-billing', fn () => ['invoices' => 42]);
        $data = $this->portrait(['laravel'])['data']['laravel'];
        $this->assertSame(['acme-billing' => ['invoices' => 42]], $data['extensions']);
    }

    /**
     * Secrets placed in the configuration and the environment never leave the application.
     */
    public function test_privacy_canary(): void
    {
        $canary = 'CANARY-7f3a9e';
        config([
            'database.connections.testing.password' => $canary.'-db',
            'database.connections.testing.host' => $canary.'-host.internal',
            'mail.mailers.smtp.password' => $canary.'-smtp',
            'mail.from.address' => $canary.'@example.com',
            'services.stripe.secret' => $canary.'-stripe',
            'queue.connections.sync.queue' => $canary.'-queue',
            'filesystems.disks.s3' => ['driver' => 's3', 'key' => $canary.'-s3', 'bucket' => $canary.'-bucket'],
            'cache.stores.array.driver' => 'array',
        ]);
        putenv('SECRET_TOKEN='.$canary.'-env');
        $_SERVER['SECRET_TOKEN'] = $canary.'-server';
        $this->app->make(Schedule::class)->command('backup:run --password='.$canary.'-cmd')->daily();
        $this->createPairing(self::ALL);

        $outputs = [
            (string) json_encode(app(PortraitBuilder::class)->build(self::ALL)),
            (string) $this->signed('GET', '/site-portrait/v1/portrait')->assertOk()->getContent(),
            (string) $this->signed('GET', '/site-portrait/v1/status')->assertOk()->getContent(),
            (string) $this->signed('GET', '/site-portrait/v1/portrait?scopes=nope')->getContent(),
        ];

        foreach ($outputs as $output) {
            $this->assertStringNotContainsString($canary, $output);
            $this->assertStringNotContainsString(base_path(), $output);
            $this->assertStringNotContainsString(json_encode(base_path()) ?: '', $output);
            $this->assertStringNotContainsString('alice@example.com', $output);
            $this->assertStringNotContainsString((string) config('app.key'), $output);
        }

        putenv('SECRET_TOKEN');
        unset($_SERVER['SECRET_TOKEN']);
    }
}
