<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests;

use Ctrlweb\SitePortrait\SitePortraitServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    public const SITE_URL = 'https://site.test';

    protected function getPackageProviders($app): array
    {
        return [SitePortraitServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', self::SITE_URL);
        $app['config']->set('app.name', 'Test Bakery');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        // SP_TEST_DB=mysql|mariadb|pgsql runs the suite on a real server (CI).
        $app['config']->set('database.default', getenv('SP_TEST_DB') ?: 'testing');
        $app['config']->set('cache.default', 'array');
    }

    /**
     * @return array<string, mixed>
     */
    protected static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__.'/fixtures/test-vectors.json'), true, flags: JSON_THROW_ON_ERROR);
    }
}
