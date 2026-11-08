<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Composer\InstalledVersions;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Queue\Failed\CountableFailedJobProvider;
use Illuminate\Queue\Failed\FailedJobProviderInterface;
use Illuminate\Queue\Failed\NullFailedJobProvider;
use Illuminate\Queue\NullQueue;
use Illuminate\Queue\SyncQueue;
use Illuminate\Routing\Router;

/**
 * Scope "laravel": framework version, environment, driver names, queues,
 * scheduler and first-party/ecosystem packages. Only whitelisted values are
 * read from the configuration (driver names, booleans, timezone, locale):
 * never credentials, hosts, queue names, commands or URIs.
 */
class LaravelCollector implements Collector
{
    /** Package => short identifier reported in "ecosystem" when installed. */
    public const ECOSYSTEM = [
        'laravel/horizon' => 'horizon',
        'laravel/pulse' => 'pulse',
        'laravel/telescope' => 'telescope',
        'laravel/reverb' => 'reverb',
        'laravel/octane' => 'octane',
        'laravel/nova' => 'nova',
        'laravel/sanctum' => 'sanctum',
        'laravel/passport' => 'passport',
        'laravel/cashier' => 'cashier',
        'laravel/cashier-paddle' => 'cashier-paddle',
        'laravel/scout' => 'scout',
        'laravel/vapor-core' => 'vapor',
        'laravel/folio' => 'folio',
        'laravel/pennant' => 'pennant',
        'laravel/socialite' => 'socialite',
        'laravel/fortify' => 'fortify',
        'laravel/jetstream' => 'jetstream',
        'laravel/breeze' => 'breeze',
        'livewire/livewire' => 'livewire',
        'livewire/volt' => 'volt',
        'inertiajs/inertia-laravel' => 'inertia',
        'filament/filament' => 'filament',
        'statamic/cms' => 'statamic',
        'spatie/laravel-permission' => 'spatie-permission',
        'spatie/laravel-medialibrary' => 'spatie-medialibrary',
        'spatie/laravel-backup' => 'spatie-backup',
        'barryvdh/laravel-debugbar' => 'debugbar',
        'sentry/sentry-laravel' => 'sentry',
    ];

    public function __construct(protected Application $app) {}

    public function collect(CollectContext $context): array
    {
        return [
            'version' => $this->app->version(),
            'environment_type' => $this->environmentType(),
            'debug' => (bool) config('app.debug'),
            'maintenance' => $this->app->isDownForMaintenance(),
            'timezone' => $this->stringOrNull(config('app.timezone'), 64),
            'locale' => $this->stringOrNull(config('app.locale'), 16),
            'https' => str_starts_with(strtolower((string) config('app.url')), 'https://'),
            'optimizations' => [
                'config_cached' => $this->app->configurationIsCached(),
                'routes_cached' => $this->app->routesAreCached(),
                'events_cached' => $this->app->eventsAreCached(),
            ],
            'drivers' => $this->drivers(),
            'octane' => [
                'enabled' => self::installed('laravel/octane') && is_string(config('octane.server')),
                'server' => $this->driverName(config('octane.server')),
            ],
            'ecosystem' => array_values(array_unique(array_values(array_filter(
                self::ECOSYSTEM,
                fn (string $id, string $package) => self::installed($package),
                ARRAY_FILTER_USE_BOTH,
            )))),
            'queue' => $this->queue($context),
            'schedule' => $this->schedule($context),
            'routes_count' => $this->routesCount(),
            'commands_count' => $this->commandsCount($context),
        ];
    }

    protected function environmentType(): ?string
    {
        $env = strtolower((string) $this->app->environment());

        // Schema 1.1.0: production, staging and local as is; dev and development
        // to development; anything else (e.g. testing) is null.
        return match ($env) {
            'production', 'staging', 'local' => $env,
            'dev', 'development' => 'development',
            default => null,
        };
    }

    /**
     * Driver of the default store/connection of each subsystem.
     *
     * @return array<string, string|null>
     */
    protected function drivers(): array
    {
        $default = fn (string $section, string $collection, string $key = 'driver') => $this->driverName(
            config($section.'.'.$collection.'.'.config($section.'.default').'.'.$key)
        );

        return [
            'cache' => $default('cache', 'stores'),
            'session' => $this->driverName(config('session.driver')),
            'queue' => $default('queue', 'connections'),
            'mail' => $default('mail', 'mailers', 'transport'),
            'broadcasting' => $default('broadcasting', 'connections'),
            'filesystem' => $default('filesystems', 'disks'),
            'filesystem_cloud' => $this->driverName(config('filesystems.disks.'.config('filesystems.cloud').'.driver')),
            'log' => $default('logging', 'channels'),
        ];
    }

    /**
     * @return array{pending_jobs: int|null, failed_jobs: int|null, batches: int|null}
     */
    protected function queue(CollectContext $context): array
    {
        $pending = null;
        try {
            $connection = $this->app->make('queue')->connection();
            if (! $connection instanceof SyncQueue && ! $connection instanceof NullQueue) {
                $pending = (int) $connection->size();
            }
        } catch (\Throwable) {
            $context->warn('queue.pending_jobs', 'unavailable', 'The default queue size could not be read.');
        }

        $failed = null;
        try {
            $failer = $this->app->bound('queue.failer') ? $this->app->make('queue.failer') : null;
            // The null provider stores nothing: the count is unknown, not zero.
            if ($failer instanceof NullFailedJobProvider) {
                $failed = null;
            } elseif ($failer instanceof CountableFailedJobProvider) {
                $failed = $failer->count();
            } elseif ($failer instanceof FailedJobProviderInterface) {
                $failed = count($failer->all());
            }
        } catch (\Throwable) {
            $context->warn('queue.failed_jobs', 'unavailable', 'Failed jobs could not be counted.');
        }

        $batches = null;
        try {
            $table = config('queue.batching.table', 'job_batches');
            $db = $this->app->make('db')->connection(config('queue.batching.database'));
            if (is_string($table) && $db->getSchemaBuilder()->hasTable($table)) {
                $batches = (int) $db->table($table)->count();
            }
        } catch (\Throwable) {
            $batches = null;
        }

        return ['pending_jobs' => $pending, 'failed_jobs' => $failed, 'batches' => $batches];
    }

    /**
     * Number of scheduled tasks per cron expression (schema 1.1.0). Commands
     * and their arguments are never returned.
     *
     * @return array{tasks_count: int|null, by_frequency: object|null}
     */
    protected function schedule(CollectContext $context): array
    {
        try {
            // Console routes (routes/console.php) define the schedule; load them.
            $this->app->make(ConsoleKernel::class)->all();
            $events = $this->app->make(Schedule::class)->events();
        } catch (\Throwable) {
            $context->warn('schedule', 'unavailable', 'The schedule could not be loaded.');

            return ['tasks_count' => null, 'by_frequency' => null];
        }

        $byFrequency = [];
        foreach ($events as $event) {
            $key = self::frequencyKey($event);
            $byFrequency[$key] = ($byFrequency[$key] ?? 0) + 1;
        }
        ksort($byFrequency);

        return ['tasks_count' => count($events), 'by_frequency' => (object) $byFrequency];
    }

    /**
     * Cron expression normalised to five fields separated by single spaces,
     * or "sub_minute" for tasks repeating more than once a minute.
     */
    public static function frequencyKey(Event $event): string
    {
        if ($event->repeatSeconds !== null) {
            return 'sub_minute';
        }
        $fields = preg_split('/\s+/', trim($event->expression)) ?: [];
        if (count($fields) !== 5) {
            return 'other';
        }

        return mb_substr(implode(' ', $fields), 0, 100);
    }

    protected function routesCount(): ?int
    {
        try {
            return count($this->app->make(Router::class)->getRoutes()->getRoutes());
        } catch (\Throwable) {
            return null;
        }
    }

    protected function commandsCount(CollectContext $context): ?int
    {
        try {
            return count($this->app->make(ConsoleKernel::class)->all());
        } catch (\Throwable) {
            $context->warn('commands_count', 'unavailable', 'Artisan commands could not be listed.');

            return null;
        }
    }

    protected function driverName(mixed $value): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        return preg_match('/^[a-z0-9_-]{1,32}$/i', $value) ? strtolower($value) : 'custom';
    }

    protected function stringOrNull(mixed $value, int $length): ?string
    {
        return is_string($value) && $value !== '' ? mb_substr($value, 0, $length) : null;
    }

    public static function installed(string $package): bool
    {
        try {
            return InstalledVersions::isInstalled($package, false);
        } catch (\Throwable) {
            return false;
        }
    }
}
