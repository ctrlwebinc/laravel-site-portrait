<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait;

use Ctrlweb\SitePortrait\Pairing\HostResolver;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Pairing\ServiceClient;
use Ctrlweb\SitePortrait\Portrait\PortraitBuilder;
use Ctrlweb\SitePortrait\Protocol\ProtocolError;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Support\ServiceProvider;

class SitePortraitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/site-portrait.php', 'site-portrait');

        $this->app->singleton(SitePortrait::class);
        $this->app->singleton(HostResolver::class);
        $this->app->singleton(ServiceClient::class);
        $this->app->singleton(PairingManager::class);
        $this->app->bind(PortraitBuilder::class);
    }

    public function boot(): void
    {
        if (config('site-portrait.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/site-portrait.php');
        }

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // Protocol errors are expected answers, not application errors.
        $this->callAfterResolving(ExceptionHandler::class, function (ExceptionHandler $handler) {
            if ($handler instanceof Handler) {
                $handler->dontReport(ProtocolError::class);
            }
        });

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/site-portrait.php' => config_path('site-portrait.php'),
            ], 'site-portrait-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'site-portrait-migrations');

            $this->commands([
                Console\InstallCommand::class,
                Console\PairCommand::class,
                Console\StatusCommand::class,
                Console\ScopesCommand::class,
                Console\ShowCommand::class,
                Console\LogCommand::class,
                Console\RotateKeyCommand::class,
                Console\DisconnectCommand::class,
                Console\ForgetCommand::class,
                Console\PruneCommand::class,
            ]);
        }
    }
}
