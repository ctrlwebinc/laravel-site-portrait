<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'site-portrait:install {--no-migrate : Do not run the migrations}';

    protected $description = 'Publish the Site Portrait configuration and run its migrations';

    public function handle(SitePortrait $sitePortrait): int
    {
        $this->call('vendor:publish', ['--tag' => 'site-portrait-config']);
        if (! $this->option('no-migrate')) {
            $this->call('migrate');
        }

        $this->newLine();
        $this->components->info('Site Portrait is installed. Before pairing, check that:');
        $this->components->bulletList([
            'APP_URL (or SITE_PORTRAIT_URL) is the public HTTPS address: '.$sitePortrait->siteUrl(),
            'TrustProxies is configured if the application runs behind a proxy or load balancer (HTTPS detection, client IP)',
            'the endpoints are reachable without redirection: '.$sitePortrait->endpointUrl('status'),
            'php artisan site-portrait:prune is scheduled (e.g. daily)',
        ]);
        $this->line('  Then run: php artisan site-portrait:pair https://service.example');

        return self::SUCCESS;
    }
}
