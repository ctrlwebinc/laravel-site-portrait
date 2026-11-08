<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingException;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Pairing\ServiceClient;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\multiselect;

/**
 * Starts a pairing (PROTOCOL.md §3, §4.1–4.2): discovery, consent, then the
 * authorization URL to open in a browser.
 */
class PairCommand extends Command
{
    protected $signature = 'site-portrait:pair
        {service : Base URL of the service, e.g. https://service.example}
        {--scopes= : Comma-separated scopes to grant (default: those requested by the service)}
        {--yes : Do not ask for confirmation}';

    protected $description = 'Connect this application to a Site Portrait service';

    public function handle(ServiceClient $client, PairingManager $pairings, SitePortrait $sitePortrait): int
    {
        if ($pairings->isActive()) {
            $this->components->error('This application is already connected to a service. Run site-portrait:disconnect first.');

            return self::FAILURE;
        }

        $service = $this->argument('service');
        if (! is_string($service)) {
            $this->components->error('Give the base URL of the service.');

            return self::FAILURE;
        }

        try {
            $discovery = $client->discover($service);
        } catch (PairingException $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        $this->components->twoColumnDetail('<fg=green;options=bold>Service</>', $discovery['name']);
        $this->components->twoColumnDetail('Origin', $discovery['origin']);
        if ($discovery['description'] !== '') {
            $this->components->twoColumnDetail('Description', $discovery['description']);
        }
        $this->components->twoColumnDetail('Privacy policy', $discovery['privacy_policy_url']);
        if ($discovery['terms_url'] !== '') {
            $this->components->twoColumnDetail('Terms', $discovery['terms_url']);
        }
        if ($discovery['contact'] !== '') {
            $this->components->twoColumnDetail('Contact', $discovery['contact']);
        }
        $this->newLine();
        $this->line('  The service will be able to read, at most once per request and only over signed HTTPS calls,');
        $this->line('  the categories of technical data you select below. It can never modify the application.');
        $this->newLine();

        $labels = [];
        foreach ($discovery['scopes_supported'] as $scope) {
            $reason = $discovery['scope_reasons'][$scope] ?? null;
            $labels[$scope] = $scope.' — '.(self::DESCRIPTIONS[$scope] ?? 'custom scope').($reason ? ' (service: '.$reason.')' : '');
        }

        if (is_string($this->option('scopes')) && $this->option('scopes') !== '') {
            $scopes = array_values(array_intersect($discovery['scopes_supported'], array_map('trim', explode(',', $this->option('scopes')))));
        } elseif ($this->option('yes') || ! $this->input->isInteractive()) {
            $scopes = $discovery['scopes_requested'];
        } else {
            $scopes = multiselect(
                label: 'Data the service may read',
                options: $labels,
                default: $discovery['scopes_requested'],
                required: true,
                scroll: 10,
            );
        }
        if ($scopes === []) {
            $this->components->error('Select at least one scope among: '.implode(', ', $discovery['scopes_supported']).'.');

            return self::FAILURE;
        }
        foreach ($scopes as $scope) {
            $this->components->bulletList([$labels[$scope] ?? $scope]);
        }

        if (! $this->option('yes') && $this->input->isInteractive()
            && ! confirm('Connect to '.$discovery['name'].' and share these data?', default: false)) {
            $this->components->warn('Cancelled.');

            return self::FAILURE;
        }

        try {
            $result = $pairings->begin($discovery, array_values($scopes));
        } catch (PairingException $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        $this->newLine();
        $this->components->info('Open this address in your browser within 15 minutes, sign in to the service and approve the connection:');
        $this->line($result['authorization_url']);
        $this->newLine();
        $this->line('  You will then be sent back to '.$sitePortrait->origin().' to complete the connection.');

        return self::SUCCESS;
    }

    /** Short descriptions shown in the consent screen. */
    public const DESCRIPTIONS = [
        'laravel' => 'Laravel version, environment type, debug and maintenance flags, driver names (cache, queue, mail…), queue and scheduler counts',
        'packages' => 'Installed Composer packages with their versions (no repository URLs)',
        'server' => 'OS family, web server, PHP version, extensions and limits, OPcache, CPU, memory and disk space (no host names, IPs or paths)',
        'database' => 'Database engine and version, total size, number and size of the largest tables (no credentials, host or prefix)',
        'storage' => 'Sizes of the storage, public and vendor directories and of local disks (no paths, no file names)',
        'users_counts' => 'Number of users, per role when roles exist (never names, logins or e-mail addresses)',
    ];
}
