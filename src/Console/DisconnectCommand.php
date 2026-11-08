<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingException;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Illuminate\Console\Command;

class DisconnectCommand extends Command
{
    protected $signature = 'site-portrait:disconnect
        {--reason=revoked_by_site : revoked_by_site, plugin_uninstalled or key_compromised}
        {--force : Do not ask for confirmation}';

    protected $description = 'Disconnect from the service (local revocation, then notice to the service)';

    public function handle(PairingManager $pairings): int
    {
        $reason = $this->option('reason');
        if (! is_string($reason) || ! in_array($reason, PairingManager::REVOCATION_REASONS, true)) {
            $this->components->error('Invalid reason. Use one of: '.implode(', ', PairingManager::REVOCATION_REASONS).'.');

            return self::FAILURE;
        }
        $pairing = $pairings->active();
        if ($pairing === null) {
            $this->components->info('Not connected.');

            return self::SUCCESS;
        }
        if (! $this->option('force') && ! $this->confirm('Disconnect from '.($pairing->service['name'] ?? 'the service').'?', true)) {
            return self::FAILURE;
        }

        try {
            $pairings->disconnect($reason);
        } catch (PairingException $e) {
            $this->components->warn('Disconnected locally, but the service could not be notified: '.$e->getMessage());

            return self::SUCCESS;
        }
        $this->components->info('Disconnected; the service was notified.');

        return self::SUCCESS;
    }
}
