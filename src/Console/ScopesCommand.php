<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Illuminate\Console\Command;

class ScopesCommand extends Command
{
    protected $signature = 'site-portrait:scopes
        {--grant= : Comma-separated scopes to add}
        {--deny= : Comma-separated scopes to remove}';

    protected $description = 'Show or change the scopes granted to the service (no re-pairing needed)';

    public function handle(PairingManager $pairings): int
    {
        $pairing = $pairings->active();
        if ($pairing === null) {
            $this->components->error('This application is not connected to a service.');

            return self::FAILURE;
        }

        $split = fn ($value) => is_string($value) && $value !== '' ? array_map('trim', explode(',', $value)) : [];
        $grant = $split($this->option('grant'));
        $deny = $split($this->option('deny'));

        if ($grant !== [] || $deny !== []) {
            $scopes = array_values(array_diff(array_unique([...$pairing->scopes, ...$grant]), $deny));
            $pairing = $pairings->setScopes($scopes);
            $ignored = array_diff($grant, $pairing->scopes);
            if ($ignored !== []) {
                $this->components->warn('Not supported by the service, ignored: '.implode(', ', $ignored));
            }
        }

        $supported = (array) ($pairing->service['scopes_supported'] ?? []);
        $this->components->twoColumnDetail('Granted', implode(', ', $pairing->scopes) ?: '(none)');
        $this->components->twoColumnDetail('Supported by the service', implode(', ', $supported));

        return self::SUCCESS;
    }
}
