<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Console\Command;

class StatusCommand extends Command
{
    protected $signature = 'site-portrait:status';

    protected $description = 'Show the Site Portrait connection';

    public function handle(PairingManager $pairings, SitePortrait $sitePortrait): int
    {
        $this->components->twoColumnDetail('Package version', $sitePortrait->version());
        $this->components->twoColumnDetail('Site URL (client_id)', $sitePortrait->origin());
        $this->components->twoColumnDetail('Status endpoint', $sitePortrait->endpointUrl('status'));
        if ($sitePortrait->isDevMode()) {
            $this->components->warn('Development mode is active: HTTP and local hosts are accepted. Never use it in production.');
        }

        $pairing = $pairings->active();
        if ($pairing === null) {
            $pending = Pairing::query()->where('status', Pairing::PENDING)->first();
            $this->components->info($pending !== null && $pending->expires_at?->isFuture()
                ? 'An authorization is in progress (expires '.$pending->expires_at->diffForHumans().').'
                : 'Not connected. Run php artisan site-portrait:pair <service URL>.');

            return self::SUCCESS;
        }

        $this->components->twoColumnDetail('<fg=green;options=bold>Service</>', (string) ($pairing->service['name'] ?? ''));
        $this->components->twoColumnDetail('Origin', (string) ($pairing->service['origin'] ?? ''));
        if ($pairing->account_hint) {
            $this->components->twoColumnDetail('Account', $pairing->account_hint);
        }
        $this->components->twoColumnDetail('Pairing id', (string) $pairing->pairing_id);
        $this->components->twoColumnDetail('Connected', (string) $pairing->connected_at?->toDateTimeString());
        $this->components->twoColumnDetail('Confirmed by the service', $pairing->confirmed_at ? $pairing->confirmed_at->toDateTimeString() : '<fg=yellow>not yet</>');
        $this->components->twoColumnDetail('Scopes granted', implode(', ', $pairing->scopes));
        $this->components->twoColumnDetail('Site key', $pairing->site_key_kid);
        $this->components->twoColumnDetail('Pinned service keys', implode(', ', array_keys((array) $pairing->service_keys)));
        $limit = (int) config('site-portrait.rate_limit', 60);
        $this->components->twoColumnDetail('Requests in the last hour', AccessLogEntry::authenticatedLastHour().' / '.$limit);

        $last = AccessLogEntry::query()->latest('id')->first();
        if ($last !== null) {
            $this->components->twoColumnDetail('Last request', $last->created_at->toDateTimeString().' '.$last->method.' '.$last->endpoint.' → '.$last->status);
        }

        return self::SUCCESS;
    }
}
