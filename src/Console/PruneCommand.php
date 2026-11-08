<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Models\Nonce;
use Ctrlweb\SitePortrait\Models\Pairing;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;

class PruneCommand extends Command
{
    protected $signature = 'site-portrait:prune';

    protected $description = 'Delete expired nonces, old access log entries and expired authorizations';

    public function handle(): int
    {
        $nonces = Nonce::query()->where('expires_at', '<', Carbon::now())->delete();
        $days = (int) config('site-portrait.access_log.retention_days', 90);
        $log = AccessLogEntry::query()->where('created_at', '<', Carbon::now()->subDays($days))->delete();
        AccessLogEntry::trimToMaxEntries();
        $pending = Pairing::query()->where('status', Pairing::PENDING)->where('expires_at', '<', Carbon::now())->delete();

        $this->components->info("Pruned $nonces nonces, $log log entries and $pending expired authorizations.");

        return self::SUCCESS;
    }
}
