<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Illuminate\Console\Command;

class LogCommand extends Command
{
    protected $signature = 'site-portrait:log {--limit=30 : Number of entries}';

    protected $description = 'Show the access log of the Site Portrait endpoints';

    public function handle(): int
    {
        $entries = AccessLogEntry::query()->latest('id')->limit(max(1, (int) $this->option('limit')))->get();
        if ($entries->isEmpty()) {
            $this->components->info('No request yet.');

            return self::SUCCESS;
        }

        $this->table(
            ['Date (UTC)', 'IP', 'Request', 'Key', 'Scopes', 'Status', 'Error'],
            $entries->map(fn (AccessLogEntry $e) => [
                $e->created_at->utc()->toDateTimeString(),
                (string) $e->ip,
                $e->method.' '.$e->endpoint,
                $e->key_id ? substr($e->key_id, 0, 10).'…' : '',
                implode(',', (array) $e->scopes),
                $e->status,
                (string) $e->error_code,
            ])->all(),
        );

        return self::SUCCESS;
    }
}
