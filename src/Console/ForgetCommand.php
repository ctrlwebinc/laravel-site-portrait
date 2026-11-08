<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Illuminate\Console\Command;

class ForgetCommand extends Command
{
    protected $signature = 'site-portrait:forget {--force : Do not ask for confirmation}';

    protected $description = 'Delete the pairing locally without notifying the service';

    public function handle(PairingManager $pairings): int
    {
        if (! $this->option('force') && ! $this->confirm('Delete the pairing and its keys without notifying the service?', false)) {
            return self::FAILURE;
        }
        $pairings->forget();
        $this->components->info('Pairing deleted locally.');

        return self::SUCCESS;
    }
}
