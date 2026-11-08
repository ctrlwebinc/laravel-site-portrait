<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingException;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Illuminate\Console\Command;

class RotateKeyCommand extends Command
{
    protected $signature = 'site-portrait:rotate-key';

    protected $description = 'Replace the site signing key (the old key stays published for 7 days)';

    public function handle(PairingManager $pairings): int
    {
        try {
            $pairing = $pairings->rotateSiteKey();
        } catch (PairingException $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }
        $this->components->info('New site key: '.$pairing->site_key_kid.' (endorsed by the previous key).');

        return self::SUCCESS;
    }
}
