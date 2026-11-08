<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Console;

use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Portrait\PortraitBuilder;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Console\Command;

/**
 * Prints the portrait exactly as the service would receive it.
 */
class ShowCommand extends Command
{
    protected $signature = 'site-portrait:show
        {--scopes= : Comma-separated scopes (default: granted scopes, or all when not connected)}';

    protected $description = 'Print the portrait that would be sent to the service (JSON)';

    public function handle(PortraitBuilder $builder, PairingManager $pairings, SitePortrait $sitePortrait): int
    {
        $pairing = $pairings->active();
        $scopes = is_string($this->option('scopes')) && $this->option('scopes') !== ''
            ? $sitePortrait->sanitizeScopes(array_map('trim', explode(',', $this->option('scopes'))))
            : ($pairing !== null ? $pairing->scopes : $sitePortrait->scopes());

        if ($scopes === []) {
            $this->components->error('Unknown scopes. Available: '.implode(', ', $sitePortrait->scopes()));

            return self::FAILURE;
        }

        $portrait = $builder->build($scopes, [], $pairing !== null ? (string) $pairing->pairing_id : 'local');
        $this->line((string) json_encode($portrait, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION));

        return self::SUCCESS;
    }
}
