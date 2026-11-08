<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Http\Controllers;

use Ctrlweb\SitePortrait\Models\AccessLogEntry;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Carbon;

/**
 * GET /status (PROTOCOL.md §6.2).
 */
class StatusController
{
    public function __invoke(SitePortrait $sitePortrait, PairingManager $pairings): JsonResponse
    {
        $pairings->markConfirmed();
        $pairing = $pairings->active();
        $limit = max(1, (int) config('site-portrait.rate_limit', 60));

        return new JsonResponse([
            'protocol_version' => SitePortrait::PROTOCOL_VERSION,
            'plugin_version' => $sitePortrait->version(),
            'platform' => $sitePortrait->platform(),
            'pairing_id' => $pairing?->pairing_id,
            'mode' => 'single',
            'site_url' => $sitePortrait->origin(),
            'sites_count' => 1,
            'scopes_granted' => array_values((array) $pairing?->scopes),
            'scopes_available' => $sitePortrait->scopes(),
            'site_jwks' => $pairings->siteJwks(),
            'rate_limit' => [
                'limit' => $limit,
                'remaining' => max(0, $limit - AccessLogEntry::authenticatedLastHour() - 1),
                'window' => 3600,
            ],
            'server_time' => Carbon::now()->getTimestamp(),
        ]);
    }
}
