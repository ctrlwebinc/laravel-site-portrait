<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Http\Controllers;

use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Protocol\ProtocolError;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * POST /revoke: service-initiated revocation (PROTOCOL.md §6.4). The response
 * is signed with the site key that was just discarded.
 */
class RevokeController
{
    public function __invoke(Request $request, PairingManager $pairings): JsonResponse
    {
        $body = json_decode((string) $request->getContent(), true);
        if (! is_array($body)) {
            throw new ProtocolError('site_portrait_invalid_body', 'Malformed JSON body.', 400);
        }
        $pairing = $pairings->active();
        if ($pairing === null || ! is_string($body['pairing_id'] ?? null) || ! hash_equals((string) $pairing->pairing_id, $body['pairing_id'])) {
            throw new ProtocolError('site_portrait_pairing_mismatch', 'Unknown pairing_id.', 409);
        }
        $pairings->forget();

        return new JsonResponse(['revoked' => true]);
    }
}
