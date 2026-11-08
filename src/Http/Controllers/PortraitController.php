<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Http\Controllers;

use Ctrlweb\SitePortrait\Http\Middleware\HandleSitePortraitRequest;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Ctrlweb\SitePortrait\Portrait\PortraitBuilder;
use Ctrlweb\SitePortrait\Protocol\ProtocolError;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * GET /portrait?scopes=a,b (PROTOCOL.md §6.3).
 */
class PortraitController
{
    public function __invoke(Request $request, SitePortrait $sitePortrait, PairingManager $pairings, PortraitBuilder $builder): JsonResponse
    {
        $pairing = $pairings->active();
        $granted = array_values((array) $pairing?->scopes);
        $raw = $request->query('scopes');

        if ($raw === null || $raw === '') {
            $requested = $granted;
        } elseif (! is_string($raw)) {
            throw new ProtocolError('site_portrait_invalid_scope', 'Invalid scopes parameter.', 400);
        } else {
            $requested = array_values(array_unique(array_map('trim', explode(',', $raw))));
            $unknown = array_diff($requested, $sitePortrait->scopes());
            if ($unknown !== []) {
                $names = array_map(fn ($s) => (string) preg_replace('/[^a-z0-9_]/', '', strtolower((string) $s)), $unknown);
                throw new ProtocolError('site_portrait_invalid_scope', 'Unknown scope: '.implode(', ', $names).'.', 400);
            }
        }

        if ($request->query('site_id') !== null && $request->query('site_id') !== '') {
            throw new ProtocolError('site_portrait_invalid_param', 'Invalid site_id parameter.', 400);
        }

        $returned = array_values(array_intersect($sitePortrait->scopes(), $requested, $granted));
        $denied = array_values(array_diff($requested, $granted));
        if ($returned === []) {
            throw new ProtocolError('site_portrait_scope_denied', 'None of the requested scopes is granted.', 403);
        }

        $request->attributes->set(HandleSitePortraitRequest::SCOPES_ATTRIBUTE, $returned);

        return new JsonResponse($builder->build($returned, $denied, (string) $pairing?->pairing_id));
    }
}
