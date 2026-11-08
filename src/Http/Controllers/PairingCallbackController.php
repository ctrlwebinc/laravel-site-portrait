<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Http\Controllers;

use Ctrlweb\SitePortrait\Pairing\PairingException;
use Ctrlweb\SitePortrait\Pairing\PairingManager;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Browser callback at the end of the authorization (PROTOCOL.md §4.3):
 * checks the single-use token and the state, then exchanges the code.
 */
class PairingCallbackController
{
    public function __invoke(Request $request, PairingManager $pairings): Response
    {
        $token = $request->query('token');
        $token = is_string($token) ? $token : '';

        if ($request->query('error') !== null) {
            // The authorization was declined: discard the pending pairing if the token is genuine.
            try {
                $pairings->complete($token, null, $request->query('state'));
            } catch (PairingException) {
                // Expected: no code was given.
            }
            $error = is_string($request->query('error')) ? $request->query('error') : 'error';

            return $this->page(false, 'The service did not approve the connection ('.$error.').');
        }

        try {
            $pairing = $pairings->complete($token, $request->query('code'), $request->query('state'));
        } catch (PairingException $e) {
            return $this->page(false, $e->getMessage(), 400);
        }

        $service = (string) ($pairing->service['name'] ?? 'the service');

        return $this->page(true, 'This application is now connected to '.$service.'. The service will confirm the connection within a few seconds. You can close this page; run "php artisan site-portrait:status" to check.');
    }

    protected function page(bool $success, string $message, int $status = 200): Response
    {
        $title = $success ? 'Site Portrait: connected' : 'Site Portrait: connection failed';
        $html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            .'<meta name="robots" content="noindex"><title>'.e($title).'</title>'
            .'<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:#1f2328}'
            .'h1{font-size:1.4rem}.ok{color:#1a7f37}.ko{color:#cf222e}</style></head><body>'
            .'<h1 class="'.($success ? 'ok' : 'ko').'">'.e($title).'</h1><p>'.e($message).'</p></body></html>';

        return new Response($html, $status, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Frame-Options' => 'DENY',
        ]);
    }
}
