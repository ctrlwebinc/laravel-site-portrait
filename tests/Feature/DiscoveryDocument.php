<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Feature;

use Ctrlweb\SitePortrait\Protocol\Crypto;

final class DiscoveryDocument
{
    /**
     * @return array<string, mixed>
     */
    public static function make(string $servicePublicKey): array
    {
        $scopes = ['core', 'plugins', 'themes', 'server', 'database', 'content', 'users_counts', 'laravel', 'packages', 'storage'];

        return [
            'protocol' => 'site-portrait',
            'protocol_versions' => ['1'],
            'service' => [
                'name' => 'Example <b>Hosting</b>',
                'description' => 'Recommends a hosting plan.',
                'privacy_policy_url' => 'https://service.example/privacy',
                'terms_url' => 'javascript:alert(1)',
            ],
            'authorization_endpoint' => 'https://service.example/site-portrait/authorize',
            'token_endpoint' => 'https://service.example/site-portrait/token',
            'revocation_endpoint' => 'https://service.example/site-portrait/revoke',
            'scopes_supported' => $scopes,
            'scopes_requested' => ['plugins', 'server', 'database', 'laravel'],
            'scope_reasons' => ['database' => 'Database size drives storage sizing.'],
            'jwks' => ['keys' => [Crypto::publicJwk($servicePublicKey)]],
        ];
    }
}
