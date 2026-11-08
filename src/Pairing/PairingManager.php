<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Pairing;

use Ctrlweb\SitePortrait\Events\PairingCompleted;
use Ctrlweb\SitePortrait\Events\PairingConfirmed;
use Ctrlweb\SitePortrait\Events\PairingRevoked;
use Ctrlweb\SitePortrait\Models\Nonce;
use Ctrlweb\SitePortrait\Models\Pairing;
use Ctrlweb\SitePortrait\Protocol\Crypto;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * Pairing lifecycle: start, completion, confirmation, scopes, key rotation
 * and revocation (PROTOCOL.md §4, §10, §11).
 */
class PairingManager
{
    public const PENDING_TTL = 15 * 60;

    public const KEY_GRACE_PERIOD = 7 * 86400;

    public const KEY_REFRESH_SPACING = 3600;

    public const PAIRING_ID_RE = '/^[A-Za-z0-9._-]{1,64}$/';

    public const REVOCATION_REASONS = ['revoked_by_site', 'plugin_uninstalled', 'key_compromised'];

    public function __construct(
        protected SitePortrait $sitePortrait,
        protected ServiceClient $client,
    ) {}

    /**
     * The active pairing, or null. Never cached: this service is a singleton
     * and may live across requests (Octane, queue workers).
     */
    public function active(): ?Pairing
    {
        return Pairing::query()->active()->latest('id')->first();
    }

    public function isActive(): bool
    {
        return $this->active() !== null;
    }

    /**
     * Starts a pairing (§4.1–4.2).
     *
     * @param  array<string, mixed>  $discovery  Output of ServiceClient::discover().
     * @param  list<string>  $scopes  Scopes granted by the administrator.
     * @return array{authorization_url: string, pairing: Pairing}
     */
    public function begin(array $discovery, array $scopes): array
    {
        $scopes = array_values(array_intersect($this->sitePortrait->sanitizeScopes($scopes), $discovery['scopes_supported']));
        if ($scopes === []) {
            throw new PairingException('no_scope', 'Select at least one category of data to share.');
        }
        if ($this->isActive()) {
            throw new PairingException('already_paired', 'This application is already connected to a service. Disconnect it first.');
        }

        $keys = Crypto::generateKeypair();
        $kid = Crypto::thumbprint($keys['public']);
        $verifier = Crypto::randomToken(32);
        $state = Crypto::randomToken(32);
        $token = Crypto::randomToken(32);
        $redirect = $this->sitePortrait->callbackUrl($token);

        $pairing = DB::connection((new Pairing)->getConnectionName())->transaction(function () use ($discovery, $scopes, $keys, $kid, $verifier, $state, $token, $redirect) {
            // A single authorization can be in progress.
            Pairing::query()->where('status', Pairing::PENDING)->delete();

            return Pairing::query()->create([
                'status' => Pairing::PENDING,
                'service' => $discovery,
                'scopes' => $scopes,
                'site_key_kid' => $kid,
                'site_key_public' => Crypto::b64urlEncode($keys['public']),
                'site_key_secret' => Crypto::b64urlEncode($keys['secret']),
                'callback_token_hash' => hash('sha256', $token),
                'state_hash' => hash('sha256', $state),
                'code_verifier' => $verifier,
                'redirect_uri' => $redirect,
                'expires_at' => Carbon::now()->addSeconds(self::PENDING_TTL),
            ]);
        });

        $params = [
            'response_type' => 'code',
            'client_id' => $this->sitePortrait->origin(),
            'redirect_uri' => $redirect,
            'state' => $state,
            'code_challenge' => Crypto::pkceChallenge($verifier),
            'code_challenge_method' => 'S256',
            'scope' => implode(' ', $scopes),
            'site_key_thumbprint' => $kid,
            'site_name' => $this->sitePortrait->siteName(),
            'protocol_version' => SitePortrait::PROTOCOL_VERSION,
        ];
        $endpoint = (string) $discovery['authorization_endpoint'];
        $url = $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return ['authorization_url' => $url, 'pairing' => $pairing];
    }

    /**
     * Completes the pairing when the browser comes back (§4.3–4.4).
     */
    public function complete(string $token, mixed $code, mixed $state): Pairing
    {
        $pending = $token === '' ? null : Pairing::query()
            ->where('status', Pairing::PENDING)
            ->where('callback_token_hash', hash('sha256', $token))
            ->first();
        // Single use: the pending pairing is discarded whatever happens next.
        $pending?->delete();

        if ($pending === null || $pending->expires_at === null || $pending->expires_at->isPast()
            || ! is_string($state) || ! hash_equals((string) $pending->state_hash, hash('sha256', $state))) {
            throw new PairingException('state_mismatch', 'The connection request expired or was not started from this application. Please start again.');
        }
        if (! is_string($code) || $code === '' || strlen($code) > 512) {
            throw new PairingException('invalid_code', 'The service returned an invalid authorization code.');
        }
        if ($this->isActive()) {
            throw new PairingException('already_paired', 'This application is already connected to a service. Disconnect it first.');
        }

        $discovery = $pending->service;
        $response = $this->client->request('POST', $discovery['token_endpoint'], [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => $pending->code_verifier,
            'client_id' => $this->sitePortrait->origin(),
            'redirect_uri' => $pending->redirect_uri,
            'site_jwk' => Crypto::publicJwk($pending->sitePublicKey()),
            'endpoints' => $this->sitePortrait->endpoints(),
            'mode' => 'single',
            'scopes' => $pending->scopes,
            'platform' => $this->sitePortrait->platform(),
            'plugin_version' => $this->sitePortrait->version(),
            'protocol_version' => SitePortrait::PROTOCOL_VERSION,
        ], ['secret' => $pending->siteSecretKey(), 'kid' => $pending->site_key_kid]);

        if ($response['status'] !== 200) {
            throw ServiceClient::errorFromResponse($response, 'The code exchange with the service');
        }

        $data = json_decode($response['body'], true);
        if (! is_array($data) || ! is_string($data['pairing_id'] ?? null) || ! preg_match(self::PAIRING_ID_RE, $data['pairing_id'])) {
            throw new PairingException('invalid_token_response', 'The service returned an invalid response (pairing_id).');
        }

        $scopes = isset($data['scopes'])
            ? array_values(array_intersect($pending->scopes, $this->sitePortrait->sanitizeScopes($data['scopes'])))
            : $pending->scopes;
        if ($scopes === []) {
            throw new PairingException('invalid_token_response', 'The service returned an invalid response (scopes).');
        }

        // Pin only keys that were also published in the discovery document.
        $serviceKeys = [];
        foreach (ServiceClient::parseJwks($data['jwks'] ?? null) as $kid => $jwk) {
            if (isset($discovery['keys'][$kid])) {
                $serviceKeys[$kid] = $jwk['x'];
            }
        }
        if ($serviceKeys === []) {
            throw new PairingException('invalid_token_response', 'The service returned keys that do not match its discovery document.');
        }

        unset($discovery['keys'], $discovery['scopes_requested'], $discovery['scope_reasons']);

        $pairing = Pairing::query()->create([
            'status' => Pairing::ACTIVE,
            'pairing_id' => $data['pairing_id'],
            'service' => $discovery,
            'service_keys' => $serviceKeys,
            'scopes' => $scopes,
            'site_key_kid' => $pending->site_key_kid,
            'site_key_public' => $pending->site_key_public,
            'site_key_secret' => $pending->site_key_secret,
            'site_key_endorsements' => [],
            'previous_site_keys' => [],
            'account_hint' => is_string($data['account_hint'] ?? null) ? ServiceClient::text($data['account_hint'], 100) : null,
            'connected_at' => Carbon::now(),
            'keys_refreshed_at' => Carbon::now(),
        ]);
        Nonce::clear();

        event(new PairingCompleted($pairing));

        return $pairing;
    }

    /** Records the first successful status call (§4.5). */
    public function markConfirmed(): void
    {
        $pairing = $this->active();
        if ($pairing !== null && $pairing->confirmed_at === null) {
            $pairing->forceFill(['confirmed_at' => Carbon::now()])->save();
            event(new PairingConfirmed($pairing));
        }
    }

    /**
     * Updates the granted scopes (the service reads them from /status).
     *
     * @param  list<string>  $scopes
     */
    public function setScopes(array $scopes): Pairing
    {
        $pairing = $this->requireActive();
        $supported = (array) ($pairing->service['scopes_supported'] ?? []);
        $pairing->forceFill(['scopes' => array_values(array_intersect($this->sitePortrait->sanitizeScopes($scopes), $supported))])->save();

        return $pairing;
    }

    /**
     * Current site signing key.
     *
     * @return array{secret: string, kid: string}|null
     */
    public function siteSigner(): ?array
    {
        $pairing = $this->active();

        return $pairing === null ? null : ['secret' => $pairing->siteSecretKey(), 'kid' => $pairing->site_key_kid];
    }

    /**
     * Public site keys published in /status (current first).
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function siteJwks(): array
    {
        $pairing = $this->active();
        if ($pairing === null) {
            return ['keys' => []];
        }
        $current = Crypto::publicJwk($pairing->sitePublicKey());
        if (! empty($pairing->site_key_endorsements)) {
            $current['endorsements'] = $pairing->site_key_endorsements;
        }
        $keys = [$current];
        foreach ((array) $pairing->previous_site_keys as $previous) {
            if (Carbon::now()->getTimestamp() < $previous['retired_at'] + self::KEY_GRACE_PERIOD) {
                $keys[] = Crypto::publicJwk((string) Crypto::b64urlDecode($previous['public']));
            }
        }

        return ['keys' => $keys];
    }

    /** Replaces the site key by a new one endorsed by the current key (§11.2). */
    public function rotateSiteKey(): Pairing
    {
        $pairing = $this->requireActive();
        $now = Carbon::now()->getTimestamp();
        $keys = Crypto::generateKeypair();
        $kid = Crypto::thumbprint($keys['public']);

        $previous = array_values(array_filter(
            (array) $pairing->previous_site_keys,
            fn (array $p) => $now < $p['retired_at'] + self::KEY_GRACE_PERIOD,
        ));
        array_unshift($previous, ['kid' => $pairing->site_key_kid, 'public' => $pairing->site_key_public, 'retired_at' => $now]);

        $pairing->forceFill([
            'previous_site_keys' => $previous,
            'site_key_kid' => $kid,
            'site_key_public' => Crypto::b64urlEncode($keys['public']),
            'site_key_secret' => Crypto::b64urlEncode($keys['secret']),
            'site_key_endorsements' => [Crypto::endorse($kid, $pairing->siteSecretKey(), $pairing->site_key_kid)],
        ])->save();

        return $pairing;
    }

    /**
     * Raw public key of a pinned service key, refreshing the pinned set from
     * discovery when the key id is unknown (§11.1).
     */
    public function serviceKey(string $kid): ?string
    {
        $pairing = $this->active();
        if ($pairing === null) {
            return null;
        }
        if (! isset($pairing->service_keys[$kid]) && $this->refreshServiceKeys()) {
            $pairing = $this->active();
        }
        $x = $pairing?->service_keys[$kid] ?? null;

        return $x === null ? null : Crypto::b64urlDecode($x);
    }

    /**
     * Re-reads the discovery document and pins endorsed keys, at most once per hour.
     */
    public function refreshServiceKeys(): bool
    {
        $pairing = $this->active();
        $interval = max(0, (int) config('site-portrait.key_refresh_interval', self::KEY_REFRESH_SPACING));
        if ($pairing === null || ($pairing->keys_refreshed_at !== null && $pairing->keys_refreshed_at->getTimestamp() + $interval > Carbon::now()->getTimestamp())) {
            return false;
        }
        $pairing->forceFill(['keys_refreshed_at' => Carbon::now()])->save();

        try {
            $discovery = $this->client->discover((string) $pairing->service['origin']);
        } catch (PairingException) {
            return false;
        }

        $trusted = [];
        foreach ((array) $pairing->service_keys as $kid => $x) {
            $trusted[$kid] = (string) Crypto::b64urlDecode($x);
        }

        $pinned = [];
        foreach ($discovery['keys'] as $kid => $jwk) {
            if (isset($trusted[$kid]) || Crypto::isEndorsed($jwk, $trusted)) {
                $pinned[$kid] = $jwk['x'];
            }
        }
        if ($pinned === [] || array_keys($pinned) === array_keys((array) $pairing->service_keys)) {
            return false;
        }

        $pairing->forceFill(['service_keys' => $pinned])->save();

        return true;
    }

    /**
     * Disconnects: local revocation first, then a best-effort notice to the
     * service (§10.1). Throws when the service could not be notified; the
     * local revocation is done in any case.
     */
    public function disconnect(string $reason = 'revoked_by_site', int $timeout = 10): void
    {
        if (! in_array($reason, self::REVOCATION_REASONS, true)) {
            throw new \InvalidArgumentException('Invalid revocation reason.');
        }
        $pairing = $this->active();
        if ($pairing === null) {
            return;
        }
        $signer = ['secret' => $pairing->siteSecretKey(), 'kid' => $pairing->site_key_kid];
        $this->forget();

        $response = $this->client->request('POST', (string) $pairing->service['revocation_endpoint'], [
            'pairing_id' => $pairing->pairing_id,
            'client_id' => $this->sitePortrait->origin(),
            'reason' => $reason,
        ], $signer, $timeout);
        if ($response['status'] !== 200) {
            throw ServiceClient::errorFromResponse($response, 'Notifying the service');
        }
    }

    /** Deletes the pairing locally (keys included) without notifying anyone. */
    public function forget(): void
    {
        $pairing = $this->active();
        Pairing::query()->delete();
        Nonce::clear();

        if ($pairing !== null) {
            event(new PairingRevoked($pairing));
        }
    }

    protected function requireActive(): Pairing
    {
        return $this->active() ?? throw new PairingException('not_paired', 'This application is not connected to a service.');
    }
}
