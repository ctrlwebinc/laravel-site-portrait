<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Models;

use Ctrlweb\SitePortrait\Protocol\Crypto;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The pairing of this application with a service (active), or an
 * authorization in progress (pending).
 *
 * @property int $id
 * @property string $status
 * @property string|null $pairing_id
 * @property array<string, mixed> $service
 * @property array<string, string>|null $service_keys kid => base64url public key
 * @property list<string> $scopes
 * @property string $site_key_kid
 * @property string $site_key_public base64url
 * @property string $site_key_secret base64url, encrypted at rest
 * @property list<array{kid: string, sig: string}>|null $site_key_endorsements
 * @property list<array{kid: string, public: string, retired_at: int}>|null $previous_site_keys
 * @property string|null $account_hint
 * @property string|null $callback_token_hash
 * @property string|null $state_hash
 * @property string|null $code_verifier
 * @property string|null $redirect_uri
 * @property Carbon|null $expires_at
 * @property Carbon|null $connected_at
 * @property Carbon|null $confirmed_at
 * @property Carbon|null $keys_refreshed_at
 */
class Pairing extends Model
{
    public const PENDING = 'pending';

    public const ACTIVE = 'active';

    protected $table = 'site_portrait_pairings';

    protected $guarded = [];

    protected $hidden = ['site_key_secret', 'code_verifier', 'callback_token_hash', 'state_hash'];

    public function getConnectionName(): ?string
    {
        return config('site-portrait.storage_connection') ?? parent::getConnectionName();
    }

    protected function casts(): array
    {
        return [
            'service' => 'array',
            'service_keys' => 'array',
            'scopes' => 'array',
            'site_key_secret' => 'encrypted',
            'site_key_endorsements' => 'array',
            'previous_site_keys' => 'array',
            'code_verifier' => 'encrypted',
            'expires_at' => 'datetime',
            'connected_at' => 'datetime',
            'confirmed_at' => 'datetime',
            'keys_refreshed_at' => 'datetime',
        ];
    }

    /**
     * @param  Builder<Pairing>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->where('status', self::ACTIVE);
    }

    /** Raw secret key of the current site key. */
    public function siteSecretKey(): string
    {
        return (string) Crypto::b64urlDecode($this->site_key_secret);
    }

    /** Raw public key of the current site key. */
    public function sitePublicKey(): string
    {
        return (string) Crypto::b64urlDecode($this->site_key_public);
    }
}
