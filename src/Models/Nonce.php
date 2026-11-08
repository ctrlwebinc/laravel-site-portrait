<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;

/**
 * Replay protection (PROTOCOL.md §5.4): (kid, nonce) pairs seen recently.
 *
 * @property string $kid
 * @property string $nonce
 * @property Carbon $expires_at
 */
class Nonce extends Model
{
    use MassPrunable;

    public $timestamps = false;

    protected $table = 'site_portrait_nonces';

    protected $guarded = [];

    public function getConnectionName(): ?string
    {
        return config('site-portrait.storage_connection') ?? parent::getConnectionName();
    }

    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }

    /**
     * Records a nonce atomically. Returns false if it was already used.
     */
    public static function consume(string $kid, string $nonce, int $signatureExpires): bool
    {
        // Keep it at least expires - now + 60 seconds.
        $keepUntil = max($signatureExpires, Carbon::now()->getTimestamp()) + 60;

        try {
            static::query()->create([
                'kid' => $kid,
                'nonce' => $nonce,
                'expires_at' => Carbon::createFromTimestamp($keepUntil),
            ]);
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        if (random_int(1, 50) === 1) {
            static::query()->where('expires_at', '<', Carbon::now())->delete();
        }

        return true;
    }

    public static function clear(): void
    {
        static::query()->delete();
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('expires_at', '<', Carbon::now());
    }
}
