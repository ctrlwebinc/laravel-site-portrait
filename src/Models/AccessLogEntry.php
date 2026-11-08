<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Access log of the endpoints (PROTOCOL.md §12.3), also backing the rate limits.
 *
 * @property int $id
 * @property Carbon $created_at
 * @property string|null $ip
 * @property string $method
 * @property string $endpoint
 * @property string|null $key_id
 * @property list<string>|null $scopes
 * @property int $status
 * @property string|null $error_code
 * @property bool $authenticated
 */
class AccessLogEntry extends Model
{
    use MassPrunable;

    public const UPDATED_AT = null;

    protected $table = 'site_portrait_access_log';

    protected $guarded = [];

    public function getConnectionName(): ?string
    {
        return config('site-portrait.storage_connection') ?? parent::getConnectionName();
    }

    protected function casts(): array
    {
        return [
            'created_at' => 'datetime',
            'scopes' => 'array',
            'authenticated' => 'boolean',
            'status' => 'integer',
        ];
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public static function record(array $attributes): void
    {
        static::query()->create($attributes + ['created_at' => Carbon::now()]);

        if (random_int(1, 100) === 1) {
            static::trimToMaxEntries();
        }
    }

    public static function authenticatedLastHour(): int
    {
        return static::query()
            ->where('authenticated', true)
            ->where('created_at', '>', Carbon::now()->subHour())
            ->count();
    }

    public static function oldestAuthenticatedInWindow(): ?Carbon
    {
        $value = static::query()
            ->where('authenticated', true)
            ->where('created_at', '>', Carbon::now()->subHour())
            ->min('created_at');

        return $value === null ? null : Carbon::parse($value);
    }

    public static function failuresLastHour(string $ip): int
    {
        return static::query()
            ->where('authenticated', false)
            ->where('ip', $ip)
            ->where('created_at', '>', Carbon::now()->subHour())
            ->count();
    }

    public static function trimToMaxEntries(): void
    {
        $max = (int) config('site-portrait.access_log.max_entries', 10000);
        $threshold = static::query()->orderByDesc('id')->skip($max)->value('id');
        if ($threshold !== null) {
            static::query()->where('id', '<=', $threshold)->delete();
        }
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $days = (int) config('site-portrait.access_log.retention_days', 90);

        return static::query()->where('created_at', '<', Carbon::now()->subDays($days));
    }
}
