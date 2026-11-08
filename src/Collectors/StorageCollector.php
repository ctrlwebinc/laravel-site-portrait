<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Ctrlweb\SitePortrait\Support\DirectorySize;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Carbon;

/**
 * Scope "storage": sizes of the application directories and of the local
 * filesystem disks, computed under a time budget and cached. Remote disks
 * (S3…) are never listed. No paths are returned.
 */
class StorageCollector implements Collector
{
    public const CACHE_KEY = 'site-portrait:storage-sizes';

    public function __construct(protected Cache $cache) {}

    public function collect(CollectContext $context): array
    {
        $ttl = (int) config('site-portrait.size_cache_ttl', 3600);
        try {
            $cached = $this->cache->get(self::CACHE_KEY);
        } catch (\Throwable) {
            $cached = null;
        }
        // Entries cached by a version without file counts are recomputed.
        if (! is_array($cached) || ! isset($cached['sizes'], $cached['files'], $cached['disks'], $cached['timeout'])) {
            $cached = $this->compute();
            if (! $cached['timeout']) {
                try {
                    $this->cache->put(self::CACHE_KEY, $cached, $ttl);
                } catch (\Throwable) {
                    // An unavailable cache only costs a recomputation.
                }
            }
        }

        if ($cached['timeout']) {
            $context->warn('sizes', 'timeout', 'The time budget for directory sizes was exceeded; remaining sizes are null.');
        }

        return [
            'sizes' => $cached['sizes'],
            'files' => $cached['files'],
            'disks' => $cached['disks'],
        ];
    }

    /**
     * @return array{sizes: array<string, int|string|null>, files: array<string, int|string|null>, disks: list<array<string, mixed>>, timeout: bool}
     */
    protected function compute(): array
    {
        $budget = new DirectorySize((float) config('site-portrait.size_budget', 10));
        $timeout = false;
        $fileCounts = [];
        $measure = function (string $path, ?string $countAs = null) use ($budget, &$timeout, &$fileCounts): ?int {
            $result = $budget->measure($path);
            $timeout = $timeout || $result['timeout'];
            if ($countAs !== null) {
                $fileCounts[$countAs] = $result['files'];
            }

            return $result['size'];
        };

        $sizes = [
            'app' => $measure(storage_path('app'), 'app'),
            'app_public' => $measure(storage_path('app/public'), 'app_public'),
            'logs' => $measure(storage_path('logs')),
            'framework_cache' => $measure(storage_path('framework/cache')),
            'framework_sessions' => $measure(storage_path('framework/sessions')),
            'framework_views' => $measure(storage_path('framework/views')),
            'public' => $measure(public_path(), 'public'),
            'vendor' => $measure(base_path('vendor')),
            'node_modules' => $measure(base_path('node_modules')),
            'computed_at' => Carbon::now('UTC')->format('Y-m-d\TH:i:s\Z'),
        ];
        $files = [
            'app' => $fileCounts['app'] ?? null,
            'app_public' => $fileCounts['app_public'] ?? null,
            'public' => $fileCounts['public'] ?? null,
            'computed_at' => $sizes['computed_at'],
        ];

        $default = config('filesystems.default');
        $disks = [];
        foreach ((array) config('filesystems.disks', []) as $name => $disk) {
            if (! is_string($name) || ! is_array($disk)) {
                continue;
            }
            $driver = is_string($disk['driver'] ?? null) && preg_match('/^[a-z0-9_-]{1,32}$/', $disk['driver']) ? $disk['driver'] : 'custom';
            $size = null;
            if ($driver === 'local' && is_string($disk['root'] ?? null)) {
                $size = $measure($disk['root']);
            }
            $disks[] = [
                'name' => mb_substr($name, 0, 64),
                'driver' => $driver,
                'default' => $name === $default,
                'size' => $size,
            ];
        }

        return ['sizes' => $sizes, 'files' => $files, 'disks' => $disks, 'timeout' => $timeout];
    }
}
