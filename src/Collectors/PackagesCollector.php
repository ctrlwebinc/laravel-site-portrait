<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Composer\InstalledVersions;
use Illuminate\Support\Str;

/**
 * Scope "packages": installed Composer packages (name, version, type, direct,
 * dev). No repository URLs, no network call (hence no update information).
 */
class PackagesCollector implements Collector
{
    public function collect(CollectContext $context): array
    {
        $root = $this->rootRequirements();
        $hidden = array_values(array_filter((array) config('site-portrait.hidden_packages', []), 'is_string'));

        $items = [];
        $counts = ['total' => 0, 'direct' => 0, 'dev' => 0, 'direct_dev' => 0];
        $rootName = null;

        foreach (InstalledVersions::getAllRawData() as $dataset) {
            $rootName ??= $dataset['root']['name'] ?? null;
            foreach ($dataset['versions'] ?? [] as $name => $package) {
                // Entries without a version are virtual (provided / replaced).
                if (! isset($package['pretty_version']) || $name === $rootName || isset($items[$name])) {
                    continue;
                }
                $isDev = (bool) ($package['dev_requirement'] ?? false);
                $direct = isset($root['require'][$name]) || isset($root['require-dev'][$name]);
                $directDev = isset($root['require-dev'][$name]);

                $counts['total']++;
                $counts['direct'] += $direct ? 1 : 0;
                $counts['dev'] += $isDev ? 1 : 0;
                $counts['direct_dev'] += $directDev ? 1 : 0;

                if (Str::is($hidden, $name)) {
                    continue;
                }
                $items[$name] = [
                    'name' => (string) $name,
                    'version' => (string) $package['pretty_version'],
                    'type' => isset($package['type']) ? (string) $package['type'] : null,
                    'direct' => $direct,
                    'dev' => $isDev,
                ];
            }
        }
        ksort($items);

        if ($root === null) {
            $context->warn('counts.direct', 'unavailable', 'composer.json is not readable.');
        }

        $extensions = [];
        foreach (array_keys(($root['require'] ?? []) + ($root['require-dev'] ?? [])) as $requirement) {
            if (str_starts_with($requirement, 'ext-')) {
                $extensions[] = substr($requirement, 4);
            }
        }
        sort($extensions);

        return [
            'counts' => $counts,
            'items' => array_values($items),
            'platform' => [
                'php' => isset($root['require']['php']) && is_string($root['require']['php']) ? mb_substr($root['require']['php'], 0, 64) : null,
                'extensions' => array_values(array_unique($extensions)),
            ],
        ];
    }

    /**
     * Requirements of the root composer.json (only the require sections are used).
     *
     * @return array{require: array<string, string>, require-dev: array<string, string>}|null
     */
    protected function rootRequirements(): ?array
    {
        $file = base_path('composer.json');
        if (! @is_file($file) || ! @is_readable($file)) {
            return null;
        }
        $json = json_decode((string) @file_get_contents($file, false, null, 0, 1048576), true);
        if (! is_array($json)) {
            return null;
        }

        return [
            'require' => is_array($json['require'] ?? null) ? $json['require'] : [],
            'require-dev' => is_array($json['require-dev'] ?? null) ? $json['require-dev'] : [],
        ];
    }
}
