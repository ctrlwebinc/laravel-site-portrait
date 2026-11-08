<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Portrait;

use Ctrlweb\SitePortrait\Collectors\CollectContext;
use Ctrlweb\SitePortrait\Collectors\Collector;
use Ctrlweb\SitePortrait\SitePortrait;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Carbon;

/**
 * Builds the portrait document (PROTOCOL.md §8).
 */
class PortraitBuilder
{
    public function __construct(
        protected Container $container,
        protected SitePortrait $sitePortrait,
    ) {}

    /**
     * @param  list<string>  $scopes  Scopes to return.
     * @param  list<string>  $denied  Requested but not granted.
     * @return array<string, mixed>
     */
    public function build(array $scopes, array $denied = [], string $pairingId = 'local'): array
    {
        $start = hrtime(true);
        $context = new CollectContext;
        $data = [];

        foreach ($scopes as $scope) {
            $context->forScope($scope);
            $data[$scope] = $this->collectScope($scope, $context);
        }

        return [
            'schema_version' => SitePortrait::SCHEMA_VERSION,
            'protocol_version' => SitePortrait::PROTOCOL_VERSION,
            'generated_at' => Carbon::now('UTC')->format('Y-m-d\TH:i:s\Z'),
            'generation_time_ms' => (int) round((hrtime(true) - $start) / 1e6),
            'pairing_id' => $pairingId,
            'mode' => 'single',
            'site_id' => null,
            'site' => [
                'home_url' => $this->sitePortrait->siteUrl(),
                'site_url' => $this->sitePortrait->siteUrl(),
                'name' => $this->sitePortrait->siteName(),
            ],
            'platform' => $this->sitePortrait->platform(),
            'plugin' => ['version' => $this->sitePortrait->version()],
            'scopes_returned' => array_values($scopes),
            'scopes_denied' => array_values($denied),
            'data' => (object) $data,
            'warnings' => $context->warnings(),
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function collectScope(string $scope, CollectContext $context): ?array
    {
        $class = config('site-portrait.scopes.'.$scope);

        try {
            $collector = is_string($class) ? $this->container->make($class) : null;
            if (! $collector instanceof Collector) {
                throw new \RuntimeException('No collector for this scope.');
            }
            $result = $collector->collect($context);
        } catch (\Throwable $e) {
            report($e);
            $context->warn(null, 'collector_error', 'The data of this scope could not be collected.');

            return null;
        }

        $extensions = [];
        foreach ($this->sitePortrait->extensions($scope) as $slug => $callback) {
            try {
                $value = $callback($context);
                if (is_array($value)) {
                    $extensions[$slug] = $value;
                }
            } catch (\Throwable $e) {
                report($e);
                $context->warn('extensions.'.$slug, 'collector_error', 'An extension failed.');
            }
        }
        if ($extensions !== []) {
            $result['extensions'] = $extensions;
        }

        return $result;
    }
}
