<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

/**
 * Collects the data of one scope. Rules (PROTOCOL.md §8.3): read-only, no
 * network, no shell, never secrets, credentials, host names, IP addresses,
 * absolute paths or environment variables. Unknown values are null.
 */
interface Collector
{
    /**
     * @return array<string, mixed>
     */
    public function collect(CollectContext $context): array;
}
