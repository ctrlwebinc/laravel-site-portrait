<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Ctrlweb\SitePortrait\SitePortrait extend(string $scope, string $slug, \Closure $callback)
 * @method static \Ctrlweb\SitePortrait\SitePortrait resolveClientIpUsing(\Closure $resolver)
 * @method static string version()
 * @method static list<string> scopes()
 *
 * @see \Ctrlweb\SitePortrait\SitePortrait
 */
class SitePortrait extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Ctrlweb\SitePortrait\SitePortrait::class;
    }
}
