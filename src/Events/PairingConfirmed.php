<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Events;

use Ctrlweb\SitePortrait\Models\Pairing;
use Illuminate\Foundation\Events\Dispatchable;

/** The service called /status for the first time (PROTOCOL.md §4.5). */
class PairingConfirmed
{
    use Dispatchable;

    public function __construct(public readonly Pairing $pairing) {}
}
