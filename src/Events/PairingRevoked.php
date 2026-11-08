<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Events;

use Ctrlweb\SitePortrait\Models\Pairing;
use Illuminate\Foundation\Events\Dispatchable;

/** The pairing was deleted (by the administrator or by the service). */
class PairingRevoked
{
    use Dispatchable;

    public function __construct(public readonly Pairing $pairing) {}
}
