<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Events;

use Ctrlweb\SitePortrait\Models\Pairing;
use Illuminate\Foundation\Events\Dispatchable;

/** The code exchange succeeded; the service has not confirmed yet. */
class PairingCompleted
{
    use Dispatchable;

    public function __construct(public readonly Pairing $pairing) {}
}
