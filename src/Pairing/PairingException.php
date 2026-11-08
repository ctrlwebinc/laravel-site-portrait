<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Pairing;

/**
 * Pairing or outbound call failure, with a message meant for the administrator.
 */
final class PairingException extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
