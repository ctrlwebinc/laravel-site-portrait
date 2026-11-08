<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * Signature verification failure, carrying a protocol error code (§9).
 */
final class SignatureException extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status = 401,
    ) {
        parent::__construct($message);
    }
}
