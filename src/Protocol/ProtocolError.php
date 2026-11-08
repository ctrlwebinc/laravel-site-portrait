<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * Error returned by the site API, serialised in the REST format of §9:
 * {"code": "...", "message": "...", "data": {"status": 400}}.
 */
final class ProtocolError extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct($message);
    }

    public static function fromSignature(SignatureException $e): self
    {
        return new self($e->errorCode, $e->getMessage(), $e->status);
    }

    /**
     * @return array{code: string, message: string, data: array{status: int}}
     */
    public function toArray(): array
    {
        return ['code' => $this->errorCode, 'message' => $this->getMessage(), 'data' => ['status' => $this->status]];
    }
}
