<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

/**
 * Collection context of one scope: warnings and shared time budget.
 */
final class CollectContext
{
    public const CODES = ['unavailable', 'timeout', 'partial', 'permission_denied', 'collector_error'];

    /** @var list<array{scope: string, field: string|null, code: string, message: string}> */
    private array $warnings = [];

    public function __construct(public string $scope = '') {}

    public function forScope(string $scope): self
    {
        $this->scope = $scope;

        return $this;
    }

    public function warn(?string $field, string $code, string $message): void
    {
        if (! in_array($code, self::CODES, true)) {
            $code = 'collector_error';
        }
        $this->warnings[] = ['scope' => $this->scope, 'field' => $field, 'code' => $code, 'message' => $message];
    }

    /**
     * @return list<array{scope: string, field: string|null, code: string, message: string}>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }
}
