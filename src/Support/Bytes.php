<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Support;

final class Bytes
{
    /** Parses a php.ini size ("128M"); null when unlimited (-1) or invalid. */
    public static function fromIni(mixed $value): ?int
    {
        if (! is_string($value) && ! is_int($value)) {
            return null;
        }
        $value = trim((string) $value);
        if ($value === '' || $value === '-1') {
            return null;
        }
        if (! preg_match('/^(\d+)\s*([kmgt]?)b?$/i', $value, $m)) {
            return null;
        }
        $number = (int) $m[1];

        return match (strtolower($m[2])) {
            'k' => $number * 1024,
            'm' => $number * 1024 ** 2,
            'g' => $number * 1024 ** 3,
            't' => $number * 1024 ** 4,
            default => $number,
        };
    }

    public static function intOrNull(mixed $value): ?int
    {
        return $value === false || $value === null || ! is_numeric($value) ? null : (int) $value;
    }
}
