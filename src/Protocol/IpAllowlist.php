<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * IP allow-list matching, IPv4 and IPv6 with CIDR (§12.2).
 */
final class IpAllowlist
{
    public static function isValidEntry(string $entry): bool
    {
        $parts = explode('/', $entry, 2);
        $ip = filter_var($parts[0], FILTER_VALIDATE_IP);
        if ($ip === false) {
            return false;
        }
        if (! isset($parts[1])) {
            return true;
        }
        $max = str_contains($ip, ':') ? 128 : 32;

        return ctype_digit($parts[1]) && (int) $parts[1] <= $max;
    }

    /**
     * @param  list<string>  $entries
     */
    public static function matches(string $ip, array $entries): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach ($entries as $entry) {
            if (! self::isValidEntry($entry)) {
                continue;
            }
            $parts = explode('/', $entry, 2);
            $subnet = @inet_pton($parts[0]);
            if ($subnet === false || strlen($subnet) !== strlen($packed)) {
                continue;
            }
            $bits = isset($parts[1]) ? (int) $parts[1] : strlen($packed) * 8;
            if (self::prefixEquals($packed, $subnet, $bits)) {
                return true;
            }
        }

        return false;
    }

    private static function prefixEquals(string $a, string $b, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }
}
