<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Support;

/**
 * Host and container resources from /proc and cgroup files (Linux), when
 * readable. Never executes commands. The root can point to a fixture directory.
 */
final class SystemInfo
{
    private string $root;

    public function __construct(string $root = '')
    {
        $this->root = rtrim($root, '/');
    }

    /**
     * @return array{count: int|null, model: string|null, cgroup_quota: float|null}
     */
    public function cpu(): array
    {
        $count = null;
        $model = null;
        $cpuinfo = $this->read('/proc/cpuinfo');
        if ($cpuinfo !== null) {
            $count = preg_match_all('/^processor\s*:/m', $cpuinfo) ?: null;
            // x86 "model name", MIPS "cpu model", ARM boards "Model"; x86 "model" is numeric.
            foreach (['/^model name\s*:\s*(.+)$/m', '/^cpu model\s*:\s*(.+)$/m', '/^Model\s*:\s*(.+)$/m'] as $pattern) {
                if (preg_match($pattern, $cpuinfo, $m)) {
                    $model = (string) preg_replace('/\s+/', ' ', trim($m[1]));
                    break;
                }
            }
        }

        return ['count' => $count, 'model' => $model, 'cgroup_quota' => $this->cgroupCpuQuota()];
    }

    /**
     * @return array{total: int|null, available: int|null, cgroup_limit: int|null, swap_total: int|null}
     */
    public function memory(): array
    {
        $info = [];
        $meminfo = $this->read('/proc/meminfo');
        if ($meminfo !== null && preg_match_all('/^(\w+):\s+(\d+)\s*kB$/m', $meminfo, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $info[$match[1]] = (int) $match[2] * 1024;
            }
        }

        return [
            'total' => $info['MemTotal'] ?? null,
            'available' => $info['MemAvailable'] ?? null,
            'cgroup_limit' => $this->cgroupMemoryLimit(),
            'swap_total' => $info['SwapTotal'] ?? null,
        ];
    }

    public function containerized(): ?bool
    {
        if ($this->isReadable('/.dockerenv') || $this->isReadable('/run/.containerenv')) {
            return true;
        }
        if ($this->cgroupCpuQuota() !== null || $this->cgroupMemoryLimit() !== null) {
            return true;
        }

        return $this->read('/proc/1/cgroup') === null ? null : false;
    }

    /** CPUs allowed by the cgroup (v2 cpu.max or v1 CFS quota); null if unlimited or unknown. */
    public function cgroupCpuQuota(): ?float
    {
        $max = $this->read('/sys/fs/cgroup/cpu.max');
        if ($max !== null && preg_match('/^(\d+)\s+(\d+)/', trim($max), $m) && (int) $m[2] > 0) {
            return round((int) $m[1] / (int) $m[2], 2);
        }
        $quota = $this->read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us');
        $period = $this->read('/sys/fs/cgroup/cpu/cpu.cfs_period_us');
        if ($quota !== null && $period !== null && (int) $quota > 0 && (int) $period > 0) {
            return round((int) $quota / (int) $period, 2);
        }

        return null;
    }

    /** Memory limit of the cgroup; null if unlimited or unknown. */
    public function cgroupMemoryLimit(): ?int
    {
        foreach (['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes'] as $file) {
            $value = $this->read($file);
            if ($value === null) {
                continue;
            }
            $value = trim($value);
            // cgroup v1 reports "unlimited" as a value close to PHP_INT_MAX.
            if (ctype_digit($value) && strlen($value) < 19) {
                return (int) $value;
            }

            return null;
        }

        return null;
    }

    private function read(string $path): ?string
    {
        if (! $this->isReadable($path)) {
            return null;
        }
        $content = @file_get_contents($this->root.$path, false, null, 0, 1048576);

        return $content === false || $content === '' ? null : $content;
    }

    /** Honours open_basedir to avoid warnings. */
    private function isReadable(string $path): bool
    {
        $full = $this->root.$path;
        $basedirs = (string) ini_get('open_basedir');
        if ($basedirs !== '') {
            $allowed = false;
            foreach (explode(PATH_SEPARATOR, $basedirs) as $dir) {
                if ($dir !== '' && str_starts_with($full, rtrim($dir, '/').'/')) {
                    $allowed = true;
                    break;
                }
            }
            if (! $allowed) {
                return false;
            }
        }

        return @is_file($full) && @is_readable($full);
    }
}
