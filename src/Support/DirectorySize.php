<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Support;

/**
 * Directory sizes under a shared time budget. Symbolic links are not followed
 * (public/storage would otherwise be counted twice).
 */
final class DirectorySize
{
    private float $deadline;

    public function __construct(float $budgetSeconds)
    {
        $this->deadline = microtime(true) + max(0.0, $budgetSeconds);
    }

    /**
     * Depends on the clock: two calls may return different values.
     *
     * @phpstan-impure
     */
    public function expired(): bool
    {
        return microtime(true) >= $this->deadline;
    }

    /**
     * Size in bytes and number of regular files, both null when the directory
     * is absent, unreadable or out of budget.
     *
     * @return array{size: int|null, files: int|null, timeout: bool}
     */
    public function measure(string $path): array
    {
        if (! @is_dir($path) || @is_link($path)) {
            return ['size' => null, 'files' => null, 'timeout' => false];
        }
        if ($this->expired()) {
            return ['size' => null, 'files' => null, 'timeout' => true];
        }

        $size = 0;
        $files = 0;
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD,
            );
            $i = 0;
            foreach ($iterator as $file) {
                /** @var \SplFileInfo $file */
                if (++$i % 500 === 0 && $this->expired()) {
                    return ['size' => null, 'files' => null, 'timeout' => true];
                }
                if ($file->isLink() || ! $file->isFile()) {
                    continue;
                }
                $size += (int) $file->getSize();
                $files++;
            }
        } catch (\Throwable) {
            return ['size' => null, 'files' => null, 'timeout' => false];
        }

        return ['size' => $size, 'files' => $files, 'timeout' => false];
    }
}
