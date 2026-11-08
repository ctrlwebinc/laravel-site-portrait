<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Ctrlweb\SitePortrait\Support\Bytes;
use Ctrlweb\SitePortrait\Support\SystemInfo;
use Illuminate\Http\Request;

/**
 * Scope "server": OS, web server, PHP, CPU, memory, disk and libraries.
 * Same schema as the WordPress implementation; the disk is the volume of
 * storage_path(). No host names, IP addresses or paths.
 */
class ServerCollector implements Collector
{
    public function __construct(protected Request $request, protected ?SystemInfo $system = null) {}

    public function collect(CollectContext $context): array
    {
        $system = $this->system ?? new SystemInfo;
        $cpu = $system->cpu();
        $memory = $system->memory();

        if ($cpu['count'] === null) {
            $context->warn('cpu.count', 'unavailable', '/proc/cpuinfo is not readable.');
        }
        if ($memory['total'] === null) {
            $context->warn('memory.total', 'unavailable', '/proc/meminfo is not readable.');
        }

        $extensions = array_map('strtolower', get_loaded_extensions());
        sort($extensions);

        $load = function_exists('sys_getloadavg') ? sys_getloadavg() : false;
        $software = $this->request->server('SERVER_SOFTWARE');
        $protocol = $this->request->server('SERVER_PROTOCOL');
        $disk = storage_path();

        return [
            'os' => [
                'family' => PHP_OS_FAMILY,
                'architecture' => function_exists('php_uname') ? php_uname('m') : null,
                'containerized' => $system->containerized(),
            ],
            'web_server' => [
                'software' => is_string($software) && $software !== '' ? mb_substr(strip_tags($software), 0, 100) : null,
                'http2' => is_string($protocol) ? str_starts_with($protocol, 'HTTP/2') : null,
            ],
            'php' => [
                'version' => PHP_VERSION,
                'sapi' => PHP_SAPI,
                'bits' => PHP_INT_SIZE * 8,
                'extensions' => $extensions,
                'ini' => $this->ini(),
                'opcache' => $this->opcache(),
            ],
            'cpu' => [
                'count' => $cpu['count'],
                'model' => $cpu['model'],
                'cgroup_quota' => $cpu['cgroup_quota'],
                'load_average' => is_array($load) && count($load) === 3 ? array_map('floatval', $load) : null,
            ],
            'memory' => $memory,
            'disk' => [
                'free' => function_exists('disk_free_space') ? Bytes::intOrNull(@disk_free_space($disk)) : null,
                'total' => function_exists('disk_total_space') ? Bytes::intOrNull(@disk_total_space($disk)) : null,
            ],
            'libraries' => $this->libraries(),
        ];
    }

    /**
     * @return array<string, int|bool|null>
     */
    protected function ini(): array
    {
        $disabled = trim((string) ini_get('disable_functions'));

        return [
            'memory_limit' => Bytes::fromIni(ini_get('memory_limit')),
            'max_execution_time' => self::iniInt('max_execution_time'),
            'max_input_time' => self::iniSignedInt('max_input_time'),
            'max_input_vars' => self::iniInt('max_input_vars'),
            'post_max_size' => Bytes::fromIni(ini_get('post_max_size')),
            'upload_max_filesize' => Bytes::fromIni(ini_get('upload_max_filesize')),
            'max_file_uploads' => self::iniInt('max_file_uploads'),
            'allow_url_fopen' => self::iniBool('allow_url_fopen'),
            'display_errors' => self::iniBool('display_errors'),
            'disabled_functions_count' => $disabled === '' ? 0 : count(array_filter(array_map('trim', explode(',', $disabled)))),
        ];
    }

    /**
     * OPcache status, without the list of cached scripts (it contains paths).
     *
     * @return array<string, mixed>
     */
    protected function opcache(): array
    {
        $enabled = extension_loaded('Zend OPcache') && (bool) self::iniBool(PHP_SAPI === 'cli' ? 'opcache.enable_cli' : 'opcache.enable');
        $result = [
            'enabled' => $enabled,
            'jit' => null,
            'memory_size' => Bytes::fromIni(ini_get('opcache.memory_consumption').'M'),
            'memory_used' => null,
            'hit_rate' => null,
            'cached_scripts' => null,
        ];
        if (! $enabled || ! function_exists('opcache_get_status')) {
            return $result;
        }
        // opcache.restrict_api may forbid the call and emit a warning.
        $status = @opcache_get_status(false);
        if (! is_array($status)) {
            return $result;
        }
        $result['jit'] = isset($status['jit']['enabled']) ? (bool) $status['jit']['enabled'] : null;
        $result['memory_used'] = isset($status['memory_usage']['used_memory']) ? (int) $status['memory_usage']['used_memory'] : null;
        $result['hit_rate'] = isset($status['opcache_statistics']['opcache_hit_rate']) ? round((float) $status['opcache_statistics']['opcache_hit_rate'], 2) : null;
        $result['cached_scripts'] = isset($status['opcache_statistics']['num_cached_scripts']) ? (int) $status['opcache_statistics']['num_cached_scripts'] : null;

        return $result;
    }

    /**
     * @return array<string, string|null>
     */
    protected function libraries(): array
    {
        $curl = function_exists('curl_version') ? curl_version() : null;
        $gd = function_exists('gd_info') ? gd_info() : null;

        $imagick = null;
        if (class_exists(\Imagick::class)) {
            $version = \Imagick::getVersion();
            if (isset($version['versionString']) && preg_match('/ImageMagick\s+[\d.]+(-\d+)?/', $version['versionString'], $m)) {
                $imagick = $m[0];
            }
        }

        $sodium = extension_loaded('sodium') ? 'native' : (function_exists('sodium_crypto_sign_detached') ? 'polyfill' : null);

        return [
            'curl' => is_array($curl) && isset($curl['version']) ? (string) $curl['version'] : null,
            'openssl' => defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : null,
            'gd' => is_array($gd) && isset($gd['GD Version']) ? (string) $gd['GD Version'] : null,
            'imagick' => $imagick,
            'icu' => defined('INTL_ICU_VERSION') ? INTL_ICU_VERSION : null,
            'sodium' => $sodium,
        ];
    }

    protected static function iniInt(string $name): ?int
    {
        $value = ini_get($name);

        return is_string($value) && ctype_digit(trim($value)) ? (int) $value : null;
    }

    protected static function iniSignedInt(string $name): ?int
    {
        $value = ini_get($name);

        return is_string($value) && preg_match('/^-?\d+$/', trim($value)) ? (int) $value : null;
    }

    protected static function iniBool(string $name): ?bool
    {
        $value = ini_get($name);
        if ($value === false) {
            return null;
        }

        return in_array(strtolower(trim($value)), ['1', 'on', 'yes', 'true', 'stderr', 'stdout'], true);
    }
}
