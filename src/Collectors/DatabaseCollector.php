<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;

/**
 * Scope "database": engine, version, sizes and largest tables of the
 * configured connection. No credentials, host, database name or table prefix.
 * The WordPress-only members (options, transients_count, tables.site_count)
 * are null.
 */
class DatabaseCollector implements Collector
{
    public function __construct(protected DatabaseManager $db) {}

    public function collect(CollectContext $context): array
    {
        $connection = $this->db->connection(config('site-portrait.database_connection'));
        $driver = $connection->getDriverName();
        $engine = $this->engine($connection, $driver);

        $tables = null;
        try {
            $tables = $this->tableStats($connection, $driver);
        } catch (\Throwable) {
            $tables = null;
        }

        $size = ['data' => null, 'index' => null, 'total' => null];
        if ($tables !== null && $driver !== 'sqlite') {
            $size['data'] = array_sum(array_map(fn ($t) => (int) $t['data'], $tables));
            $size['index'] = array_sum(array_map(fn ($t) => (int) $t['index'], $tables));
            $size['total'] = $size['data'] + $size['index'];
        } elseif ($driver === 'sqlite') {
            $file = (string) $connection->getConfig('database');
            if ($file !== '' && $file !== ':memory:' && @is_file($file)) {
                $size['total'] = (int) filesize($file);
            }
        }
        if ($size['total'] === null) {
            $context->warn('size', 'unavailable', 'Table statistics are not available for this database engine.');
        }

        $prefix = $connection->getTablePrefix();
        $largest = [];
        if ($tables !== null) {
            usort($tables, fn ($a, $b) => ((int) $b['data'] + (int) $b['index']) <=> ((int) $a['data'] + (int) $a['index']));
            foreach (array_slice($tables, 0, 10) as $table) {
                if ($prefix !== '' && str_starts_with($table['name'], $prefix)) {
                    $table['name'] = substr($table['name'], strlen($prefix));
                }
                $largest[] = $table;
            }
        }

        return [
            'engine' => $engine,
            'server_version' => $this->serverVersion($connection, $driver),
            'client' => $this->client($connection, $driver),
            'charset' => $this->stringOrNull($connection->getConfig('charset')),
            'collate' => $this->stringOrNull($connection->getConfig('collation')),
            'size' => $size,
            'tables' => [
                'count' => $tables === null ? null : count($tables),
                'site_count' => null,
                'largest' => $largest,
            ],
            'options' => ['count' => null, 'autoload_count' => null, 'autoload_size' => null],
            'transients_count' => null,
            'variables' => (object) $this->variables($connection, $driver),
        ];
    }

    protected function engine(Connection $connection, string $driver): string
    {
        return match ($driver) {
            'mysql', 'mariadb' => $driver === 'mariadb' || stripos((string) $this->rawServerVersion($connection), 'mariadb') !== false ? 'mariadb' : 'mysql',
            'sqlite' => 'sqlite',
            'pgsql' => 'pgsql',
            'sqlsrv' => 'sqlsrv',
            default => 'other',
        };
    }

    protected function rawServerVersion(Connection $connection): ?string
    {
        try {
            return (string) $connection->getPdo()->getAttribute(\PDO::ATTR_SERVER_VERSION);
        } catch (\Throwable) {
            return null;
        }
    }

    protected function serverVersion(Connection $connection, string $driver): ?string
    {
        if ($driver === 'sqlite') {
            try {
                return (string) $connection->scalar('select sqlite_version()');
            } catch (\Throwable) {
                return null;
            }
        }
        // MariaDB may report a "5.5.5-" compatibility prefix.
        $info = (string) preg_replace('/^5\.5\.5-/', '', (string) $this->rawServerVersion($connection));

        return preg_match('/^\d+(\.\d+){1,2}/', $info, $m) ? $m[0] : null;
    }

    protected function client(Connection $connection, string $driver): ?string
    {
        try {
            $version = $connection->getPdo()->getAttribute(\PDO::ATTR_CLIENT_VERSION);
        } catch (\Throwable) {
            return null;
        }
        if (! is_string($version) || $version === '') {
            return null;
        }
        // mysqlnd reports "mysqlnd 8.3.12 - …"; keep the name and version only.
        if (preg_match('/^(mysqlnd)\s+([\d.]+)/', $version, $m)) {
            return $m[1].' '.$m[2];
        }

        return 'pdo_'.$driver.' '.mb_substr($version, 0, 40);
    }

    /**
     * @return list<array{name: string, engine: string|null, rows: int|null, data: int|null, index: int|null}>|null
     */
    protected function tableStats(Connection $connection, string $driver): ?array
    {
        $rows = match ($driver) {
            'mysql', 'mariadb' => $connection->select(
                'SELECT TABLE_NAME AS name, ENGINE AS engine, TABLE_ROWS AS row_count, DATA_LENGTH AS data_length, INDEX_LENGTH AS index_length
                 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = ?',
                ['BASE TABLE'],
            ),
            'pgsql' => $connection->select(
                "SELECT c.relname AS name, NULL AS engine, GREATEST(c.reltuples, 0)::bigint AS row_count,
                        pg_relation_size(c.oid) AS data_length, pg_indexes_size(c.oid) AS index_length
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE c.relkind IN ('r', 'p') AND n.nspname = current_schema()"
            ),
            'sqlite' => $connection->select(
                "SELECT name, NULL AS engine, NULL AS row_count, NULL AS data_length, NULL AS index_length
                 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ),
            default => null,
        };
        if ($rows === null || $rows === []) {
            return null;
        }

        $tables = [];
        foreach ($rows as $row) {
            $row = (array) $row;
            $tables[] = [
                'name' => (string) $row['name'],
                'engine' => $row['engine'] !== null ? (string) $row['engine'] : null,
                'rows' => $row['row_count'] !== null ? (int) $row['row_count'] : null,
                'data' => $row['data_length'] !== null ? (int) $row['data_length'] : null,
                'index' => $row['index_length'] !== null ? (int) $row['index_length'] : null,
            ];
        }

        return $tables;
    }

    /**
     * @return array<string, int|null>
     */
    protected function variables(Connection $connection, string $driver): array
    {
        $names = ['max_connections', 'max_allowed_packet', 'innodb_buffer_pool_size'];
        $variables = array_fill_keys($names, null);

        try {
            if ($driver === 'mysql' || $driver === 'mariadb') {
                foreach ($connection->select("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections', 'max_allowed_packet', 'innodb_buffer_pool_size')") as $row) {
                    $row = array_change_key_case((array) $row, CASE_LOWER);
                    if (isset($row['variable_name']) && is_numeric($row['value'] ?? null)) {
                        $variables[$row['variable_name']] = (int) $row['value'];
                    }
                }
            } elseif ($driver === 'pgsql') {
                $value = $connection->scalar('SHOW max_connections');
                $variables['max_connections'] = is_numeric($value) ? (int) $value : null;
            }
        } catch (\Throwable) {
            // Not allowed or not supported: stays null.
        }

        return $variables;
    }

    protected function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? mb_substr($value, 0, 64) : null;
    }
}
