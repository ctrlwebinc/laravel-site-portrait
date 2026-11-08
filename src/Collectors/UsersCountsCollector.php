<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Collectors;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;

/**
 * Scope "users_counts": number of users of the default auth provider, and
 * per role when spatie/laravel-permission is used. Counts only.
 */
class UsersCountsCollector implements Collector
{
    public function __construct(protected DatabaseManager $db) {}

    public function collect(CollectContext $context): array
    {
        $guard = (string) config('auth.defaults.guard', 'web');
        $providerName = (string) config("auth.guards.$guard.provider", 'users');
        $provider = (array) config("auth.providers.$providerName", []);

        $model = null;
        $query = null;
        if (($provider['driver'] ?? null) === 'eloquent' && is_string($provider['model'] ?? null) && is_subclass_of($provider['model'], Model::class)) {
            $model = new $provider['model'];
            $query = $model->newQuery()->withoutGlobalScopes();
        } elseif (($provider['driver'] ?? null) === 'database' && is_string($provider['table'] ?? null)) {
            $query = $this->db->connection($provider['connection'] ?? null)->table($provider['table']);
        }

        if ($query === null) {
            $context->warn('total', 'unavailable', 'No database-backed user provider is configured.');

            return ['total' => 0, 'by_role' => (object) []];
        }

        $total = (int) $query->count();

        return ['total' => $total, 'by_role' => (object) $this->byRole($model, $total, $context)];
    }

    /**
     * @return array<string, int>
     */
    protected function byRole(?Model $model, int $total, CollectContext $context): array
    {
        $tables = (array) config('permission.table_names', []);
        if ($model === null || ! isset($tables['roles'], $tables['model_has_roles'])) {
            return $total > 0 ? ['none' => $total] : [];
        }

        try {
            $column = (string) config('permission.column_names.model_morph_key', 'model_id');
            $connection = $model->getConnection();
            $rows = $connection->table($tables['model_has_roles'].' as mhr')
                ->join($tables['roles'].' as r', 'r.id', '=', 'mhr.role_id')
                ->where('mhr.model_type', $model->getMorphClass())
                ->groupBy('r.name')
                ->selectRaw('r.name as role, count(*) as aggregate')
                ->get();

            $byRole = [];
            foreach ($rows as $row) {
                $role = strtolower((string) preg_replace('/[^A-Za-z0-9_-]+/', '_', (string) $row->role));
                $byRole[$role] = ($byRole[$role] ?? 0) + (int) $row->aggregate;
            }
            $withRole = (int) $connection->table($tables['model_has_roles'])
                ->where('model_type', $model->getMorphClass())
                ->distinct()
                ->count($column);
            if ($total - $withRole > 0) {
                $byRole['none'] = $total - $withRole;
            }
            ksort($byRole);

            return $byRole;
        } catch (\Throwable) {
            $context->warn('by_role', 'unavailable', 'Role tables could not be read.');

            return $total > 0 ? ['none' => $total] : [];
        }
    }
}
