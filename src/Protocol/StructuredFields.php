<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * Minimal RFC 8941 (Structured Field Values) dictionary parser and serializer,
 * sufficient for the Signature-Input and Signature fields of RFC 9421.
 *
 * Items are arrays: ['type' => string, 'value' => mixed, 'params' => array].
 * Types: integer, decimal, string, token, bytes (raw binary), boolean and
 * inner_list (value is a list of items). Parameters map a key to
 * ['type' => string, 'value' => mixed].
 */
final class StructuredFields
{
    private int $pos = 0;

    private function __construct(private readonly string $input) {}

    /**
     * @return array<string, array<string, mixed>>|null Ordered map key => item, or null on syntax error.
     */
    public static function parseDictionary(mixed $input): ?array
    {
        if (! is_string($input)) {
            return null;
        }

        try {
            return (new self(trim($input, ' ')))->dictionary();
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    /**
     * @param  list<array<string, mixed>>  $items
     * @param  array<string, array{type: string, value: mixed}>  $params
     */
    public static function serializeInnerList(array $items, array $params): string
    {
        $parts = [];
        foreach ($items as $item) {
            $parts[] = self::serializeBare($item['type'], $item['value']).self::serializeParams($item['params'] ?? []);
        }

        return '('.implode(' ', $parts).')'.self::serializeParams($params);
    }

    /**
     * @param  array<string, array{type: string, value: mixed}>  $params
     */
    public static function serializeParams(array $params): string
    {
        $out = '';
        foreach ($params as $key => $param) {
            $out .= ';'.$key;
            if (! ($param['type'] === 'boolean' && $param['value'] === true)) {
                $out .= '='.self::serializeBare($param['type'], $param['value']);
            }
        }

        return $out;
    }

    public static function serializeBare(string $type, mixed $value): string
    {
        return match ($type) {
            'integer' => (string) (int) $value,
            'decimal' => rtrim(rtrim(number_format((float) $value, 3, '.', ''), '0'), '.'),
            'string' => self::serializeString((string) $value),
            'token' => (string) $value,
            'bytes' => ':'.base64_encode((string) $value).':',
            'boolean' => $value ? '?1' : '?0',
            default => throw new \InvalidArgumentException('Unsupported item type.'),
        };
    }

    /**
     * @param  array<string, array{type: string, value: mixed}>  $params
     * @return array{type: string, value: string, params: array<string, array{type: string, value: mixed}>}
     */
    public static function stringItem(string $value, array $params = []): array
    {
        return ['type' => 'string', 'value' => $value, 'params' => $params];
    }

    private static function serializeString(string $value): string
    {
        if (preg_match('/[^\x20-\x7e]/', $value)) {
            throw new \InvalidArgumentException('Invalid string item.');
        }

        return '"'.str_replace(['\\', '"'], ['\\\\', '\\"'], $value).'"';
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function dictionary(): array
    {
        $members = [];
        while (! $this->eof()) {
            $key = $this->key();
            if ($this->peek() === '=') {
                $this->pos++;
                $members[$key] = $this->peek() === '(' ? $this->innerList() : $this->item();
            } else {
                $members[$key] = ['type' => 'boolean', 'value' => true, 'params' => $this->parameters()];
            }
            $this->skipOws();
            if ($this->eof()) {
                break;
            }
            $this->expect(',');
            $this->skipOws();
            if ($this->eof()) {
                $this->fail();
            }
        }

        return $members;
    }

    /**
     * @return array<string, mixed>
     */
    private function innerList(): array
    {
        $this->expect('(');
        $items = [];
        while (! $this->eof()) {
            $this->skipSp();
            if ($this->peek() === ')') {
                $this->pos++;

                return ['type' => 'inner_list', 'value' => $items, 'params' => $this->parameters()];
            }
            $items[] = $this->item();
            $next = $this->peek();
            if ($next !== ' ' && $next !== ')') {
                $this->fail();
            }
        }
        $this->fail();
    }

    /**
     * @return array<string, mixed>
     */
    private function item(): array
    {
        $bare = $this->bareItem();
        $bare['params'] = $this->parameters();

        return $bare;
    }

    /**
     * @return array<string, array{type: string, value: mixed}>
     */
    private function parameters(): array
    {
        $params = [];
        while ($this->peek() === ';') {
            $this->pos++;
            $this->skipSp();
            $key = $this->key();
            if ($this->peek() === '=') {
                $this->pos++;
                $params[$key] = $this->bareItem();
            } else {
                $params[$key] = ['type' => 'boolean', 'value' => true];
            }
        }

        return $params;
    }

    private function key(): string
    {
        if (! preg_match('/\G[a-z*][a-z0-9_.*-]*/', $this->input, $m, 0, $this->pos)) {
            $this->fail();
        }
        $this->pos += strlen($m[0]);

        return $m[0];
    }

    /**
     * @return array{type: string, value: mixed}
     */
    private function bareItem(): array
    {
        $c = $this->peek();
        if ($c === '"') {
            return $this->string();
        }
        if ($c === ':') {
            return $this->bytes();
        }
        if ($c === '?') {
            return $this->boolean();
        }
        if (preg_match('/\G-?[0-9]{1,15}(\.[0-9]{1,3})?/', $this->input, $m, 0, $this->pos)) {
            $this->pos += strlen($m[0]);

            return isset($m[1])
                ? ['type' => 'decimal', 'value' => (float) $m[0]]
                : ['type' => 'integer', 'value' => (int) $m[0]];
        }
        if (preg_match('/\G[A-Za-z*][!#$%&\'*+\-.^_`|~0-9A-Za-z:\/]*/', $this->input, $m, 0, $this->pos)) {
            $this->pos += strlen($m[0]);

            return ['type' => 'token', 'value' => $m[0]];
        }
        $this->fail();
    }

    /**
     * @return array{type: string, value: string}
     */
    private function string(): array
    {
        $this->pos++;
        $out = '';
        $len = strlen($this->input);
        while ($this->pos < $len) {
            $c = $this->input[$this->pos++];
            if ($c === '\\') {
                $next = $this->pos < $len ? $this->input[$this->pos++] : '';
                if ($next !== '\\' && $next !== '"') {
                    $this->fail();
                }
                $out .= $next;
            } elseif ($c === '"') {
                return ['type' => 'string', 'value' => $out];
            } elseif (ord($c) < 0x20 || ord($c) > 0x7E) {
                $this->fail();
            } else {
                $out .= $c;
            }
        }
        $this->fail();
    }

    /**
     * @return array{type: string, value: string}
     */
    private function bytes(): array
    {
        if (! preg_match('/\G:([A-Za-z0-9+\/=]*):/', $this->input, $m, 0, $this->pos)) {
            $this->fail();
        }
        $this->pos += strlen($m[0]);
        $decoded = base64_decode($m[1], true);
        if ($decoded === false) {
            $this->fail();
        }

        return ['type' => 'bytes', 'value' => $decoded];
    }

    /**
     * @return array{type: string, value: bool}
     */
    private function boolean(): array
    {
        $token = substr($this->input, $this->pos, 2);
        if ($token !== '?1' && $token !== '?0') {
            $this->fail();
        }
        $this->pos += 2;

        return ['type' => 'boolean', 'value' => $token === '?1'];
    }

    private function peek(): string
    {
        return $this->input[$this->pos] ?? '';
    }

    private function eof(): bool
    {
        return $this->pos >= strlen($this->input);
    }

    private function expect(string $char): void
    {
        if ($this->peek() !== $char) {
            $this->fail();
        }
        $this->pos++;
    }

    private function skipSp(): void
    {
        while ($this->peek() === ' ') {
            $this->pos++;
        }
    }

    private function skipOws(): void
    {
        while ($this->peek() === ' ' || $this->peek() === "\t") {
            $this->pos++;
        }
    }

    private function fail(): never
    {
        throw new \UnexpectedValueException('Invalid structured field.');
    }
}
