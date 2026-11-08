<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Protocol;

/**
 * Ed25519 keys, JWK helpers, PKCE, digests and key endorsements
 * (PROTOCOL.md §2, §4, §11). Free of Laravel dependencies.
 */
final class Crypto
{
    /** Prefix of the message signed to endorse a new key (§11). */
    public const ENDORSEMENT_PREFIX = 'site-portrait/1 key-endorsement ';

    public static function b64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64urlDecode(mixed $data): ?string
    {
        if (! is_string($data) || ! preg_match('/^[A-Za-z0-9_-]*$/', $data) || strlen($data) % 4 === 1) {
            return null;
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    public static function randomToken(int $bytes = 32): string
    {
        if ($bytes < 16) {
            throw new \InvalidArgumentException('Tokens need at least 128 bits of randomness.');
        }

        return self::b64urlEncode(random_bytes($bytes));
    }

    /**
     * @return array{public: string, secret: string} Raw binary keys.
     */
    public static function generateKeypair(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [
            'public' => sodium_crypto_sign_publickey($pair),
            'secret' => sodium_crypto_sign_secretkey($pair),
        ];
    }

    /**
     * @return array{public: string, secret: string} Raw binary keys derived from a 32-byte seed.
     */
    public static function keypairFromSeed(string $seed): array
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('An Ed25519 seed is 32 bytes long.');
        }
        $pair = sodium_crypto_sign_seed_keypair($seed);

        return [
            'public' => sodium_crypto_sign_publickey($pair),
            'secret' => sodium_crypto_sign_secretkey($pair),
        ];
    }

    /** RFC 7638 thumbprint of an Ed25519 public key, used as key id. */
    public static function thumbprint(string $publicKey): string
    {
        $canonical = '{"crv":"Ed25519","kty":"OKP","x":"'.self::b64urlEncode($publicKey).'"}';

        return self::b64urlEncode(hash('sha256', $canonical, true));
    }

    /**
     * @return array{kty: string, crv: string, x: string, kid: string}
     */
    public static function publicJwk(string $publicKey): array
    {
        return [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => self::b64urlEncode($publicKey),
            'kid' => self::thumbprint($publicKey),
        ];
    }

    /**
     * Raw public key of a JWK, or null when invalid. A present kid must equal the thumbprint.
     */
    public static function publicKeyFromJwk(mixed $jwk): ?string
    {
        if (! is_array($jwk) || ($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519' || ! isset($jwk['x'])) {
            return null;
        }
        $key = self::b64urlDecode($jwk['x']);
        if ($key === null || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return null;
        }
        if (isset($jwk['kid']) && ! hash_equals(self::thumbprint($key), (string) $jwk['kid'])) {
            return null;
        }

        return $key;
    }

    public static function sign(string $message, string $secretKey): string
    {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('Invalid Ed25519 secret key.');
        }

        return sodium_crypto_sign_detached($message, $secretKey);
    }

    /** Verifies a signature, never throwing. */
    public static function verify(mixed $signature, string $message, mixed $publicKey): bool
    {
        if (! is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || ! is_string($publicKey) || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Endorsement of a new key by a trusted key (§11).
     *
     * @return array{kid: string, sig: string}
     */
    public static function endorse(string $newKid, string $signerSecretKey, string $signerKid): array
    {
        return [
            'kid' => $signerKid,
            'sig' => self::b64urlEncode(self::sign(self::ENDORSEMENT_PREFIX.$newKid, $signerSecretKey)),
        ];
    }

    /**
     * Whether a JWK carries a valid endorsement by one of the trusted keys.
     *
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $trustedKeys  kid => raw public key
     */
    public static function isEndorsed(array $jwk, array $trustedKeys): bool
    {
        $key = self::publicKeyFromJwk($jwk);
        if ($key === null || empty($jwk['endorsements']) || ! is_array($jwk['endorsements'])) {
            return false;
        }
        $message = self::ENDORSEMENT_PREFIX.self::thumbprint($key);
        foreach ($jwk['endorsements'] as $endorsement) {
            if (! is_array($endorsement) || ! isset($endorsement['kid'], $endorsement['sig']) || ! is_string($endorsement['kid'])) {
                continue;
            }
            if (! isset($trustedKeys[$endorsement['kid']])) {
                continue;
            }
            $signature = self::b64urlDecode($endorsement['sig']);
            if ($signature !== null && self::verify($signature, $message, $trustedKeys[$endorsement['kid']])) {
                return true;
            }
        }

        return false;
    }

    /** PKCE S256 code challenge. */
    public static function pkceChallenge(string $verifier): string
    {
        return self::b64urlEncode(hash('sha256', $verifier, true));
    }

    /** RFC 9530 Content-Digest header value (sha-256). */
    public static function contentDigest(string $body): string
    {
        return 'sha-256=:'.base64_encode(hash('sha256', $body, true)).':';
    }
}
