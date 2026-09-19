<?php

namespace Gibbon\Module\OIDCServer\Issuer;

class Jwt
{
    public static function generateKey(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($resource === false) {
            throw new \RuntimeException('Unable to generate RSA key');
        }
        openssl_pkey_export($resource, $pem);
        $details = openssl_pkey_get_details($resource);
        $kid = bin2hex(random_bytes(8));
        $jwk = [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kid,
            'n' => self::b64url($details['rsa']['n']),
            'e' => self::b64url($details['rsa']['e']),
        ];

        return [
            'kid' => $kid,
            'privatePem' => $pem,
            'publicJwk' => json_encode($jwk, JSON_UNESCAPED_SLASHES),
        ];
    }

    public static function sign(array $payload, string $privatePem, string $kid): string
    {
        $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid];
        $segments = [
            self::b64url(json_encode($header, JSON_UNESCAPED_SLASHES)),
            self::b64url(json_encode($payload, JSON_UNESCAPED_SLASHES)),
        ];
        $data = implode('.', $segments);
        $ok = openssl_sign($data, $signature, $privatePem, OPENSSL_ALGO_SHA256);
        if (!$ok) {
            throw new \RuntimeException('JWT sign failed');
        }
        $segments[] = self::b64url($signature);

        return implode('.', $segments);
    }

    public static function decodeUnverified(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \InvalidArgumentException('Malformed JWT');
        }

        return json_decode(self::b64urlDecode($parts[1]), true) ?: [];
    }

    public static function verify(string $jwt, string $publicJwkJson): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \InvalidArgumentException('Malformed JWT');
        }
        $jwk = json_decode($publicJwkJson, true);
        $n = self::b64urlDecode($jwk['n']);
        $e = self::b64urlDecode($jwk['e']);
        $pem = self::rsaPublicPem($n, $e);
        $ok = openssl_verify($parts[0].'.'.$parts[1], self::b64urlDecode($parts[2]), $pem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new \RuntimeException('JWT signature invalid');
        }

        return json_decode(self::b64urlDecode($parts[1]), true) ?: [];
    }

    public static function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/')) ?: '';
    }

    private static function rsaPublicPem(string $n, string $e): string
    {
        $modulus = self::derInteger($n);
        $exponent = self::derInteger($e);
        $inner = self::derSequence($modulus.$exponent);
        $bitstring = "\x03".self::derLength(strlen($inner) + 1)."\x00".$inner;
        $rsaOid = pack('H*', '300d06092a864886f70d0101010500');
        $spki = self::derSequence($rsaOid.$bitstring);
        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::derLength(strlen($bytes)).$bytes;
    }

    private static function derSequence(string $contents): string
    {
        return "\x30".self::derLength(strlen($contents)).$contents;
    }

    private static function derLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $out = '';
        while ($length > 0) {
            $out = chr($length & 0xff).$out;
            $length >>= 8;
        }

        return chr(0x80 | strlen($out)).$out;
    }
}
