<?php

namespace Yabx\WebToken;

use DateTimeInterface;
use Yabx\WebToken\Exceptions\TokenException;

class Token {

    public const KEY_USER = 'u';
    public const KEY_PAYLOAD = 'p';
    public const KEY_ISSUED_AT = 'i';
    public const KEY_EXPIRES_AT = 'e';

    private string $token;
    protected string|int $user;
    private array $payload;
    private DateTimeInterface $issuedAt;
    private DateTimeInterface $expiresAt;

    public function __construct(string $token, array $data) {
        $this->token = $token;
        $this->user = $data[self::KEY_USER] ?? throw new TokenException('Invalid token (user)');
        $this->payload = $data[self::KEY_PAYLOAD] ?? throw new TokenException('Invalid token (payload)');
        $this->issuedAt = Utils::fromTimestamp($data[self::KEY_ISSUED_AT] ?? $data['c'] ?? throw new TokenException('Invalid token (issue date)'));
        $this->expiresAt = Utils::fromTimestamp($data[self::KEY_EXPIRES_AT] ?? throw new TokenException('Invalid token (expires date)'));
    }

    public function getToken(): string {
        return $this->token;
    }

    public function getUser(): int|string {
        return $this->user;
    }

    public function getPayload(): array {
        return $this->payload;
    }

    public function getIssuedAt(): DateTimeInterface {
        return $this->issuedAt;
    }

    public function getExpiresAt(): DateTimeInterface {
        return $this->expiresAt;
    }

    public function __toString(): string {
        return $this->token;
    }

}
