<?php

namespace Yabx\WebToken;

use DateTimeInterface;
use DateTimeImmutable;
use Yabx\WebToken\Exceptions\TokenException;

class Token {

    public const KEY_USER = 'u';
    public const KEY_NONCE = 'n';
    public const KEY_PAYLOAD = 'p';
    public const KEY_CREATED = 'c';
    public const KEY_EXPIRES = 'e';
    public const KEY_VERSION = 'v';

    private string $token;
    protected string|int $user;
    private array $payload;
    private DateTimeInterface $created;
    private DateTimeInterface $expires;
    private string $version;

    public function __construct(string $token, array $data) {
        $this->token = $token;
        $this->user = $data[self::KEY_USER] ?? throw new TokenException('Invalid token (user)');
        $this->payload = $data[self::KEY_PAYLOAD] ?? throw new TokenException('Invalid token (payload)');
        $this->created = new DateTimeImmutable($data[self::KEY_CREATED]) ?? throw new TokenException('Invalid token (created)');
        $this->expires = new DateTimeImmutable($data[self::KEY_EXPIRES]) ?? throw new TokenException('Invalid token (expires)');
        $this->version = $data[self::KEY_VERSION] ?? throw new TokenException('Invalid token (version)');
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

    public function getCreated(): DateTimeInterface {
        return $this->created;
    }

    public function getExpires(): DateTimeInterface {
        return $this->expires;
    }

    public function getVersion(): string {
        return $this->version;
    }

    public function __toString(): string {
        return $this->token;
    }

}
