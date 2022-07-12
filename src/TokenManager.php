<?php

namespace Yabx\WebToken;

use DateTime;
use Exception;
use Yabx\WebToken\Exceptions\TokenException;
use Yabx\WebToken\Exceptions\TokenExpiredException;

class TokenManager {

    protected string $secret;
    protected const SIGNATURE = 'WT10';

    public function __construct(string $secret) {
        $this->secret = $secret;
    }

    public function issue(int|string $user, array $payload = [], int $ttl = 3600): Token {
        $created = new DateTime();
        $expires = new DateTime("+$ttl seconds");
        $data = [
            Token::KEY_NONCE => bin2hex(random_bytes(8)),
            Token::KEY_USER => $user,
            Token::KEY_PAYLOAD => $payload,
            Token::KEY_CREATED => $created->format('c'),
            Token::KEY_EXPIRES => $expires->format('c'),
            Token::KEY_VERSION => '1.0',
        ];
        $json = json_encode($data);
        $hash = sha1($json . $this->secret);
        $token = self::SIGNATURE . base64_encode($json . PHP_EOL . $hash);
        return new Token($token, $data);
    }

    public function refresh(Token|string $token, int $ttl = 3600): Token {
        if($token instanceof Token) $token = $token->getToken();
        $token = $this->read($token);
        return $this->issue($token->getUser(), $token->getPayload(), $ttl);
    }

    public function read(string $token): Token {
        if(!str_starts_with($token, self::SIGNATURE)) throw new TokenException('Invalid token signature');
        $encoded = preg_replace('/^' . self::SIGNATURE . '/', '', $token);
        $decoded = base64_decode($encoded);
        [$data, $hash] = explode("\n", $decoded, 2);
        if(sha1($data . $this->secret) === $hash) {
            $data = json_decode($data, true);
            $expires = new DateTime($data[Token::KEY_EXPIRES]);
            if($expires < new DateTime()) throw new TokenExpiredException;
            return new Token($token, $data);
        } else {
            throw new TokenException;
        }
    }

}
