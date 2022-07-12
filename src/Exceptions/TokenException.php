<?php

namespace Yabx\WebToken\Exceptions;

use Exception;

class TokenException extends Exception {

    public function __construct(string $message = 'Invalid token') {
        parent::__construct($message, 401);
    }

}
