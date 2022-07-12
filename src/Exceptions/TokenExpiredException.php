<?php

namespace Yabx\WebToken\Exceptions;

class TokenExpiredException extends TokenException {

    public function __construct() {
        parent::__construct('Token Expired');
    }

}
