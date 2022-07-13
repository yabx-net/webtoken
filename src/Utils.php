<?php

namespace Yabx\WebToken;

use DateTime;
use DateTimeZone;
use DateTimeInterface;

class Utils {

    public static function now(): DateTimeInterface {
        return new DateTime('now', new DateTimeZone('UTC'));
    }

    public static function fromTimestamp(int $timestamp): DateTimeInterface {
        return self::now()->setTimestamp($timestamp);
    }

}
