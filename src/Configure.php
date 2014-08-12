<?php

define('APP_DIR', __DIR__);

require_once __DIR__.'/../conf/config.php';

class Configure {
    static function get($setting) {
        global $_CONFIG;
        return $_CONFIG[$setting];
    }
}


