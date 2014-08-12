<?php

require_once APP_DIR.'/Configure.php';
require_once APP_DIR.'/../vendor/autoload.php';


class BBOAuthCore {

    public static function getInstance() {
        static $_instance;
        if (!isset ($_instance)) {
            $_instance = static::init();
        }
        return $_instance;
    }

    static $_SRVR_CONFIG = array(
        'require_exact_redirect_uri' => false,
        'always_issue_new_refresh_token' => true,
        'enforce_state' => false,
    );


    protected function init() {
        $p = 'db.oauth.';
        $oaname = Configure::get($p.'name');
        $oauser = Configure::get($p.'user');
        $oapass = Configure::get($p.'password');
        $oahost = Configure::get($p.'host');
        $oaport = Configure::get($p.'port');

        $dsn = "mysql:dbname=$oaname;host=$oahost";
        $dbconnect = array('dsn' => $dsn, 'username' => $oauser, 'password' => $oapass);

        // error reporting (this is a demo, after all!)
        ini_set('display_errors',1);error_reporting(E_ALL);

        // Autoloading (composer is preferred, but for this example let's just do this)

        OAuth2\Autoloader::register();

        // $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
        $storage = new OAuth2\Storage\Pdo($dbconnect);

        // Pass a storage object or array of storage objects to the OAuth2 server class



        $server = new OAuth2\Server($storage, self::$_SRVR_CONFIG);

        // Add the "Client Credentials" grant type (it is the simplest of the grant types)
        $server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

        // Add the "Authorization Code" grant type (this is where the oauth magic happens)
        $server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));

        $server->addGrantType(new OAuth2\GrantType\RefreshToken($storage));
        return $server;
    }
}


