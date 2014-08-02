<?php

require_once __DIR__.'/../../conf/config.php';
require_once __DIR__.'/../../vendor/autoload.php';


class OAuthCore {

    public static function getInstance() {
        static $_instance;
        if (!isset ($_instance)) {
            $_instance = static::init();
        }
        return $_instance;
    }

    public static function config($setting) {
        global $_CONFIG;
        return $_CONFIG[$setting];
    }

    static $_SRVR_CONFIG = array(
        'require_exact_redirect_uri' => false,
        'always_issue_new_refresh_token' => true,
        'enforce_state' => false,
    );


    protected function init() {

        $oaname = static::config('oauthdb.name');
        $oauser = static::config('oauthdb.user');
        $oapass = static::config('oauthdb.password');
        $oahost = static::config('oauthdb.host');
        $oaport = static::config('oauthdb.port');

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
