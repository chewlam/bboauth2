<?php

require_once __DIR__.'/../../conf/config.php';
require_once __DIR__.'/../../vendor/autoload.php';


$oauthdb = $config['oauthdb'];

$dsn      = "mysql:dbname={$oauthdb['name']};host={$oauthdb['host']}";
$dbconnect = array('dsn' => $dsn, 'username' => $oauthdb['user'], 'password' => $oauthdb['password']);

// error reporting (this is a demo, after all!)
ini_set('display_errors',1);error_reporting(E_ALL);

// Autoloading (composer is preferred, but for this example let's just do this)
#require_once('oauth2-server-php/src/OAuth2/Autoloader.php');

OAuth2\Autoloader::register();

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
$storage = new OAuth2\Storage\Pdo($dbconnect);

// Pass a storage object or array of storage objects to the OAuth2 server class

$osrvrConfig = array(
    'require_exact_redirect_uri' => false,
    'always_issue_new_refresh_token' => true,
    'enforce_state' => false);


$server = new OAuth2\Server($storage, $osrvrConfig);

// Add the "Client Credentials" grant type (it is the simplest of the grant types)
$server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

// Add the "Authorization Code" grant type (this is where the oauth magic happens)
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));

$server->addGrantType(new OAuth2\GrantType\RefreshToken($storage, $osrvrConfig));
