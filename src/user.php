<?php

// include our OAuth2 Server object
require_once __DIR__.'/server.php';


$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

// Handle a request for an OAuth2.0 Access Token and send the response to the client
if (!$server->verifyResourceRequest($request)) {
    $server->getResponse()->send();
    die;
}

$token = $server->getAccessTokenData($request);

$scopeRequired = 'basic_profile'; // this resource requires "postonwall" scope
if (!$server->verifyResourceRequest($request, $response, $scopeRequired)) {
  // if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
  $response->send();
}

$q = array('email', 'last_name', 'first_name', 'time_zone');
/*
$scopeRequired = 'extra_profile'; // this resource requires "postonwall" scope
if ($server->verifyResourceRequest($request, $response, $scopeRequired)) {
    // if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
    echo "extra_profile".PHP_EOL;
}
*/

$sql = "select ".implode(',', $q)." from t_users where id=:user_id";

$db = $config['userdb'];
$dsn = "mysql:dbname={$db['name']};host={$db['host']}";
$db = new PDO($dsn, $db['user'], $db['password']);
$st = $db->prepare($sql);
$st->execute(array(':user_id' => $token['user_id']));
$data = $st->fetchAll();

if (count($data) < 1) {
    die(json_encode(array()));
}
$data = $data[0];
$newData = array();

foreach ($q as $k) {
    $newData[$k] = $data[$k];
}

die(json_encode($newData));


