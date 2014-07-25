<?php

// include our OAuth2 Server object
require_once __DIR__.'/server.php';

$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

// validate the authorize request
if (!$server->validateAuthorizeRequest($request, $response)) {
    $response->send();
    die;
}


function checkPassword($username, $password) {
    $userdb = $config['userdb'];

    $dsn = "mysql:dbname={$userdb['name']};host={$userdb['host']}";
    $db = new PDO($dsn, $userdb['user'], $userdb['password']);
    $sql = "select u.id, u.password from t_users u where u.username=:user_name";
    $st = $db->prepare($sql);
    $st->execute(array(':user_name' => $username));
    $data = $st->fetchAll();

    if (count($data) < 0) {
        return false;
    }

    $data = $data[0];
    $hash = crypt($password, $data['password']);
    if (strcmp($hash, $data['password'])===0) {
        return $data['id'];
    }
    return false;
}


function renderLoginPage($clientName, $message="") {
    $params = array('client_name' => $clientName, 'message' => $message);
    $page = file_get_contents('login.html');

    foreach ($params as $key => $value) {
        $page = str_replace(':'.$key, $value, $page);
    }

    return $page;
}


// display an authorization form
if (empty($_POST)) {
    exit(renderLoginPage('TestClient'. '')); 
}

if (!isset($_POST['username']) || 
    !isset($_POST['password']) ||
    !isset($_POST['authorized'])) {
    exit(renderLoginPage('TestClient', 'Missing required fields');
}

$username = $_POST['username'];
$password = $_POST['password'];

$userId = checkPassword($username, $password);

if ($userId === false) {
    exit(renderLoginPage('TestClient', 'Incorrect login');
}

// print the authorization code if the user has authorized your client
$is_authorized = ($_POST['authorized'] === 'yes');
$server->handleAuthorizeRequest($request, $response, $is_authorized, $userId);
if ($is_authorized) {
  // this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
  $code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
  exit("SUCCESS! Authorization Code: $code");
}
$response->send();
