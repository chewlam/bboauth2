<?php

// include our OAuth2 Server object
require_once __DIR__.'/BBOAuthCore.php';

class BBOAuthService {
    function __construct() {
        $this->oaServer = BBOAuthCore::getInstance();

        $this->oaRequest = OAuth2\Request::createFromGlobals();
        $this->oaResponse = new OAuth2\Response();
    }

    protected function config($setting) {
        global $_CONFIG;
        return $_CONFIG[$setting];
    }

    protected function getClientName($clientId) {
        $p = 'oauthdb.';
        $db = $this->config($p.'name');
        $user = $this->config($p.'user');
        $pass = $this->config($p.'password');
        $host = $this->config($p.'host');
        $port = $this->config($p.'port');

        $dsn = "mysql:dbname=$db;host=$host";
        $pdo = new PDO($dsn, $user, $pass);
        $sql = "select client_name from oauth_clients where client_id=:client_id";
        $st = $pdo->prepare($sql);
        $st->execute(array(':client_id' => $clientId));
        $data = $st->fetchAll();

        if (count($data) < 0) {
            return false;
        }

        return $data[0]['client_name'];
    }

    protected function checkPassword($username, $password){
        $p = 'udb.';
        $db = $this->config($p.'name');
        $user = $this->config($p.'user');
        $pass = $this->config($p.'password');
        $host = $this->config($p.'host');
        $port = $this->config($p.'port');
 
        $dsn = "mysql:dbname=$db;host=$host";
        $pdo = new PDO($dsn, $user, $pass);
        $sql = "select u.id, u.password from t_users u where u.username=:user_name";
        $st = $pdo->prepare($sql);
        $st->execute(array(':user_name' => $username));
        $data = $st->fetchAll();

        if (count($data) > 0) {
            $data = $data[0];
            $hash = crypt($password, $data['password']);
            if (strcmp($hash, $data['password'])===0) {
                return $data['id'];
            }
        }
        return false;
    }

    public function assertRequiredScope ($scope) {
        if (!$this->oaServer->verifyResourceRequest($this->oaRequest, $this->oaResponse, $scope)) {
            // if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
            $this->oaResponse->send();
        }
        return $this->oaServer->getAccessTokenData($this->oaRequest);
    }

    public function token() {
        $this->oaServer->handleTokenRequest($this->oaRequest)->send();
    }

    public function authorizeForm() {
        if (!$this->oaServer->validateAuthorizeRequest($this->oaRequest, $this->oaResponse)) {
            $this->oaResponse->send();
            die;
        }

        $clientId = $this->oaRequest->query['client_id'];
        return $this->getClientName($clientId);
    }

    public function authorize() {

        // validate the authorize request
        if (!$this->oaServer->validateAuthorizeRequest($this->oaRequest, $this->oaResponse)) {
            $this->oaResponse->send();
            die;
        }

        $clientId = $this->oaRequest->query['client_id'];

        $username = $this->oaRequest->request['username'];
        $password = $this->oaRequest->request['password'];
        $authorized = $this->oaRequest->request['authorized'];

        if (empty($username) || empty($password) || empty($authorized)) {
            throw new Exception('Missing required fields', 401);
        }

        $userId = $this->checkPassword($username, $password);
        if ($userId === false) {
            throw new Exception('Incorrect login', 401);
        }

        // print the authorization code if the user has authorized your client
        $this->oaServer->handleAuthorizeRequest($this->oaRequest, $this->oaResponse, ($authorized === 'yes'), $userId);
        $this->oaResponse->send();
        return true;
    }
}


