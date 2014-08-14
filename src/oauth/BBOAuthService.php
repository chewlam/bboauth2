<?php

// include our OAuth2 Server object
require_once __DIR__.'/BBOAuthCore.php';

class BBOAuthService {
    function __construct() {
        $this->oaServer = BBOAuthCore::getInstance();

        $this->oaRequest = OAuth2\Request::createFromGlobals();
        $this->oaResponse = new OAuth2\Response();
    }

    protected function getClientName($clientId) {
        $p = 'db.oauth.';
        $db   = Configure::get($p.'name');
        $user = Configure::get($p.'user');
        $pass = Configure::get($p.'password');
        $host = Configure::get($p.'host');
        $port = Configure::get($p.'port');

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

    protected function confirmUser($username, $password){
        $p = 'db.proficiency.';
        $db   = Configure::get($p.'name');
        $user = Configure::get($p.'user');
        $pass = Configure::get($p.'password');
        $host = Configure::get($p.'host');
        $port = Configure::get($p.'port');
 
        $dsn = "mysql:dbname=$db;host=$host";
        $pdo = new PDO($dsn, $user, $pass);
        $sql = "select u.id, u.password from t_users u where u.username=:user_name";
        $st = $pdo->prepare($sql);
        $st->execute(array(':user_name' => $username));
        $data = $st->fetchAll();

        if (count($data) > 0) {
            $data = $data[0];
            $hash = crypt($password, $data['password']);
            if ($password === false || strcmp($hash, $data['password'])===0) {
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

        $userId = false;
        $authorized = ($this->oaRequest->request['authorized'] === 'yes');

        if ($authorized) {
            $username = $this->oaRequest->request['username'];
            $password = $this->oaRequest->request['password'];

            if (empty($username) || empty($password)) {
                throw new Exception('Missing required fields', 401);
            }
        
            $userId = $this->confirmUser($username, $password);
            if ($userId === false) {
                throw new Exception('Incorrect login', 401);
            }
        }

        // print the authorization code if the user has authorized your client
        $this->oaServer->handleAuthorizeRequest($this->oaRequest, $this->oaResponse, $authorized, $userId);
        $this->oaResponse->send();
        return true;
    }

    // INTERNAL USE ONLY.  SCOPE is presumed to have already been checked and confirmed.
    // Admin level functionality for our internal servers to create authorization codes for a client
    // on behalf of a user.  This is useful for outbound SSO functionality.
    public function superauthorize() {

        // validate the authorize request
        if (!$this->oaServer->validateAuthorizeRequest($this->oaRequest, $this->oaResponse)) {
            $this->oaResponse->send();
            die;
        }

        $authorized = true;
        $r = $this->oaRequest->request;

        $userId = isset($r['userid']) ? $r['userid'] : false;
        if (empty($userId)) {
            $username = $r['username'];
 
            if (empty($username)) {
                throw new Exception('Missing required fields', 401);
            }
        
            $userId = $this->confirmUser($username, false);
        }

        if ($userId === false) {
            throw new Exception('Unknown user', 401);
        }

        // print the authorization code if the user has authorized your client
        $this->oaServer->handleAuthorizeRequest($this->oaRequest, $this->oaResponse, $authorized, $userId);
        $this->oaResponse->send();
        return true;
    }


}


