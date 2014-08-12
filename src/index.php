<?php

require_once __DIR__.'/Configure.php';
require_once APP_DIR.'/../vendor/autoload.php';
require_once APP_DIR.'/oauth/BBOAuthService.php';


$app = new \Slim\Slim(Configure::get('slim'));
$app->setName('oauth2');

if ($app->request->isAjax()) {
    $app->response->headers->set('Content-Type', 'application/json');
}

$oaservice = new BBOAuthService();

$app->get('/oauth/authorize\?:qstring',
          function() use ($app, $oaservice) { 
              $client = $oaservice->authorizeForm(); 
              $app->render('login.html', array('message' => '', 'client_name' => $client));
          });

$app->get('/user/profile',
          function() use ($app, $oaservice) {
              $token = $oaservice->assertRequiredScope('basic_profile');
              $app->response->headers->set('Content-Type', 'application/json');
              $app->render('userprofile.php', $token);
          });


$app->post('/oauth/authorize\?:qstring', 
           function() use ($app, $oaservice) {
               try {
                   $success = $oaservice->authorize(); 
               } catch (Exception $e) {
                   $app->halt($e->getCode(), $e->getMessage());
               }
           });

$app->post('/oauth/superauthorize\?:qstring', 
           function() use ($app, $oaservice) {
              $token = $oaservice->assertRequiredScope('super_admin');

               try {
                   $success = $oaservice->superauthorize(); 
               } catch (Exception $e) {
                   $app->halt($e->getCode(), $e->getMessage());
               }
           });

$app->post('/oauth/token',
           function() use ($app, $oaservice) {
               $app->response->headers->set('Content-Type', 'application/json');
               $oaservice->token();
           });

$app->run();


?>
