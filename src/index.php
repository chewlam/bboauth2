<?php

require_once __DIR__.'/../conf/config.php';
require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/oauth/BBOAuthService.php';


$_CONFIG['templates.path'] = __DIR__.'/templates';

$app = new \Slim\Slim($_CONFIG);
$app->setName('oauth2');

if ($app->request->isAjax()) {
    $app->response->headers->set('Content-Type', 'application/json');
}

$oaservice = new BBOAuthService();

$app->get('/test/:name',       function($name) use ($app) { echo "hello $name"; });
$app->get('/test2/:name',      function($name) use ($app) { echo "param: $name".PHP_EOL; print_r($app->request->get()); });

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

$app->post('/oauth/super_authorize\?:qstring', 
           function() use ($app, $oaservice) {
              $token = $oaservice->assertRequiredScope('super_admin');

               try {
                   $success = $oaservice->authorize(); 
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
