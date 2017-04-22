<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;

require '../vendor/autoload.php';
require '../config.php';

session_start();

// if BlueMix VCAP_SERVICES environment available
// overwrite local config file with credentials from BlueMix
if ($services = getenv("VCAP_SERVICES")) {
  $services_json = json_decode($services, true);  
  $config['settings']['passport_api_key'] = $services_json["user-provided"][0]["credentials"]["api_key"];
  $config['settings']['passport_api_url'] = $services_json["user-provided"][0]["credentials"]["passport_backend_url"];
  if (getenv("passport_app_id")) {
    $config['settings']['passport_app_id'] = getenv("passport_app_id");
  } 
} 

// configure Slim application instance
// initialize application
$app = new \Slim\App($config);

// initialize dependency injection container
$container = $app->getContainer();

// add view renderer
$container['view'] = function ($container) {
  return new \Slim\Views\PhpRenderer("../views/");
};

// add Passport API client
$container['passport'] = function ($container) {
  $config = $container->get('settings');
  return new Client([
    'base_uri' => $config['passport_api_url'],
    'timeout'  => 6000,
    'verify' => false,    // set to true in production
    'headers' => [
      'Authorization' => $config['passport_api_key'],
    ]
  ]);
};

// simple authentication middleware
$authenticate = function ($request, $response, $next) {
  if (!isset($_SESSION['user'])) {
    return $response->withHeader('Location', $this->router->pathFor('login'));
  }
  return $next($request, $response);
};

// index page handler
$app->get('/', function (Request $request, Response $response) {
  return $response->withHeader('Location', $this->router->pathFor('home'));
});

// public page handler
$app->get('/home', function (Request $request, Response $response) {
  return $this->view->render($response, 'home.phtml', [
    'router' => $this->router
  ]);
})->setName('home');

// user form handler
$app->get('/admin/users/save', function (Request $request, Response $response) {
  $response = $this->view->render($response, 'users-save.phtml', [
    'router' => $this->router
  ]);
  return $response;
})->setName('admin-users-save');

// user form processor
$app->post('/admin/users/save', function (Request $request, Response $response) {
  // get configuration
  $config = $this->get('settings');

  // get input values
  $params = $request->getParams();
  
  // validate input
  if (!($fname = filter_var($params['fname'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: First name is not a valid string');
  }
  
  if (!($lname = filter_var($params['lname'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: Last name is not a valid string');
  }
  
  $password = trim(strip_tags($params['password']));
  if (strlen($password) < 8) {
    throw new Exception('ERROR: Password should be at least 8 characters long');      
  }
      
  $email = filter_var($params['email'], FILTER_SANITIZE_EMAIL);
  if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    throw new Exception('ERROR: Email address should be in a valid format');
  }
    
  // generate array of user data
  $user = [
    'registration' => [
      'applicationId' => $config['passport_app_id'],
    ],
    'skipVerification' => true,
    'user'  => [
      'email' => $email,
      'firstName' => $fname,
      'lastName' => $lname,
      'password' => $password
    ]
  ];
  
  // encode user data as JSON
  // POST to Passport API for user registration and creation
  $apiResponse = $this->passport->post('/api/user/registration', [
    'body' => json_encode($user),
    'headers' => ['Content-Type' => 'application/json'],
  ]);

  // if successful, display success message
  // with user id
  if ($apiResponse->getStatusCode() == 200) {
    $json = (string)$apiResponse->getBody();
    $body = json_decode($json);
    $response = $this->view->render($response, 'users-save.phtml', [
      'router' => $this->router, 'user' => $body->user
    ]);
    return $response;
 }
});

// user list handler
$app->get('/admin/users/index', function (Request $request, Response $response) {
  // get configuration
  $config = $this->get('settings');

  $apiResponse = $this->passport->get('/api/user/search', [
    'query' => ['queryString' => 'user.registrations.applicationId:' . $config['passport_app_id']]
  ]);
  
  if ($apiResponse->getStatusCode() == 200) {
    $json = (string)$apiResponse->getBody();
    $body = json_decode($json);

    $activeUsers = [];
    $inactiveUsers = [];      
    foreach ($body->users as $user) {
      if ($user->active == 1) {
        $activeUsers[] = $user;
      } else {
        $inactiveUsers[] = $user;
      }
    }
    
    $response = $this->view->render($response, 'users-index.phtml', [
      'router' => $this->router, 'active-users' => $activeUsers, 'inactive-users' => $inactiveUsers
    ]);
    return $response;   
  }
})->setName('admin-users-index');

// login page handler
$app->get('/login', function (Request $request, Response $response) {
  return $this->view->render($response, 'login.phtml', [
    'router' => $this->router
  ]);
})->setName('login');

// login form processor
$app->post('/login', function (Request $request, Response $response) {
  // get configuration
  $config = $this->get('settings');
  
  // set user record to false by default
  $user = false;

  try {
    // get input values
    $params = $request->getParams();
    
    // validate and sanitize input
    $email = filter_var($params['email'], FILTER_SANITIZE_EMAIL);
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
      throw new Exception('ERROR: Email address should be in a valid format');
    }

    $password = trim(strip_tags($params['password']));
    if (empty($password)) {
      throw new Exception('ERROR: Password should not be an empty string');      
    }
        
    // generate array of data for authentication
    $auth = [
      'applicationId' => $config['passport_app_id'],
      'loginId' => $email,
      'password' => $password,
    ];

    // authenticate
    $apiResponse = $this->passport->post('/api/login', [
      'body' => json_encode($auth),
      'headers' => ['Content-Type' => 'application/json'],
    ]);
    
    // if 2xx error, authentication successful
    // set user information in session
    if ($apiResponse->getStatusCode() == 200 || $apiResponse->getStatusCode() == 202) {
      $json = (string)$apiResponse->getBody();
      $body = json_decode($json);
      $_SESSION['user'] = $body->user;
      $user = $body->user;
    }
  } catch (ClientException $e) {
    // in case of a Guzzle exception
    // if 4xx, authentication error 
    // bypass exception handler for login failure page
    // for other errors, transfer to exception handler as normal
    if (!($e->getResponse()->getStatusCode() >= 400 && $e->getResponse()->getStatusCode() < 500)) {
      throw new Exception($e->getResponse());
    } 
  } 
  return $this->view->render($response, 'login.phtml', [
    'router' => $this->router, 'user' => $user
  ]);
});

// logout page handler
$app->get('/logout', function (Request $request, Response $response) {
  unset($_SESSION['user']);
  return $response->withHeader('Location', $this->router->pathFor('login'));
})->setName('logout');

// private page handler
$app->get('/account', function (Request $request, Response $response) {
  return $this->view->render($response, 'account.phtml', [
    'router' => $this->router, 'user' => $_SESSION['user']
  ]);
})->setName('account')->add($authenticate);

// user deactivation handler
$app->get('/admin/users/deactivate/{id}', function (Request $request, Response $response, $args) {
  // sanitize and validate input
  if (!($id = filter_var($args['id'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: User identifier is not a valid string');
  }
  
  $apiResponse = $this->passport->delete('/api/user/' . $id);
  return $response->withHeader('Location', $this->router->pathFor('admin-users-index'));
})->setName('admin-users-deactivate');

// user activation handler
$app->get('/admin/users/activate/{id}', function (Request $request, Response $response, $args) {
  // sanitize and validate input
  if (!($id = filter_var($args['id'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: User identifier is not a valid string');
  }

  $apiResponse = $this->passport->put('/api/user/' . $id , [
    'query' => ['reactivate' => 'true']
  ]);
  return $response->withHeader('Location', $this->router->pathFor('admin-users-index'));
})->setName('admin-users-activate');

// legal page handler
$app->get('/legal', function (Request $request, Response $response) {
  return $this->view->render($response, 'legal.phtml', [
    'router' => $this->router
  ]);
})->setName('legal');

$app->run();