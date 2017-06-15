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

// simple authorization middleware
$authorize = function ($role) {
  return function($request, $response, $next) use ($role) {
    if ($_SESSION['user']->registrations[0]->roles[0] != $role) {
      return $response->withHeader('Location', $this->router->pathFor('login'));
    } 
    return $next($request, $response);  
  };
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
$app->get('/admin/users/save[/{id}]', function (Request $request, Response $response, $args) {
  $user = [];
  
  if (isset($args['id'])) {
    // sanitize input
    if (!($id = filter_var($args['id'], FILTER_SANITIZE_STRING))) {
      throw new Exception('ERROR: User identifier is not a valid string');
    }
    
    $apiResponse = $this->passport->get('/api/user/' . $id);
    
    if ($apiResponse->getStatusCode() == 200) {
      $json = (string)$apiResponse->getBody();
      $body = json_decode($json);
      $user = $body->user;
    } 
  }

  $response = $this->view->render($response, 'users-save.phtml', [
    'router' => $this->router, 'user' => $user
  ]);
  return $response;
})->setName('admin-users-save');

// user form processor
$app->post('/admin/users/save', function (Request $request, Response $response) {
  // get configuration
  $config = $this->get('settings');

  // get input values
  $params = $request->getParams();
  
  // check for user id
  // if present, this is update modification
  // if absent, this is user creation
  if ($params['id']) {
    if (!($id = filter_var($params['id'], FILTER_SANITIZE_STRING))) {
      throw new Exception('ERROR: User identifier is not a valid string');
    }
  }    
  
  if (!($fname = filter_var($params['fname'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: First name is not a valid string');
  }
  
  if (!($lname = filter_var($params['lname'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: Last name is not a valid string');
  }
  
  $password = trim(strip_tags($params['password']));
  if (empty($id)) {
    if (strlen($password) < 8) {
      throw new Exception('ERROR: Password should be at least 8 characters long');      
    }
  } else {
    if (!empty($password) && (strlen($password) < 8)) {
      throw new Exception('ERROR: Password should be at least 8 characters long');      
    }
  }
      
  $email = filter_var($params['email'], FILTER_SANITIZE_EMAIL);
  if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    throw new Exception('ERROR: Email address should be in a valid format');
  }
  
  if (!($city = filter_var($params['city'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: City is not a valid string');
  }
  
  if (!($occupation = filter_var($params['occupation'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: Occupation is not a valid string');
  }

  $mobilePhone = filter_var($params['mobilePhone'], FILTER_SANITIZE_NUMBER_INT);
  if (filter_var($mobilePhone, FILTER_VALIDATE_FLOAT) === false) {
    throw new Exception('ERROR: Mobile phone is not a valid number');
  }
  
  if (!($tier = filter_var($params['tier'], FILTER_SANITIZE_NUMBER_INT))) {
    throw new Exception('ERROR: Membership tier is not valid');
  }
  if ($tier == 1) {
    $role = 'member-gold';
  } else if ($tier == 2) {
    $role = 'member-silver';
  }  
  
  // generate array of user data
  $user = [
    'registration' => [
      'applicationId' => $config['passport_app_id'],
      'roles' => [
        $role
      ]      
    ],
    'skipVerification' => true,
    'user'  => [
      'email' => $email,
      'firstName' => $fname,
      'lastName' => $lname,
      'mobilePhone' => $mobilePhone,
      'data' => [
        'attributes' => [
          'city' => $city,
          'occupation' => $occupation,
        ]
      ]
    ]
  ];
  
  // add password if exists
  // can be empty for user modification operations
  if (!empty($password)) {
    $user['user']['password'] = $password;
  }
  
  if (empty($id)) {
    // encode user data as JSON
    // POST to Passport API for user registration and creation
    $apiResponse = $this->passport->post('/api/user/registration', [
      'body' => json_encode($user),
      'headers' => ['Content-Type' => 'application/json'],
    ]);
  } else {
    // encode user data as JSON
    // PUT to Passport API for user modification
    $apiResponse = $this->passport->put('/api/user/' . $id, [
      'body' => json_encode($user),
      'headers' => ['Content-Type' => 'application/json'],
    ]);      
  }

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
    if (isset($body->users)) {
      foreach ($body->users as $user) {
        if ($user->active == 1) {
          $activeUsers[] = $user;
        } else {
          $inactiveUsers[] = $user;
        }
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

// role-limited page handler
$app->get('/members/gold', function (Request $request, Response $response) {
  return $this->view->render($response, 'members-gold.phtml', [
    'router' => $this->router, 'user' => $_SESSION['user']
  ]);
})->setName('members-gold')->add($authenticate)->add($authorize('member-gold'));

// role-limited page handler
$app->get('/members/silver', function (Request $request, Response $response) {
  return $this->view->render($response, 'members-silver.phtml', [
    'router' => $this->router, 'user' => $_SESSION['user']
  ]);
})->setName('members-silver')->add($authenticate)->add($authorize('member-silver'));

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

// user deletion handler
$app->get('/admin/users/delete/{id}', function (Request $request, Response $response, $args) {
  // sanitize and validate input
  if (!($id = filter_var($args['id'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: User identifier is not a valid string');
  }

  $apiResponse = $this->passport->delete('/api/user/' . $id , [
    'query' => ['hardDelete' => 'true']
  ]);

  return $response->withHeader('Location', $this->router->pathFor('admin-users-index'));
})->setName('admin-users-delete');

// password reset handlers (request step)
$app->get('/password-request', function (Request $request, Response $response) {
  return $this->view->render($response, 'password-request.phtml', [
    'router' => $this->router
  ]);
})->setName('password-request');

$app->post('/password-request', function (Request $request, Response $response) {
  try {
    // validate input 
    $params = $request->getParams();
    $email = filter_var($params['email'], FILTER_SANITIZE_EMAIL);
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
      throw new Exception('ERROR: Email address should be in a valid format');
    }

    // generate array of data
    $data = [
      'loginId' => $email,
      'sendForgotPasswordEmail' => true
    ];

    $apiResponse = $this->passport->post('/api/user/forgot-password', [
      'body' => json_encode($data),
      'headers' => ['Content-Type' => 'application/json'],
    ]);

  } catch (ClientException $e) {
    // in case of a Guzzle exception
    // if 404, user not found error 
    // bypass exception handler and show failure message
    // for other errors, transfer to exception handler as normal
    if ($e->getResponse()->getStatusCode() != 404) {
      throw new Exception($e->getResponse());
    } else {
      $apiResponse = $e->getResponse();
    }
  } 

  return $this->view->render($response, 'password-request.phtml', [
    'router' => $this->router, 'status' => $apiResponse->getStatusCode()
  ]);
});

// password reset handlers (reset step)
$app->get('/password-reset[/{id}]', function (Request $request, Response $response, $args) {
  // sanitize and validate input
  if (!($id = filter_var($args['id'], FILTER_SANITIZE_STRING))) {
    throw new Exception('ERROR: Verification string is invalid');
  }
  return $this->view->render($response, 'password-reset.phtml', [
    'router' => $this->router, 'id' => $args['id']
  ]);
})->setName('password-reset');

$app->post('/password-reset', function (Request $request, Response $response) {
  try {
    // validate input 
    $params = $request->getParams();

    // sanitize and validate input
    if (!($id = filter_var($params['id'], FILTER_SANITIZE_STRING))) {
      throw new Exception('ERROR: Verification string is invalid');
    }

    
    $password = trim(strip_tags($params['password']));
    if (strlen($password) < 8) {
      throw new Exception('ERROR: Password should be at least 8 characters long');      
    }
    $passwordConfirm = trim(strip_tags($params['password-confirm']));
    if ($password != $passwordConfirm) {
      throw new Exception('ERROR: Passwords do not match');      
    }
    
    // generate array of data
    $data = [
      'password' => $password,
    ];

    $apiResponse = $this->passport->post('/api/user/change-password/' . $id, [
      'body' => json_encode($data),
      'headers' => ['Content-Type' => 'application/json'],
    ]);

  } catch (ClientException $e) {
    // in case of a Guzzle exception
    // if 404, user not found error 
    // bypass exception handler and show failure message
    // for other errors, transfer to exception handler as normal
    if ($e->getResponse()->getStatusCode() != 404) {
      throw new Exception($e->getResponse());
    } else {
      $apiResponse = $e->getResponse();
    }
  } 

  return $this->view->render($response, 'password-reset.phtml', [
    'router' => $this->router, 'status' => $apiResponse->getStatusCode()
  ]);
});

// legal page handler
$app->get('/legal', function (Request $request, Response $response) {
  return $this->view->render($response, 'legal.phtml', [
    'router' => $this->router
  ]);
})->setName('legal');

$app->run();