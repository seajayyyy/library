<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$config = ['settings' => ['displayErrorDetails' => true]];
$app = new \Slim\App;

$key = 'server_hack';

//token rotation for every endpoint
function generateToken($userid) {
    global $key;

    // Token generation
    $iat = time(); // Issued at time
    $exp = $iat + 7200; // Expiration time (2 hours)
    
    // Payload data for JWT
    $payload = [
        'iss' => 'http://library.org', // Issuer
        'aud' => 'http://library.com', // Audience
        'iat' => $iat,                 // Issued at time
        'exp' => $exp,                 // Expiration time
        "data" => [
            "userid" => $userid        // User ID data
        ]
    ];

    // Encode the token
    $token = JWT::encode($payload, $key, 'HS256');

    // Database connection credentials
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection to the MySQL database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare the SQL query to insert token information into the database
        $sql = "INSERT INTO tokens (token, userid, status) VALUES (:token, :userid, 'active')";
        $stmt = $conn->prepare($sql);

        // Bind parameters
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':userid', $userid);

        // Execute the query
        $stmt->execute();
    } catch (PDOException $e) {
        // Handle exceptions (logging can be implemented here)
    }

    // Return the generated token
    return $token;
}

function validateToken($token) {
    global $key; // Use the global variable $key for JWT decoding
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Set error mode to exception

        // Prepare a SQL statement to check if the token exists and is active
        $sql = "SELECT * FROM tokens WHERE token = :token AND status = 'active'";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token); // Bind the token parameter
        $stmt->execute(); // Execute the statement
        $data = $stmt->fetch(PDO::FETCH_ASSOC); // Fetch the result as an associative array

        // If the token is found in the database
        if ($data) {
            // Decode the JWT token to extract user information
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            return $decoded->data->userid; // Return the user ID from the decoded token
        } else {
            return false; // Return false if the token is not active or does not exist
        }
    } catch (PDOException $e) {
        return false; // Return false if there is a database error
    }
}

function markTokenAsUsed($token) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Set error mode to exception

        // Prepare a SQL statement to revoke the token and set the used_at timestamp
        $sql = "UPDATE tokens SET status = 'revoked', used_at = NOW() WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token); // Bind the token parameter
        $stmt->execute(); // Execute the statement
    } catch (PDOException $e) {
        // Handle any errors silently (optional logging could be added here)
    }
}

function updateTokenStatus($token, $status) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Set error mode to exception

        // Prepare a SQL statement to update the status of the token
        $sql = "UPDATE tokens SET status = :status WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':status', $status); // Bind the status parameter
        $stmt->bindParam(':token', $token); // Bind the token parameter
        $stmt->execute(); // Execute the statement
    } catch (PDOException $e) {
        // Handle any errors silently (optional logging could be added here)
    }
}


//endpoint for user register
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
        $stmt->bindParam(':username', $uname);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Username already taken"))));
        } else {
            $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $stmt->bindParam(':username', $uname);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();

            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

//endpoint for user authentication
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username='" . $uname . "' 
                AND password='" . hash('SHA256', $pass) . "'";
        $stmt = $conn->prepare($sql);
        $stmt->execute();

        $data = $stmt->fetchAll();
        if (count($data) == 1) {
            $userid = $data[0]['userid'];
            $token = generateToken($userid);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $token, "data" => null)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

//endpoint to display all users
$app->get('/user/display', function (Request $request, Response $response) {
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    $userid = validateToken($token);

    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT userid, username FROM users");
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($users) {
            markTokenAsUsed($token);

            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $users)));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No users found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null;
});

//endpoint for updating users
$app->put('/user/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->userid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $useridToUpdate = $data->userid;

    if ($useridFromToken != $useridToUpdate) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized action"))));
    }

    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $hashedPassword = hash('sha256', $pass);
        $stmt->bindParam(':username', $uname);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':userid', $useridToUpdate);
        $stmt->execute();

        markTokenAsUsed($token);

        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

//endpoint for deleting/removing users
$app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->userid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "User ID missing in payload"))));
    }

    $token = $data->token;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    $useridToDelete = $data->userid;

    if ($useridFromToken != $useridToDelete) {
        return $response->withStatus(403)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized action"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $useridToDelete);
        $stmt->execute();

        markTokenAsUsed($token);

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

//Author registration
$app->post('/author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    if (!isset($data->name)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Name missing in payload"))));
    }

    $token = $data->token;
    $name = $data->name;
    $useridFromToken = validateToken($token);

    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
        $stmt->bindParam(':name', $name);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name already taken"))));
        } else {
            $sql = "INSERT INTO authors (name) VALUES (:name)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':name', $name);
            $stmt->execute();

            markTokenAsUsed($token);

            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

// Route to display authors
$app->get('/author/display', function (Request $request, Response $response) {
    // Retrieve all headers from the request
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    // Get the Authorization header
    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    
    // Check if the Authorization header is missing
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    // Extract token from the Authorization header
    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    // Validate the token and get the user ID
    $userid = validateToken($token);

    // If token is invalid or expired, return a 401 error
    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Database connection parameters
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare and execute a SQL query to fetch all authors
        $stmt = $conn->prepare("SELECT authorid, name FROM authors");
        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // If authors are found, mark the token as used and generate a new token
        if ($authors) {
            markTokenAsUsed($token);
            $newToken = generateToken($userid);

            // Return success response with authors and new token
            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $authors)));
        } else {
            // If no authors are found, return a failure message
            return $response->write(json_encode(array("status" => "fail", "message" => "No authors found")));
        }
    } catch (PDOException $e) {
        // Handle any database exceptions
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    // Close the database connection
    $conn = null;
});

// Route to update an author's details
$app->put('/author/update', function (Request $request, Response $response) {
    // Decode the JSON payload from the request body
    $data = json_decode($request->getBody());

    // Check for the presence of the token in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check for the presence of the author ID in the payload
    if (!isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID missing in payload"))));
    }

    // Extract token and validate it
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // If the token is invalid, return a 401 error
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Extract author ID and name from the payload
    $authoridToUpdate = $data->authorid;
    $name = $data->name;

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare and execute the SQL query to update the author's name
        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':authorid', $authoridToUpdate);
        $stmt->execute();

        // Mark the token as used and generate a new token
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);
        
        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response; // Return the response
});

// Route to delete an author
$app->delete('/author/delete', function (Request $request, Response $response) {
    // Decode the JSON payload from the request body
    $data = json_decode($request->getBody());

    // Check for JSON errors
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    // Check for the presence of the token in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check for the presence of the author ID in the payload
    if (!isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author ID missing in payload"))));
    }

    // Extract token and validate it
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // If the token is invalid, return a 401 error
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Extract author ID from the payload
    $authoridToDelete = $data->authorid;

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Prepare and execute the SQL query to delete the author
        $sql = "DELETE FROM authors WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':authorid', $authoridToDelete);
        $stmt->execute();

        // Mark the token as used and generate a new token
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);

        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response; // Return the response
});


// Register a new book
$app->post('/book/register', function (Request $request, Response $response, array $args) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if title and author ID are provided
    if (!isset($data->title) || !isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Title or Author ID missing in payload"))));
    }

    // Retrieve token and data
    $token = $data->token;
    $title = $data->title;
    $authorid = $data->authorid;

    // Validate the token
    $useridFromToken = validateToken($token);
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book already exists in the database
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title AND authorid = :authorid");
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            // Respond if the book already exists
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book already exists"))));
        } else {
            // Insert the new book into the database
            $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':authorid', $authorid);
            $stmt->execute();

            // Mark the token as used and generate a new one
            markTokenAsUsed($token);
            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});

// Display all books
$app->get('/book/display', function (Request $request, Response $response) {
    // Log incoming headers for debugging
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    // Get the Authorization header
    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    // Extract the token from the Authorization header
    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    // Validate the token
    $userid = validateToken($token);
    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Database connection parameters
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Retrieve all books from the database
        $stmt = $conn->prepare("SELECT bookid, title, authorid FROM books");
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            // Mark the token as used and generate a new one
            markTokenAsUsed($token);
            $newToken = generateToken($userid);
            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $books)));
        } else {
            // Respond if no books are found
            return $response->write(json_encode(array("status" => "fail", "message" => "No books found")));
        }
    } catch (PDOException $e) {
        // Handle any database exceptions
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    // Close the database connection
    $conn = null;
});

// Update an existing book
$app->put('/book/update', function (Request $request, Response $response) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if book ID is provided
    if (!isset($data->bookid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID missing in payload"))));
    }

    // Retrieve token and data
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // Validate the token
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Retrieve data to update
    $bookidToUpdate = $data->bookid;
    $title = $data->title;
    $authorid = $data->authorid;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update the book in the database
        $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->bindParam(':bookid', $bookidToUpdate);
        $stmt->execute();

        // Mark the token as used and generate a new one
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});

// Delete an existing book
$app->delete('/book/delete', function (Request $request, Response $response) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check for JSON errors
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if book ID is provided
    if (!isset($data->bookid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID missing in payload"))));
    }

    // Retrieve token and data
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // Validate the token
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Retrieve the book ID to delete
    $bookidToDelete = $data->bookid;

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete the book from the database
        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookidToDelete);
        $stmt->execute();

        // Mark the token as used and generate a new one
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});

// Register a new book-author relationship
$app->post('/book_author/register', function (Request $request, Response $response, array $args) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if both book ID and author ID are provided
    if (!isset($data->bookid) || !isset($data->authorid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book ID or Author ID missing in payload"))));
    }

    // Retrieve token and IDs
    $token = $data->token;
    $bookid = $data->bookid;
    $authorid = $data->authorid;

    // Validate the token
    $useridFromToken = validateToken($token);
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book-author relationship already exists
        $stmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE bookid = :bookid AND authorid = :authorid");
        $stmt->bindParam(':bookid', $bookid);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            // Respond if the relationship already exists
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book author relationship already exists"))));
        } else {
            // Insert the new relationship into the database
            $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':bookid', $bookid);
            $stmt->bindParam(':authorid', $authorid);
            $stmt->execute();

            // Mark the token as used and generate a new one
            markTokenAsUsed($token);
            $newToken = generateToken($useridFromToken);
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
        }
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});

// Display all book-author relationships
$app->get('/book_author/display', function (Request $request, Response $response) {
    // Log incoming headers for debugging
    $headers = $request->getHeaders();
    error_log("Headers: " . print_r($headers, true));

    // Get the Authorization header
    $authHeader = $request->getHeader('Authorization');
    error_log("Authorization Header: " . print_r($authHeader, true));
    if (empty($authHeader)) {
        error_log("Authorization header missing");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Authorization header missing"))));
    }

    // Extract the token from the Authorization header
    $token = str_replace('Bearer ', '', $authHeader[0]);
    error_log("Token: " . $token);

    // Validate the token
    $userid = validateToken($token);
    if (!$userid) {
        error_log("Invalid or expired token");
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Database connection parameters
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Retrieve all book-author relationships from the database
        $stmt = $conn->prepare("SELECT collectionid, bookid, authorid FROM books_authors");
        $stmt->execute();
        $bookAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($bookAuthors) {
            // Mark the token as used and generate a new one
            markTokenAsUsed($token);
            $newToken = generateToken($userid);

            return $response->write(json_encode(array("status" => "success", "token" => $newToken, "data" => $bookAuthors)));
        } else {
            // Respond if no relationships are found
            return $response->write(json_encode(array("status" => "fail", "message" => "No book authors found")));
        }
    } catch (PDOException $e) {
        // Handle any database exceptions
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    // Close the database connection
    $conn = null;
});

// Update an existing book-author relationship
$app->put('/book_author/update', function (Request $request, Response $response) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if collection ID is provided
    if (!isset($data->collectionid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID missing in payload"))));
    }

    // Retrieve token and IDs
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // Validate the token
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Retrieve data to update
    $collectionidToUpdate = $data->collectionid;
    $bookid = $data->bookid;
    $authorid = $data->authorid;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update the book-author relationship in the database
        $sql = "UPDATE books_authors SET bookid = :bookid, authorid = :authorid WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookid);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->bindParam(':collectionid', $collectionidToUpdate);
        $stmt->execute();

        // Mark the token as used and generate a new one
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);
        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});

// Delete an existing book-author relationship
$app->delete('/book_author/delete', function (Request $request, Response $response) {
    // Decode the incoming JSON payload
    $data = json_decode($request->getBody());

    // Check for JSON errors
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON Error: " . json_last_error_msg());
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid JSON payload"))));
    }

    // Check if token is present in the payload
    if (!isset($data->token)) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token missing in payload"))));
    }

    // Check if collection ID is provided
    if (!isset($data->collectionid)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Collection ID missing in payload"))));
    }

    // Retrieve token and collection ID
    $token = $data->token;
    $useridFromToken = validateToken($token);

    // Validate the token
    if (!$useridFromToken) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Your token is expired, Generate another transaction"))));
    }

    // Retrieve the collection ID to delete
    $collectionidToDelete = $data->collectionid;

    // Database connection parameters
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete the relationship from the database
        $sql = "DELETE FROM books_authors WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':collectionid', $collectionidToDelete);
        $stmt->execute();

        // Mark the token as used and generate a new one
        markTokenAsUsed($token);
        $newToken = generateToken($useridFromToken);

        $response->getBody()->write(json_encode(array("status" => "success", "token" => $newToken, "data" => null)));
    } catch (PDOException $e) {
        // Handle any database exceptions
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    // Close the database connection
    $conn = null;
    return $response;
});


// Search for books, authors, or users
$app->get('/search', function (Request $request, Response $response) {
    // Get query parameters (e.g. search keyword)
    $queryParams = $request->getQueryParams();
    if (!isset($queryParams['q'])) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Search query missing"))));
    }

    $keyword = '%' . $queryParams['q'] . '%';
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Search in books, authors, and users
        $sql = "
            SELECT 'book' as type, title as name FROM books WHERE title LIKE :keyword
            UNION
            SELECT 'author' as type, name as name FROM authors WHERE name LIKE :keyword
            UNION
            SELECT 'user' as type, username as name FROM users WHERE username LIKE :keyword
        ";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':keyword', $keyword);
        $stmt->execute();
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($results) {
            $response->getBody()->write(json_encode(array("status" => "success", "data" => $results)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No results found"))));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

// Get full catalog of books and authors 
$app->get('/catalog', function (Request $request, Response $response) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Query to get the catalog with books and authors only
        $sql = "
            SELECT 
                books.bookid, books.title, authors.name as author_name
            FROM 
                books
            LEFT JOIN 
                authors ON books.authorid = authors.authorid
        ";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $catalog = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($catalog) {
            $response->getBody()->write(json_encode(array("status" => "success", "data" => $catalog)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No catalog found"))));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->run();
?>