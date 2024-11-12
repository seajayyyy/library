<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php'; 
$app = new \Slim\App; 

// Registration
$app->post('/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $usr = $data['username'] ?? null;
    $pass = $data['password'] ?? null;

    if (!$usr || !$pass) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Username and password are required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO users(username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);

        $hashedPassword = password_hash($pass, PASSWORD_DEFAULT);
        $stmt->bindParam(':username', $usr);
        $stmt->bindParam(':password', $hashedPassword);

        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        return $response->withStatus(200);
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "data" => array("title" => "Database error: " . $e->getMessage()))));
    }
});

// Authentication
$app->post('/authenticate', function (Request $request, Response $response, array $args) {
    // Decode request body 
    $data = json_decode($request->getBody(), true); 
    $usr = $data['username'] ?? null; 
    $pass = $data['password'] ?? null; 

    if (!$usr || !$pass) { 
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Username and password are required")))); 
    } 

    $servername = "localhost"; 
    $username = "root"; 
    $password = "";
    $dbname = "library";

    try { 
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password); 
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); 

        $sql = "SELECT * FROM users WHERE username = :username"; 
        $stmt = $conn->prepare($sql); 
        $stmt->bindParam(':username', $usr); 
        $stmt->execute(); 
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data && password_verify($pass, $data['password'])) {
            // Token generation and response logic...
        } else { 
            return $response->withStatus(401)->write(json_encode(["status" => "fail", "data" => ["title" => "Authentication Failed"]]));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
    }

    return $response;
});


// Middleware to validate the token 
function validateToken(Request $request, Response $response, $next) {
    // Check if the token is provided in the query parameters
    $queryParams = $request->getQueryParams();
    $token = $queryParams['token'] ?? null;

    if (!$token) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "No token provided")));
    }

    $secretKey = "your_secret_key"; // The same secret key used to generate the token

    try {
        // Decode the token
        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
        
        // Check if the token is used
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check the token in the database
        $sqlTokenCheck = "SELECT * FROM tokens WHERE token = :token AND used = 0";
        $stmtTokenCheck = $conn->prepare($sqlTokenCheck);
        $stmtTokenCheck->bindParam(':token', $token);
        $stmtTokenCheck->execute();
        $tokenData = $stmtTokenCheck->fetch(PDO::FETCH_ASSOC);

        if (!$tokenData) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized - Invalid or already used token")));
        }

        // Mark token as used
        $sqlTokenUpdate = "UPDATE tokens SET used = 1 WHERE token = :token";
        $stmtTokenUpdate = $conn->prepare($sqlTokenUpdate);
        $stmtTokenUpdate->bindParam(':token', $token);
        $stmtTokenUpdate->execute();

        return $next($request, $response);
    } catch (Exception $e) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized - Invalid token")));
    }
}




// Routes for adding and updating books and authors
$app->post('/books/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $title = $data['title'] ?? null;

    if (!$title) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book title is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO books (title) VALUES (:title)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->execute();

        // Get the ID of the newly inserted book
        $bookId = $conn->lastInsertId();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book added successfully", "book_id" => $bookId)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');


// Updating a book
$app->put('/books/update/{id}', function (Request $request, Response $response, array $args) {
    $bookId = $args['id'];
    $data = json_decode($request->getBody(), true);
    $title = $data['title'] ?? null;

    if (!$title) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Book title is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title WHERE bookid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':id', $bookId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book updated successfully")));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

// Adding a new author
$app->post('/authors/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $name = $data['name'] ?? null;

    if (!$name) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->execute();

        // Get the ID of the newly inserted author
        $authorId = $conn->lastInsertId();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author added successfully", "author_id" => $authorId)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');


// Updating an author
$app->put('/authors/update/{id}', function (Request $request, Response $response, array $args) {
    $authorId = $args['id'];
    $data = json_decode($request->getBody(), true);
    $name = $data['name'] ?? null;

    if (!$name) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE authors SET name = :name WHERE authorid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':id', $authorId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author updated successfully")));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

$app->delete('/delete/{bookid}/{authorid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    $authorid = $args['authorid'];

    if (!$bookid && !$authorid) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "At least one of bookid or authorid is required.")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Begin transaction to ensure atomic operations
        $conn->beginTransaction();

        $deletedBooks = 0;
        $deletedAuthors = 0;

        // Delete from `books` table if bookid is provided
        if ($bookid) {
            $sqlBook = "DELETE FROM books WHERE bookid = :bookid";
            $stmtBook = $conn->prepare($sqlBook);
            $stmtBook->bindParam(':bookid', $bookid);
            $stmtBook->execute();
            $deletedBooks = $stmtBook->rowCount();  // Count how many rows were deleted
        }

        // Delete from `authors` table if authorid is provided
        if ($authorid) {
            $sqlAuthor = "DELETE FROM authors WHERE authorid = :authorid";
            $stmtAuthor = $conn->prepare($sqlAuthor);
            $stmtAuthor->bindParam(':authorid', $authorid);
            $stmtAuthor->execute();
            $deletedAuthors = $stmtAuthor->rowCount();  // Count how many rows were deleted
        }

        // Commit the transaction
        $conn->commit();

        // Build response message
        $responseMessage = array("status" => "success");

        if ($deletedBooks > 0) {
            $responseMessage['message'][] = "Book(s) deleted successfully.";
        }
        if ($deletedAuthors > 0) {
            $responseMessage['message'][] = "Author(s) deleted successfully.";
        }
        if ($deletedBooks == 0 && $deletedAuthors == 0) {
            $responseMessage['message'] = "No book or author found to delete.";
        }

        $response->getBody()->write(json_encode($responseMessage));
    } catch (PDOException $e) {
        // Rollback the transaction in case of an error
        $conn->rollBack();
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');


$app->post('/books-authors/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $bookid = $data['bookid'] ?? null;
    $authorid = $data['authorid'] ?? null;

    if (!$bookid || !$authorid) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Both bookid and authorid are required.")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Insert into the books_authors table
        $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookid);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();

        // Retrieve the last inserted collectionid
        $collectionid = $conn->lastInsertId();

        // Return success response with collectionid
        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "message" => "Book-Author association added successfully",
            "collectionid" => $collectionid
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

$app->put('/books-authors/update/{collectionid}', function (Request $request, Response $response, array $args) {
    $collectionid = $args['collectionid'];
    $data = json_decode($request->getBody(), true);
    $bookid = $data['bookid'] ?? null;
    $authorid = $data['authorid'] ?? null;

    // Check if at least one field is provided for update
    if (!$bookid && !$authorid) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "At least one of bookid or authorid is required for updating.")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Begin SQL update query
        $sql = "UPDATE books_authors SET ";
        $params = [];

        if ($bookid) {
            $sql .= "bookid = :bookid ";
            $params[':bookid'] = $bookid;
        }

        if ($authorid) {
            if ($bookid) {
                $sql .= ", "; // Add a comma if bookid is already part of the query
            }
            $sql .= "authorid = :authorid ";
            $params[':authorid'] = $authorid;
        }

        $sql .= "WHERE collectionid = :collectionid";
        $params[':collectionid'] = $collectionid;

        // Prepare and execute the SQL statement
        $stmt = $conn->prepare($sql);
        foreach ($params as $key => &$val) {
            $stmt->bindParam($key, $val);
        }
        $stmt->execute();

        // Check if any rows were updated
        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(array("status" => "success", "message" => "Books-Authors entry updated successfully.")));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "message" => "No entry found with the given collectionid or no changes made.")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

$app->delete('/books-authors/delete', function (Request $request, Response $response, array $args) {
    $data = $request->getQueryParams();
    $collectionid = $data['collectionid'] ?? null;
    $bookid = $data['bookid'] ?? null;
    $authorid = $data['authorid'] ?? null;

    if (!$collectionid && !$bookid && !$authorid) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "At least one of collectionid, bookid, or authorid is required.")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $conn->beginTransaction(); // Start transaction to ensure atomic operation

        $deletedRecords = 0;

        // Delete based on collectionid, bookid, or authorid
        if ($collectionid) {
            $sql = "DELETE FROM books_authors WHERE collectionid = :collectionid";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':collectionid', $collectionid);
            $stmt->execute();
            $deletedRecords = $stmt->rowCount();
        } elseif ($bookid) {
            $sql = "DELETE FROM books_authors WHERE bookid = :bookid";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':bookid', $bookid);
            $stmt->execute();
            $deletedRecords = $stmt->rowCount();
        } elseif ($authorid) {
            $sql = "DELETE FROM books_authors WHERE authorid = :authorid";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':authorid', $authorid);
            $stmt->execute();
            $deletedRecords = $stmt->rowCount();
        }

        $conn->commit(); // Commit transaction

        if ($deletedRecords > 0) {
            $response->getBody()->write(json_encode(array("status" => "success", "message" => "$deletedRecords record(s) deleted successfully.")));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "message" => "No matching record found to delete.")));
        }
    } catch (PDOException $e) {
        $conn->rollBack(); // Rollback transaction in case of failure
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');


$app->run();
