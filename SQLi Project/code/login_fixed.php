<?php
// Enable error reporting
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Database connection parameters
$host = '172.17.0.3';
$db = 'University_SWS';
$user = 'root';
$pass = 'rootpass';
$dsn = "mysql:host=$host;dbname=$db";

function suspicious($u, $p){

    $sus_char = "/[';,-]/i";

    if (preg_match($sus_char, $u) || preg_match($sus_char, $p)) {
        return true; // Suspicious input detected
    }
        return false;
}

// Open the database connection
try {
    $pdo = new PDO($dsn, $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // If connection fails, return a JSON error response
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Query to retrieve data (adjust to your specific query needs)
try {
    // Injection query for username below
    //  users and passwords: ' OR 1=1; --
    //                 ssns: SSNs root ' UNION SELECT Ssn, Sname FROM Student; --

    $sql = "SELECT * FROM users WHERE username = ? AND password = ? ;";
    //$sql = "SELECT * FROM Student";  // For example, retrieve all students from the 'Student' table
    $sth = $pdo->prepare($sql);

    $sus = suspicious($username, $password);
    $sth->execute( [$username, $password] );
    $rows = $sth->fetchAll(PDO::FETCH_ASSOC); // Fetch as associative array
} catch (Exception $e) {
    // If query fails, return a JSON error response
    echo json_encode(['success' => false, 'message' => 'Query execution failed: ' . $e->getMessage()]);
    exit;
}


// Return the query results as a JSON response
echo json_encode(['success' => true, 'data' => $rows, 'flag' => $sus]);
?>
