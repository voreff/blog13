<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../xato.log');

echo "<h1>Database Connection Test</h1>";

try {
    $host = 'localhost';
    $dbname = 'stacknro_blog';
    $username = 'stacknro_blog';
    $password = 'admin-2025';
    
    echo "<p>Attempting to connect to database...</p>";
    echo "<p>Host: $host</p>";
    echo "<p>Database: $dbname</p>";
    echo "<p>Username: $username</p>";
    
    $dsn = "mysql:host=$host;dbname=$dbname;charset=utf8mb4";
    $pdo = new PDO($dsn, $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
    
    echo "<p style='color: green;'>✅ Database connection successful!</p>";
    
    // Test tables
    $tables = ['users', 'posts', 'comments', 'likes', 'chat_messages', 'contact_messages', 'newsletter_subscribers'];
    
    echo "<h2>Table Status:</h2>";
    foreach ($tables as $table) {
        try {
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM $table");
            $count = $stmt->fetch()['count'];
            echo "<p style='color: green;'>✅ Table '$table': $count records</p>";
        } catch (Exception $e) {
            echo "<p style='color: red;'>❌ Table '$table': " . $e->getMessage() . "</p>";
        }
    }
    
    // Test API endpoint
    echo "<h2>API Test:</h2>";
    $testUrl = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . "/api.php?action=test";
    echo "<p>Testing: <a href='$testUrl' target='_blank'>$testUrl</a></p>";
    
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'ignore_errors' => true
        ]
    ]);
    
    $response = file_get_contents($testUrl, false, $context);
    if ($response) {
        $data = json_decode($response, true);
        if ($data && $data['success']) {
            echo "<p style='color: green;'>✅ API Test successful: " . $data['message'] . "</p>";
        } else {
            echo "<p style='color: red;'>❌ API Test failed: " . ($data['message'] ?? 'Unknown error') . "</p>";
        }
    } else {
        echo "<p style='color: red;'>❌ API Test failed: No response</p>";
    }
    
} catch (PDOException $e) {
    echo "<p style='color: red;'>❌ Database connection failed: " . $e->getMessage() . "</p>";
    error_log("Database test failed: " . $e->getMessage());
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ General error: " . $e->getMessage() . "</p>";
    error_log("General test error: " . $e->getMessage());
}

echo "<h2>PHP Info:</h2>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Extensions: " . implode(', ', get_loaded_extensions()) . "</p>";
echo "<p>Error Log: " . ini_get('error_log') . "</p>";
?>