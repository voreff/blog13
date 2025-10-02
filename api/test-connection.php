<?php
// Simple connection test without complex logging
error_reporting(E_ALL);
ini_set('display_errors', 1);

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
    
    // Test basic functionality
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM users");
    $userCount = $stmt->fetch()['count'];
    echo "<p>👥 Users: $userCount</p>";
    
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM posts");
    $postCount = $stmt->fetch()['count'];
    echo "<p>📝 Posts: $postCount</p>";
    
    // Test admin user
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM users WHERE is_admin = 1");
    $adminCount = $stmt->fetch()['count'];
    echo "<p>👨‍💼 Admin users: $adminCount</p>";
    
    if ($adminCount == 0) {
        echo "<p style='color: orange;'>⚠️ No admin user found. Run dbstarter.php to create one.</p>";
    }
    
    echo "<h2>✅ All tests passed!</h2>";
    
} catch (PDOException $e) {
    echo "<p style='color: red;'>❌ Database connection failed: " . $e->getMessage() . "</p>";
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ General error: " . $e->getMessage() . "</p>";
}

echo "<h2>System Info:</h2>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Server: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "</p>";
echo "<p>Current Time: " . date('Y-m-d H:i:s') . "</p>";
?>