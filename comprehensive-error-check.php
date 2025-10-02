<?php
/**
 * Comprehensive Error Check Script
 * Checks all systems for potential errors and issues
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/comprehensive-check.log');

echo "<h1>🔍 Comprehensive System Error Check</h1>";
echo "<p><strong>Check Time:</strong> " . date('Y-m-d H:i:s') . "</p>";

require_once 'api/config.php';

$errors = [];
$warnings = [];
$success = [];

try {
    // 1. Database Connection Test
    echo "<h2>📊 Database Connection Test</h2>";
    $db = Database::getInstance();
    $pdo = $db->getConnection();
    $success[] = "✅ Database connection successful";
    
    // 2. Check Table Structure
    echo "<h2>🗄️ Database Table Structure Check</h2>";
    
    $tables = ['users', 'posts', 'comments', 'likes', 'user_sessions', 'email_verifications', 'contact_messages', 'newsletter_subscribers', 'chat_messages'];
    
    foreach ($tables as $table) {
        try {
            $stmt = $pdo->query("DESCRIBE $table");
            $columns = $stmt->fetchAll();
            $success[] = "✅ Table '$table' exists with " . count($columns) . " columns";
            
            // Check specific critical columns
            if ($table === 'email_verifications') {
                $columnNames = array_column($columns, 'Field');
                if (in_array('verification_code', $columnNames)) {
                    $success[] = "✅ email_verifications has correct 'verification_code' column";
                } else {
                    $errors[] = "❌ email_verifications missing 'verification_code' column";
                }
                
                if (in_array('code_type', $columnNames)) {
                    $success[] = "✅ email_verifications has correct 'code_type' column";
                } else {
                    $errors[] = "❌ email_verifications missing 'code_type' column";
                }
                
                if (in_array('is_used', $columnNames)) {
                    $success[] = "✅ email_verifications has 'is_used' column";
                } else {
                    $warnings[] = "⚠️ email_verifications missing 'is_used' column";
                }
            }
            
            if ($table === 'users') {
                $columnNames = array_column($columns, 'Field');
                if (in_array('location', $columnNames)) {
                    $success[] = "✅ users table has 'location' column";
                } else {
                    $warnings[] = "⚠️ users table missing 'location' column";
                }
                
                if (in_array('website', $columnNames)) {
                    $success[] = "✅ users table has 'website' column";
                } else {
                    $warnings[] = "⚠️ users table missing 'website' column";
                }
            }
            
        } catch (Exception $e) {
            $errors[] = "❌ Table '$table' error: " . $e->getMessage();
        }
    }
    
    // 3. Test API Endpoints
    echo "<h2>🔌 API Endpoints Test</h2>";
    
    $endpoints = [
        'test' => '?action=test',
        'posts' => '?action=posts&page=1&limit=5',
        'captcha' => '../captcha.php'
    ];
    
    foreach ($endpoints as $name => $endpoint) {
        try {
            $url = "http://localhost/api/api.php" . $endpoint;
            if ($name === 'captcha') {
                $url = "http://localhost/api/captcha.php";
            }
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'ignore_errors' => true
                ]
            ]);
            
            $response = @file_get_contents($url, false, $context);
            
            if ($response !== false) {
                if ($name === 'captcha') {
                    $success[] = "✅ Captcha endpoint responding";
                } else {
                    $data = json_decode($response, true);
                    if ($data && isset($data['success'])) {
                        $success[] = "✅ API endpoint '$name' working";
                    } else {
                        $warnings[] = "⚠️ API endpoint '$name' unexpected response";
                    }
                }
            } else {
                $warnings[] = "⚠️ API endpoint '$name' not accessible (might be normal in CLI)";
            }
        } catch (Exception $e) {
            $warnings[] = "⚠️ API endpoint '$name' test failed: " . $e->getMessage();
        }
    }
    
    // 4. Check File Permissions
    echo "<h2>📁 File Permissions Check</h2>";
    
    $directories = [
        'uploads' => 'uploads/',
        'uploads/avatars' => 'uploads/avatars/',
        'logs' => './'
    ];
    
    foreach ($directories as $name => $path) {
        if (is_dir($path)) {
            if (is_writable($path)) {
                $success[] = "✅ Directory '$name' is writable";
            } else {
                $errors[] = "❌ Directory '$name' is not writable";
            }
        } else {
            $warnings[] = "⚠️ Directory '$name' does not exist";
        }
    }
    
    // 5. Check Session Configuration
    echo "<h2>🍪 Session Configuration Check</h2>";
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    $sessionParams = session_get_cookie_params();
    
    if ($sessionParams['secure']) {
        $success[] = "✅ Session cookies are secure";
    } else {
        $warnings[] = "⚠️ Session cookies not secure (might be normal in development)";
    }
    
    if ($sessionParams['httponly']) {
        $success[] = "✅ Session cookies are HttpOnly";
    } else {
        $errors[] = "❌ Session cookies not HttpOnly";
    }
    
    if ($sessionParams['samesite'] === 'None') {
        $success[] = "✅ Session SameSite configured for CORS";
    } else {
        $warnings[] = "⚠️ Session SameSite not configured for CORS";
    }
    
    // 6. Check PHP Extensions
    echo "<h2>🔧 PHP Extensions Check</h2>";
    
    $requiredExtensions = ['pdo', 'pdo_mysql', 'gd', 'json', 'mbstring', 'openssl'];
    
    foreach ($requiredExtensions as $ext) {
        if (extension_loaded($ext)) {
            $success[] = "✅ PHP extension '$ext' loaded";
        } else {
            $errors[] = "❌ PHP extension '$ext' not loaded";
        }
    }
    
    // 7. Check Log Files
    echo "<h2>📋 Log Files Check</h2>";
    
    $logFiles = [
        'xato.log' => 'xato.log',
        'panel.log' => 'panel.log'
    ];
    
    foreach ($logFiles as $name => $file) {
        if (file_exists($file)) {
            $size = filesize($file);
            if ($size > 0) {
                $success[] = "✅ Log file '$name' exists (" . number_format($size) . " bytes)";
            } else {
                $success[] = "✅ Log file '$name' exists (empty)";
            }
        } else {
            $warnings[] = "⚠️ Log file '$name' does not exist";
        }
    }
    
    // 8. Test SQL Queries
    echo "<h2>🔍 SQL Queries Test</h2>";
    
    try {
        // Test the problematic chat-users query
        $stmt = $pdo->prepare("SELECT u.id, u.username, u.avatar FROM users u WHERE u.id != ? AND u.is_admin = 0 LIMIT 1");
        $stmt->execute([1]);
        $result = $stmt->fetch();
        $success[] = "✅ Chat users query syntax is correct";
    } catch (Exception $e) {
        $errors[] = "❌ Chat users query failed: " . $e->getMessage();
    }
    
    try {
        // Test posts query
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM posts WHERE status = 'published'");
        $stmt->execute();
        $result = $stmt->fetch();
        $success[] = "✅ Posts query working (" . $result['count'] . " published posts)";
    } catch (Exception $e) {
        $errors[] = "❌ Posts query failed: " . $e->getMessage();
    }
    
} catch (Exception $e) {
    $errors[] = "❌ Critical error: " . $e->getMessage();
}

// Display Results
echo "<h2>📊 Check Results Summary</h2>";

echo "<h3 style='color: green;'>✅ Success (" . count($success) . ")</h3>";
foreach ($success as $item) {
    echo "<p>$item</p>";
}

if (!empty($warnings)) {
    echo "<h3 style='color: orange;'>⚠️ Warnings (" . count($warnings) . ")</h3>";
    foreach ($warnings as $item) {
        echo "<p>$item</p>";
    }
}

if (!empty($errors)) {
    echo "<h3 style='color: red;'>❌ Errors (" . count($errors) . ")</h3>";
    foreach ($errors as $item) {
        echo "<p>$item</p>";
    }
} else {
    echo "<h3 style='color: green;'>🎉 No Critical Errors Found!</h3>";
}

// Overall Status
$totalIssues = count($errors);
$totalWarnings = count($warnings);

echo "<h2>🎯 Overall System Status</h2>";

if ($totalIssues === 0 && $totalWarnings === 0) {
    echo "<p style='color: green; font-size: 18px; font-weight: bold;'>🎉 EXCELLENT: System is fully operational!</p>";
} elseif ($totalIssues === 0) {
    echo "<p style='color: orange; font-size: 18px; font-weight: bold;'>✅ GOOD: System is operational with minor warnings</p>";
} elseif ($totalIssues <= 2) {
    echo "<p style='color: red; font-size: 18px; font-weight: bold;'>⚠️ ATTENTION: System has some issues that need fixing</p>";
} else {
    echo "<p style='color: red; font-size: 18px; font-weight: bold;'>🚨 CRITICAL: System has multiple issues requiring immediate attention</p>";
}

echo "<p><strong>Total Success:</strong> " . count($success) . "</p>";
echo "<p><strong>Total Warnings:</strong> " . $totalWarnings . "</p>";
echo "<p><strong>Total Errors:</strong> " . $totalIssues . "</p>";

echo "<hr>";
echo "<p><em>Check completed at: " . date('Y-m-d H:i:s') . "</em></p>";
?>
