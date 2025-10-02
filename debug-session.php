<?php
/**
 * Session Debug Script
 * Bu script session va cookie ishlashini tekshirish uchun
 */

// CORS headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, Cookie, Authorization');
header('Content-Type: application/json; charset=utf-8');

// Session configuration
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_samesite', 'None');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_lifetime', '3600');
    ini_set('session.gc_maxlifetime', 3600);
    ini_set('session.use_cookies', '1');
    ini_set('session.use_only_cookies', '1');
    
    session_name('BLOG_SESSION');
    session_start();
}

// Set test captcha if not exists
if (!isset($_SESSION['captcha'])) {
    $_SESSION['captcha'] = 'test123';
}

// Collect debug information
$debugInfo = [
    'session_status' => session_status(),
    'session_id' => session_id(),
    'session_name' => session_name(),
    'session_data' => $_SESSION,
    'cookie_params' => session_get_cookie_params(),
    'cookies_sent' => headers_list(),
    'http_headers' => [
        'HTTP_COOKIE' => $_SERVER['HTTP_COOKIE'] ?? 'No cookies',
        'HTTP_ORIGIN' => $_SERVER['HTTP_ORIGIN'] ?? 'No origin',
        'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'] ?? 'No user agent',
        'REQUEST_METHOD' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown method'
    ],
    'php_info' => [
        'version' => PHP_VERSION,
        'session_save_path' => session_save_path(),
        'session_module_name' => session_module_name()
    ],
    'timestamp' => date('Y-m-d H:i:s')
];

// Return debug information
echo json_encode([
    'success' => true,
    'message' => 'Session debug information',
    'debug' => $debugInfo
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
?>
