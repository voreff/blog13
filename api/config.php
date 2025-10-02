<?php
/**
 * Database configuration and utility functions
 */
class Database {
    private static $instance = null;
    private $pdo;
    private $host = 'localhost';
    private $dbname = 'stacknro_blog';
    private $username = 'stacknro_blog';
    private $password = 'admin-2025';
    private $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => true,
        PDO::ATTR_TIMEOUT => 5,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
    ];
    
    /**
     * Get database instance (singleton pattern)
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private function __construct() {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->dbname};charset=utf8mb4";
            $this->pdo = new PDO($dsn, $this->username, $this->password, $this->options);
            
            // Test the connection
            $this->pdo->query('SELECT 1');
            
            error_log("[DATABASE] Connection established: " . date('Y-m-d H:i:s'));
        } catch (PDOException $e) {
            $error = "[DATABASE] Connection failed: " . $e->getMessage();
            error_log($error);
            throw new Exception('Database connection error. Please try again later.');
        }
    }
    
    /**
     * Prevent cloning of the instance
     */
    private function __clone() {}
    
    /**
     * Prevent unserializing of the instance
     */
    public function __wakeup() {
        throw new Exception('Cannot unserialize singleton');
    }
    
    /**
     * Get the PDO connection
     */
    public function getConnection() {
        // Verify connection is still alive
        try {
            $this->pdo->query('SELECT 1');
        } catch (PDOException $e) {
            // Reconnect if connection was lost
            $this->__construct();
        }
        return $this->pdo;
    }
}

// Utility functions
function sanitizeInput($data) {
    if ($data === null) {
        return '';
    }
    if ($data === '') {
        return '';
    }
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) && str_ends_with(strtolower($email), '@gmail.com');
}

function validateCaptcha($provided, $expected) {
    // Check captcha expiration (5 minutes)
    $captchaTime = $_SESSION['captcha_time'] ?? 0;
    $currentTime = time();
    $maxAge = 300; // 5 minutes
    
    if (($currentTime - $captchaTime) > $maxAge) {
        error_log("[CAPTCHA VALIDATION] Captcha expired - Age: " . ($currentTime - $captchaTime) . "s");
        return false;
    }
    
    // Detailed logging for debugging
    $sessionId = session_id();
    $debugInfo = [
        'provided' => $provided,
        'expected' => $expected,
        'session_id' => $sessionId,
        'timestamp' => date('Y-m-d H:i:s'),
        'captcha_age' => ($currentTime - $captchaTime),
        'match' => !empty($provided) && !empty($expected) && strtolower($provided) === strtolower($expected)
    ];
    error_log("[CAPTCHA VALIDATION] " . json_encode($debugInfo));
    
    return !empty($provided) && !empty($expected) && strtolower($provided) === strtolower($expected);
}

function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// Logging functions
function logSuccess($message, $context = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => 'SUCCESS',
        'message' => $message,
        'context' => $context,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    error_log(json_encode($logEntry));
}

function logError($message, $context = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => 'ERROR',
        'message' => $message,
        'context' => $context,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    error_log(json_encode($logEntry));
}

function logInfo($message, $context = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => 'INFO',
        'message' => $message,
        'context' => $context
    ];
    error_log(json_encode($logEntry));
}
?>