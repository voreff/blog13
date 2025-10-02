<?php
// Newsletter subscription endpoint
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Get origin from request
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// Set CORS headers - allow all origins
if (!empty($origin)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Max-Age: 86400'); // Cache preflight for 24 hours
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(204);
    exit(0);
}

try {
    require_once 'config.php';
    
    $db = new Database();
    $pdo = $db->getConnection();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $data = json_decode(file_get_contents('php://input'), true);
        
        if (!$data || !isset($data['email'])) {
            jsonResponse(['success' => false, 'message' => 'Email majburiy']);
        }
        
        $email = sanitizeInput($data['email']);
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri email format']);
        }
        
        // Check if already subscribed
        $stmt = $pdo->prepare("SELECT id FROM newsletter_subscribers WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            jsonResponse(['success' => false, 'message' => 'Bu email allaqachon obuna bo\'lgan']);
        }
        
        // Add to newsletter
        $stmt = $pdo->prepare("INSERT INTO newsletter_subscribers (email, created_at) VALUES (?, NOW())");
        $stmt->execute([$email]);
        
        jsonResponse(['success' => true, 'message' => 'Muvaffaqiyatli obuna bo\'ldingiz! 🎉']);
    }
    
    // GET request - return subscriber count
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM newsletter_subscribers WHERE is_active = 1");
        $count = $stmt->fetch()['count'];
        
        jsonResponse(['success' => true, 'subscribers' => $count]);
    }
    
} catch (Exception $e) {
    error_log("Newsletter error: " . $e->getMessage());
    jsonResponse(['success' => false, 'message' => 'Server xatosi yuz berdi']);
}
?>