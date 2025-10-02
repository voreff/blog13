<?php
// Ultra simple API test
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// Set CORS headers
if (!empty($origin)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Max-Age: 86400');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(204);
    exit(0);
}

try {
    require_once 'config.php';
    
    $db = new Database();
    $pdo = $db->getConnection();
    
    // Simple test query
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM users");
    $userCount = $stmt->fetch()['count'];
    
    echo json_encode([
        'success' => true,
        'message' => 'API working perfectly!',
        'users' => $userCount,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Error: ' . $e->getMessage(),
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}
?>