<?php
// Security headers and error reporting
header_remove('X-Powered-By');
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../xato.log');

// Get origin from request
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// Allow all origins - Open CORS policy
$allowedOrigin = !empty($origin) ? $origin : '*';

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: ' . $allowedOrigin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, Authorization, Cookie');
    header('Access-Control-Max-Age: 86400'); // Cache preflight for 24 hours
    http_response_code(204);
    exit;
}

// Set CORS headers for actual request - Allow all origins
header('Access-Control-Allow-Origin: ' . $allowedOrigin);
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, Authorization, Cookie');
header('Content-Type: application/json; charset=utf-8');

// Configure session settings before starting session
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_samesite', 'None');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_lifetime', '0');
    ini_set('session.gc_maxlifetime', 86400); // 24 hours
    session_name('BLOG_SESSION');
    session_start();
}

// Helper function to verify user authentication via cookies or token
function verifyUserAuth() {
    // Check session-based authentication first
    if (isset($_SESSION['user_id']) && isset($_SESSION['user_token'])) {
        return $_SESSION['user_id'];
    }
    
    // Fallback to token-based authentication
    $token = $_GET['token'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token = str_replace('Bearer ', '', $token);
    
    if ($token) {
        global $pdo;
        $stmt = $pdo->prepare("SELECT user_id FROM user_sessions WHERE session_token = ? AND expires_at > NOW()");
        $stmt->execute([$token]);
        $session = $stmt->fetch();
        
        if ($session) {
            // Set session for future requests
            $_SESSION['user_id'] = $session['user_id'];
            $_SESSION['user_token'] = $token;
            return $session['user_id'];
        }
    }
    
    return null;
}

/**
 * Implements rate limiting using session storage
 * Allows 250 requests per minute per IP address
 */
if (!function_exists('checkRateLimit')) {
    function checkRateLimit() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            error_log("[RATE LIMIT] Session not active");
            return;
        }
        
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $rateLimit = 250; // Max requests
        $timeWindow = 60; // 1 minute in seconds
        $now = time();
        
        // Initialize rate limit data in session if not exists
        if (!isset($_SESSION['rate_limit'])) {
            $_SESSION['rate_limit'] = [
                'count' => 1,
                'first_request' => $now,
                'last_request' => $now,
                'ip' => $ip
            ];
            error_log("[RATE LIMIT] New session - IP: $ip, Count: 1");
            return;
        }
    
        $rateData = &$_SESSION['rate_limit'];
        
        // Reset rate limit if IP changed
        if (($rateData['ip'] ?? '') !== $ip) {
            $rateData = [
                'count' => 1,
                'first_request' => $now,
                'last_request' => $now,
                'ip' => $ip
            ];
            error_log("[RATE LIMIT] IP changed - New IP: $ip");
            return;
        }
        
        // If still within the time window
        if (($now - $rateData['first_request']) < $timeWindow) {
            // Increment request count
            $rateData['count']++;
            $rateData['last_request'] = $now;
            
            // Check if rate limit exceeded
            if ($rateData['count'] > $rateLimit) {
                $retryAfter = $timeWindow - ($now - $rateData['first_request']);
                error_log("[RATE LIMIT] Rate limit exceeded - IP: $ip, Count: {$rateData['count']}, Retry after: {$retryAfter}s");
                
                http_response_code(429); // Too Many Requests
                header('Retry-After: ' . $retryAfter);
                echo json_encode([
                    'success' => false,
                    'message' => 'Rate limit exceeded. Please try again later.'
                ]);
                exit;
            }
        } else {
            // Reset counter if time window has passed
            $rateData = [
                'count' => 1,
                'first_request' => $now,
                'last_request' => $now
            ];
        }
        
        // Update last request time
        $rateData['last_request'] = $now;
    }
}

// Rate limiting check
checkRateLimit();

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    // Don't log every preflight - just exit
    http_response_code(204);
    exit(0);
}

try {
    error_log("API request started: " . json_encode([
        'method' => $_SERVER['REQUEST_METHOD'],
        'action' => $_GET['action'] ?? 'none',
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'origin' => $origin,
        'timestamp' => date('Y-m-d H:i:s')
    ]));
    
    error_log("[SESSION] Started - ID: " . session_id() . " | Captcha: " . ($_SESSION['captcha'] ?? 'NOT SET') . " | Cookie params: " . json_encode(session_get_cookie_params()));
    require_once 'config.php';
    require_once 'email-verification.php';

    $db = Database::getInstance();
    $pdo = $db->getConnection();
    $emailVerification = new EmailVerification($pdo);

    $method = $_SERVER['REQUEST_METHOD'];
    $request = $_GET['action'] ?? '';
    
    error_log("Processing request: " . json_encode(['action' => $request, 'method' => $method]));

    switch ($request) {
        case 'register':
            if ($method === 'POST') {
                logInfo("Register request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data received for registration");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $username = sanitizeInput($data['username'] ?? '');
                $email = sanitizeInput($data['email'] ?? '');
                $password = $data['password'] ?? '';
                $captcha = $data['captcha'] ?? '';
                
                logInfo("Registration data processed", ['username' => $username, 'email' => $email]);
                
                // Validate captcha - CRITICAL SECURITY CHECK
                if (empty($captcha)) {
                    logError("Missing captcha for registration", ['provided' => $captcha]);
                    jsonResponse(['success' => false, 'message' => 'Captcha kodi kiritilishi shart']);
                }
                
                if (!validateCaptcha($captcha, $_SESSION['captcha'] ?? '')) {
                    logError("Captcha validation failed", ['provided' => $captcha, 'expected' => $_SESSION['captcha'] ?? '']);
                    jsonResponse(['success' => false, 'message' => 'Captcha noto\'g\'ri']);
                }
                
                // Clear captcha after use for security
                unset($_SESSION['captcha']);
                
                // Validate email
                if (!validateEmail($email)) {
                    logError("Email validation failed", ['email' => $email]);
                    jsonResponse(['success' => false, 'message' => 'Faqat @gmail.com manzillari qabul qilinadi']);
                }
                
                // Check if user exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
                $stmt->execute([$username, $email]);
                if ($stmt->fetch()) {
                    logError("User already exists", ['username' => $username, 'email' => $email]);
                    jsonResponse(['success' => false, 'message' => 'Foydalanuvchi yoki email allaqachon mavjud']);
                }
                
                // Send verification email
                $result = $emailVerification->sendVerificationEmail($email, 'registration');
                if ($result['success']) {
                    // Store user data temporarily
                    $_SESSION['temp_user'] = [
                        'username' => $username,
                        'email' => $email,
                        'password' => password_hash($password, PASSWORD_DEFAULT)
                    ];
                    logSuccess("Registration email sent", ['email' => $email]);
                    jsonResponse(['success' => true, 'message' => 'Tasdiqlash kodi emailingizga yuborildi']);
                } else {
                    logError("Email sending failed", $result);
                    jsonResponse(['success' => false, 'message' => $result['message']]);
                }
            }
            break;

        case 'get-user-likes':
            if ($method === 'GET') {
                logInfo("Get user likes request received");
                // Verify user (cookie session or token)
                $userId = verifyUserAuth();
                if (!$userId) {
                    logError("Invalid authentication for get-user-likes");
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }

                $stmt = $pdo->prepare("SELECT post_id FROM likes WHERE user_id = ?");
                $stmt->execute([$userId]);
                $rows = $stmt->fetchAll();
                $likedPosts = array_map(function($r) { return (int)$r['post_id']; }, $rows);

                logSuccess("User likes retrieved", ['user_id' => $userId, 'count' => count($likedPosts)]);
                jsonResponse(['success' => true, 'liked_posts' => $likedPosts]);
            }
            break;
            
        case 'verify-email':
            if ($method === 'POST') {
                logInfo("Email verification request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for email verification");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $code = $data['code'] ?? '';
                $email = $_SESSION['temp_user']['email'] ?? '';
                
                if (!$email) {
                    logError("No temp user email found in session");
                    jsonResponse(['success' => false, 'message' => 'Sessiya muddati tugagan']);
                }
                
                $result = $emailVerification->verifyCode($email, $code, 'registration');
                if ($result['success']) {
                    // Create user account
                    $tempUser = $_SESSION['temp_user'];
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, 1)");
                    $stmt->execute([$tempUser['username'], $tempUser['email'], $tempUser['password']]);
                    
                    unset($_SESSION['temp_user']);
                    logSuccess("User registration completed", ['email' => $email]);
                    jsonResponse(['success' => true, 'message' => 'Ro\'yxatdan o\'tish muvaffaqiyatli yakunlandi!']);
                } else {
                    logError("Email verification failed", $result);
                    jsonResponse(['success' => false, 'message' => $result['message']]);
                }
            }
            break;
            
        case 'login':
            if ($method === 'POST') {
                logInfo("Login request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for login");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $email = sanitizeInput($data['email'] ?? '');
                $password = $data['password'] ?? '';
                $captcha = $data['captcha'] ?? '';
                
                logInfo("Login attempt", ['email' => $email]);
                
                // Validate captcha - CRITICAL SECURITY CHECK
                if (empty($captcha)) {
                    logError("Missing captcha for login", ['provided' => $captcha]);
                    jsonResponse(['success' => false, 'message' => 'Captcha kodi kiritilishi shart']);
                }
                
                if (!validateCaptcha($captcha, $_SESSION['captcha'] ?? '')) {
                    logError("Login captcha validation failed", ['provided' => $captcha, 'expected' => $_SESSION['captcha'] ?? '']);
                    jsonResponse(['success' => false, 'message' => 'Captcha noto\'g\'ri']);
                }
                
                // Clear captcha after use for security
                unset($_SESSION['captcha']);
                
                $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND is_verified = 1");
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password'])) {
                    // Create session
                    $sessionToken = generateSecureToken();
                    $expiresAt = date('Y-m-d H:i:s', time() + 86400); // 24 hours
                    
                    $stmt = $pdo->prepare("INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)");
                    $stmt->execute([$user['id'], $sessionToken, $expiresAt]);
                    
                    // Set session variables for cookie-based auth
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_token'] = $sessionToken;
                    $_SESSION['user_email'] = $email;
                    
                    unset($user['password']);
                    logSuccess("User logged in successfully", ['user_id' => $user['id'], 'email' => $email]);
                    jsonResponse([
                        'success' => true,
                        'message' => 'Muvaffaqiyatli tizimga kirdingiz!',
                        'user' => $user,
                        'token' => $sessionToken
                    ]);
                } else {
                    logError("Login failed - invalid credentials", ['email' => $email]);
                    jsonResponse(['success' => false, 'message' => 'Email yoki parol noto\'g\'ri']);
                }
            }
            break;
            
        case 'posts':
            if ($method === 'GET') {
                logInfo("Posts request received");
                $page = (int)($_GET['page'] ?? 1);
                $limit = (int)($_GET['limit'] ?? 10);
                $search = $_GET['search'] ?? '';
                $category = $_GET['category'] ?? '';
                $offset = ($page - 1) * $limit;
                
                logInfo("Posts query parameters", ['page' => $page, 'limit' => $limit, 'search' => $search, 'category' => $category]);
                
                $whereClause = "WHERE p.status = 'published'";
                $params = [];
                
                if ($search) {
                    $whereClause .= " AND (p.title LIKE ? OR p.content LIKE ? OR p.hashtags LIKE ?)";
                    $searchTerm = "%$search%";
                    $params[] = $searchTerm;
                    $params[] = $searchTerm;
                    $params[] = $searchTerm;
                }
                
                if ($category) {
                    $whereClause .= " AND p.hashtags LIKE ?";
                    $params[] = "%$category%";
                }
                
                $sql = "SELECT p.*, u.username, u.avatar,
                               COALESCE((SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id), 0) as like_count,
                               COALESCE((SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id), 0) as comment_count
                        FROM posts p 
                        JOIN users u ON p.author_id = u.id 
                        $whereClause
                        ORDER BY p.created_at DESC 
                        LIMIT $limit OFFSET $offset";
                
                logInfo("Executing posts query", ['sql' => $sql, 'params' => $params]);
                
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                $posts = $stmt->fetchAll();
                
                logSuccess("Posts retrieved successfully", ['count' => count($posts)]);
                jsonResponse(['success' => true, 'posts' => $posts]);
            }
            break;
            
        case 'post':
            if ($method === 'GET') {
                $id = $_GET['id'] ?? 0;
                logInfo("Single post request", ['post_id' => $id]);
                
                $stmt = $pdo->prepare("SELECT p.*, u.username, u.avatar,
                                             COALESCE((SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id), 0) as like_count,
                                             COALESCE((SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id), 0) as comment_count
                                      FROM posts p 
                                      JOIN users u ON p.author_id = u.id 
                                      WHERE p.id = ? AND p.status = 'published'");
                $stmt->execute([$id]);
                $post = $stmt->fetch();
                
                if ($post) {
                    // Increment views
                    $stmt = $pdo->prepare("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?");
                    $stmt->execute([$id]);
                    
                    logSuccess("Post retrieved and view incremented", ['post_id' => $id, 'title' => $post['title']]);
                    jsonResponse(['success' => true, 'post' => $post]);
                } else {
                    logError("Post not found", ['post_id' => $id]);
                    jsonResponse(['success' => false, 'message' => 'Post topilmadi'], 404);
                }
            }
            break;
            
        case 'like':
            if ($method === 'POST') {
                logInfo("Like request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for like");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $postId = $data['post_id'] ?? 0;
                
                logInfo("Like request data", ['post_id' => $postId]);
                
                // Verify user authentication
                $userId = verifyUserAuth();
                
                if (!$userId) {
                    logError("Invalid authentication for like");
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                
                // Check if already liked
                $stmt = $pdo->prepare("SELECT id FROM likes WHERE user_id = ? AND post_id = ?");
                $stmt->execute([$userId, $postId]);
                $existingLike = $stmt->fetch();
                
                if ($existingLike) {
                    // Unlike
                    $stmt = $pdo->prepare("DELETE FROM likes WHERE user_id = ? AND post_id = ?");
                    $stmt->execute([$userId, $postId]);
                    $action = 'unliked';
                } else {
                    // Like
                    $stmt = $pdo->prepare("INSERT INTO likes (user_id, post_id) VALUES (?, ?)");
                    $stmt->execute([$userId, $postId]);
                    $action = 'liked';
                }
                
                // Get updated like count
                $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM likes WHERE post_id = ?");
                $stmt->execute([$postId]);
                $likeCount = $stmt->fetch()['count'];
                
                logSuccess("Like action completed", ['action' => $action, 'post_id' => $postId, 'user_id' => $userId, 'like_count' => $likeCount]);
                jsonResponse(['success' => true, 'action' => $action, 'like_count' => $likeCount]);
            }
            break;
            
        case 'comments':
            if ($method === 'GET') {
                $postId = $_GET['post_id'] ?? 0;
                logInfo("Comments request", ['post_id' => $postId]);
                $limit = (int)($_GET['limit'] ?? 30);
                $offset = (int)($_GET['offset'] ?? 0);
                if ($limit <= 0 || $limit > 100) { $limit = 30; }
                if ($offset < 0) { $offset = 0; }
                
                $sql = "SELECT c.*, u.username, u.avatar 
                                      FROM comments c 
                                      JOIN users u ON c.user_id = u.id 
                                      WHERE c.post_id = ? 
                                      ORDER BY c.created_at DESC 
                                      LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$postId]);
                $comments = $stmt->fetchAll();
                
                logSuccess("Comments retrieved", ['post_id' => $postId, 'count' => count($comments)]);
                jsonResponse(['success' => true, 'comments' => $comments]);
            } elseif ($method === 'POST') {
                logInfo("Add comment request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for comment");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $token = $data['token'] ?? '';
                $postId = $data['post_id'] ?? 0;
                $content = sanitizeInput($data['content'] ?? '');
                
                logInfo("Comment data", ['post_id' => $postId, 'content_length' => strlen($content)]);
                
                // Verify user session
                $stmt = $pdo->prepare("SELECT user_id FROM user_sessions WHERE session_token = ? AND expires_at > NOW()");
                $stmt->execute([$token]);
                $session = $stmt->fetch();
                
                if (!$session) {
                    logError("Invalid session for comment", ['token' => substr($token, 0, 10) . '...']);
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                
                $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)");
                $stmt->execute([$postId, $session['user_id'], $content]);
                
                logSuccess("Comment added", ['post_id' => $postId, 'user_id' => $session['user_id']]);
                jsonResponse(['success' => true, 'message' => 'Izoh qo\'shildi']);
            }
            break;
            
        case 'contact':
            if ($method === 'POST') {
                logInfo("Contact request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for contact");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $name = sanitizeInput($data['name'] ?? '');
                $email = sanitizeInput($data['email'] ?? '');
                $message = sanitizeInput($data['message'] ?? '');
                $captcha = $data['captcha'] ?? '';
                
                logInfo("Contact form data", ['name' => $name, 'email' => $email]);
                
                // Validate captcha - CRITICAL SECURITY CHECK
                if (empty($captcha)) {
                    logError("Missing captcha for contact", ['provided' => $captcha]);
                    jsonResponse(['success' => false, 'message' => 'Captcha kodi kiritilishi shart']);
                }
                
                if (!validateCaptcha($captcha, $_SESSION['captcha'] ?? '')) {
                    logError("Contact captcha validation failed", ['provided' => $captcha, 'expected' => $_SESSION['captcha'] ?? '']);
                    jsonResponse(['success' => false, 'message' => 'Captcha noto\'g\'ri']);
                }
                
                // Clear captcha after use for security
                unset($_SESSION['captcha']);
                
                $stmt = $pdo->prepare("INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)");
                $stmt->execute([$name, $email, $message]);
                
                logSuccess("Contact message saved", ['name' => $name, 'email' => $email]);
                jsonResponse(['success' => true, 'message' => 'Sizning habaringiz yuborildi']);
            }
            break;

        case 'chat-users':
            if ($method === 'GET') {
                logInfo("Chat users request received");
                $token = $_GET['token'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
                $token = str_replace('Bearer ', '', $token);
                $search = $_GET['search'] ?? '';
                $limit = (int)($_GET['limit'] ?? 30);
                $offset = (int)($_GET['offset'] ?? 0);
                if ($limit <= 0 || $limit > 100) { $limit = 30; }
                if ($offset < 0) { $offset = 0; }
                
                logInfo("Chat users request data", ['search' => $search]);
                
                // Verify user session
                $stmt = $pdo->prepare("SELECT user_id FROM user_sessions WHERE session_token = ? AND expires_at > NOW()");
                $stmt->execute([$token]);
                $session = $stmt->fetch();
                
                if (!$session) {
                    logError("Invalid session for chat users", ['token' => substr($token, 0, 10) . '...']);
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                
                $currentUserId = $session['user_id'];
                
                // Build WHERE clause for filtering users
                $whereParams = [$currentUserId];
                $whereClause = "WHERE u.id != ? AND u.is_admin = 0";
                
                if ($search) {
                    $whereClause .= " AND u.username LIKE ?";
                    $whereParams[] = "%$search%";
                }
                
                // Build complete SQL with proper parameter order
                $sql = "SELECT u.id, u.username, u.avatar,
                               COALESCE((SELECT cm.message FROM chat_messages cm 
                                WHERE (cm.sender_id = u.id AND cm.receiver_id = ?) 
                                   OR (cm.sender_id = ? AND cm.receiver_id = u.id)
                                ORDER BY cm.created_at DESC LIMIT 1), '') as last_message,
                               COALESCE((SELECT cm.created_at FROM chat_messages cm 
                                WHERE (cm.sender_id = u.id AND cm.receiver_id = ?) 
                                   OR (cm.sender_id = ? AND cm.receiver_id = u.id)
                                ORDER BY cm.created_at DESC LIMIT 1), NULL) as last_message_time,
                               COALESCE((SELECT COUNT(*) FROM chat_messages cm 
                                WHERE cm.sender_id = u.id AND cm.receiver_id = ? AND cm.is_read = 0), 0) as unread_count
                        FROM users u 
                        $whereClause
                        ORDER BY last_message_time DESC, u.username ASC
                        LIMIT $limit OFFSET $offset";
                
                // Combine parameters: subquery params first, then WHERE clause params
                $params = array_merge(
                    [$currentUserId, $currentUserId, $currentUserId, $currentUserId, $currentUserId], 
                    $whereParams
                );
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                $users = $stmt->fetchAll();
                
                logSuccess("Chat users retrieved", ['count' => count($users), 'current_user_id' => $currentUserId]);
                jsonResponse(['success' => true, 'users' => $users]);
            }
            break;
            
        case 'chat-messages':
            if ($method === 'GET') {
                logInfo("Chat messages request received");
                $token = $_GET['token'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
                $token = str_replace('Bearer ', '', $token);
                $userId = $_GET['user_id'] ?? 0;
                $limit = (int)($_GET['limit'] ?? 30);
                $offset = (int)($_GET['offset'] ?? 0);
                if ($limit <= 0 || $limit > 200) { $limit = 30; }
                if ($offset < 0) { $offset = 0; }
                
                logInfo("Chat messages request data", ['user_id' => $userId]);
                
                // Verify user session
                $stmt = $pdo->prepare("SELECT user_id FROM user_sessions WHERE session_token = ? AND expires_at > NOW()");
                $stmt->execute([$token]);
                $session = $stmt->fetch();
                
                if (!$session) {
                    logError("Invalid session for chat messages", ['token' => substr($token, 0, 10) . '...']);
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                
                $currentUserId = $session['user_id'];
                
                $sql = "SELECT cm.*, u.username as sender_username, u.avatar as sender_avatar
                                      FROM chat_messages cm
                                      JOIN users u ON cm.sender_id = u.id
                                      WHERE (cm.sender_id = ? AND cm.receiver_id = ?) 
                                         OR (cm.sender_id = ? AND cm.receiver_id = ?)
                                      ORDER BY cm.created_at ASC
                                      LIMIT $limit OFFSET $offset";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$currentUserId, $userId, $userId, $currentUserId]);
                $messages = $stmt->fetchAll();
                
                // Mark messages as read
                $stmt = $pdo->prepare("UPDATE chat_messages SET is_read = 1 
                                      WHERE sender_id = ? AND receiver_id = ? AND is_read = 0");
                $stmt->execute([$userId, $currentUserId]);
                
                logSuccess("Chat messages retrieved", ['count' => count($messages), 'between_users' => [$currentUserId, $userId]]);
                jsonResponse(['success' => true, 'messages' => $messages]);
            }
            break;
            
        case 'send-message':
            if ($method === 'POST') {
                logInfo("Send message request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for send message");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $receiverId = $data['receiver_id'] ?? 0;
                $message = sanitizeInput($data['message'] ?? '');
                
                logInfo("Send message data", ['receiver_id' => $receiverId, 'message_length' => strlen($message)]);
                
                // Verify authentication (cookie session or token)
                $userId = verifyUserAuth();
                if (!$userId) {
                    logError("Invalid authentication for send message");
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                
                $stmt = $pdo->prepare("INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)");
                $stmt->execute([$userId, $receiverId, $message]);
                
                logSuccess("Message sent", ['sender_id' => $userId, 'receiver_id' => $receiverId]);
                jsonResponse(['success' => true, 'message' => 'Xabar yuborildi']);
            }
            break;
            
        case 'profile':
            if ($method === 'GET') {
                $username = $_GET['username'] ?? '';
                logInfo("Profile request", ['username' => $username]);
                
                if (!$username) {
                    logError("Username not provided for profile");
                    jsonResponse(['success' => false, 'message' => 'Username kerak'], 400);
                }
                
                $stmt = $pdo->prepare("SELECT u.id, u.username, u.email, u.avatar, u.bio, u.location, u.website, u.created_at, u.is_admin,
                                             (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id) as post_count,
                                             (SELECT COUNT(*) FROM comments c WHERE c.user_id = u.id) as comment_count,
                                             (SELECT COUNT(*) FROM likes l JOIN posts p ON l.post_id = p.id WHERE p.author_id = u.id) as like_count
                                      FROM users u 
                                      WHERE u.username = ?");
                $stmt->execute([$username]);
                $profile = $stmt->fetch();
                
                if ($profile) {
                    // Remove sensitive data
                    unset($profile['password']);
                    logSuccess("Profile retrieved", ['username' => $username, 'user_id' => $profile['id']]);
                    jsonResponse(['success' => true, 'profile' => $profile]);
                } else {
                    logError("Profile not found", ['username' => $username]);
                    jsonResponse(['success' => false, 'message' => 'Foydalanuvchi topilmadi'], 404);
                }
            }
            break;
            
        case 'newsletter-subscribe':
            if ($method === 'POST') {
                logInfo("Newsletter subscribe request received");
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!$data) {
                    logError("Invalid JSON data for newsletter");
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri ma\'lumot formati']);
                }
                
                $email = sanitizeInput($data['email'] ?? '');
                $captcha = $data['captcha'] ?? '';
                
                logInfo("Newsletter subscription attempt", ['email' => $email]);
                
                // Require captcha - CRITICAL SECURITY CHECK
                if (empty($captcha)) {
                    logError("Missing captcha for newsletter", ['provided' => $captcha]);
                    jsonResponse(['success' => false, 'message' => 'Captcha kodi kiritilishi shart']);
                }
                
                if (!validateCaptcha($captcha, $_SESSION['captcha'] ?? '')) {
                    logError("Invalid captcha for newsletter", ['provided' => $captcha, 'expected' => $_SESSION['captcha'] ?? '']);
                    jsonResponse(['success' => false, 'message' => 'Captcha noto\'g\'ri']);
                }
                
                // Clear captcha after use for security
                unset($_SESSION['captcha']);

                // Validate email format
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    logError("Invalid email format for newsletter", ['email' => $email]);
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri email format']);
                }
                
                // Check if already subscribed
                $stmt = $pdo->prepare("SELECT id FROM newsletter_subscribers WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    logError("Email already subscribed", ['email' => $email]);
                    jsonResponse(['success' => false, 'message' => 'Bu email allaqachon obuna bo\'lgan']);
                }
                
                // Add to newsletter
                $stmt = $pdo->prepare("INSERT INTO newsletter_subscribers (email, created_at) VALUES (?, NOW())");
                $stmt->execute([$email]);
                
                logSuccess("Newsletter subscription successful", ['email' => $email]);
                jsonResponse(['success' => true, 'message' => 'Muvaffaqiyatli obuna bo\'ldingiz! 🎉']);
            }
            break;

        case 'admin-newsletter':
            if ($method === 'GET') {
                logInfo("Admin newsletter request received");
                // Verify admin session
                $token = $_GET['token'] ?? '';
                $stmt = $pdo->prepare("SELECT u.* FROM users u 
                                      JOIN user_sessions s ON u.id = s.user_id 
                                      WHERE s.session_token = ? AND s.expires_at > NOW() AND u.is_admin = 1");
                $stmt->execute([$token]);
                $admin = $stmt->fetch();
                
                if (!$admin) {
                    logError("Unauthorized admin newsletter access", ['token' => substr($token, 0, 10) . '...']);
                    jsonResponse(['success' => false, 'message' => 'Admin huquqi kerak'], 401);
                }
                
                $stmt = $pdo->query("SELECT * FROM newsletter_subscribers ORDER BY created_at DESC");
                $subscribers = $stmt->fetchAll();
                
                logSuccess("Admin newsletter data retrieved", ['count' => count($subscribers)]);
                jsonResponse(['success' => true, 'subscribers' => $subscribers]);
            }
            break;

        case 'test':
            logInfo("Test endpoint called");
            jsonResponse(['success' => true, 'message' => 'API ishlamoqda', 'timestamp' => date('Y-m-d H:i:s')]);
            break;

        case 'get-user-likes':
            if ($method === 'GET') {
                logInfo("Get user likes request received");

                // Verify user authentication
                $userId = verifyUserAuth();

                if (!$userId) {
                    logError("No authentication provided for user likes");
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }

                // Get user's liked posts
                $stmt = $pdo->prepare("SELECT post_id FROM likes WHERE user_id = ?");
                $stmt->execute([$userId]);
                $likedPosts = $stmt->fetchAll(PDO::FETCH_COLUMN);

                logSuccess("User likes retrieved", ['user_id' => $userId, 'liked_count' => count($likedPosts)]);
                jsonResponse(['success' => true, 'liked_posts' => $likedPosts]);
            }
            break;

        case 'view':
            if ($method === 'POST') {
                logInfo("Increment view request received");
                $postId = (int)($_GET['post_id'] ?? 0);

                if ($postId <= 0) {
                    logError("Invalid post_id for view", ['post_id' => $postId]);
                    jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri post ID'], 400);
                }

                $stmt = $pdo->prepare("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?");
                $stmt->execute([$postId]);

                logSuccess("Post view incremented", ['post_id' => $postId]);
                jsonResponse(['success' => true, 'message' => 'Ko\'rishlar yangilandi']);
            }
            break;

        case 'heartbeat':
            if ($method === 'POST') {
                // mark user online in session
                $userId = verifyUserAuth();
                if (!$userId) {
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }
                $_SESSION['online'] = $_SESSION['online'] ?? [];
                $_SESSION['online'][$userId] = time();
                // Cleanup entries older than 1 hour
                foreach ($_SESSION['online'] as $uid => $ts) {
                    if (time() - $ts > 3600) {
                        unset($_SESSION['online'][$uid]);
                    }
                }
                jsonResponse(['success' => true, 'timestamp' => time()]);
            }
            break;

        case 'online-status':
            if ($method === 'GET') {
                $username = $_GET['username'] ?? '';
                if (!$username) {
                    jsonResponse(['success' => false, 'message' => 'Username kerak'], 400);
                }
                // Map username to id
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $u = $stmt->fetch();
                if (!$u) {
                    jsonResponse(['success' => false, 'message' => 'Foydalanuvchi topilmadi'], 404);
                }
                $uid = (int)$u['id'];
                $last = $_SESSION['online'][$uid] ?? 0;
                $isOnline = $last && (time() - $last) <= 120; // 2 minutes
                jsonResponse(['success' => true, 'online' => (bool)$isOnline, 'last_seen' => $last]);
            }
            break;

        case 'update-profile':
            if ($method === 'POST') {
                logInfo("Update profile request received");
                
                // Handle both JSON and FormData
                $bio = '';
                $location = '';
                $website = '';
                
                if (isset($_POST['bio']) || isset($_POST['location']) || isset($_POST['website'])) {
                    // FormData request
                    $bio = sanitizeInput($_POST['bio'] ?? '');
                    $location = sanitizeInput($_POST['location'] ?? '');
                    $website = sanitizeInput($_POST['website'] ?? '');
                } else {
                    // JSON request
                    $data = json_decode(file_get_contents('php://input'), true);
                    if ($data) {
                        $bio = sanitizeInput($data['bio'] ?? '');
                        $location = sanitizeInput($data['location'] ?? '');
                        $website = sanitizeInput($data['website'] ?? '');
                    }
                }

                logInfo("Profile update data", ['bio_length' => strlen($bio), 'location' => $location, 'website' => $website]);

                // Verify user authentication
                $userId = verifyUserAuth();
                if (!$userId) {
                    logError("Invalid authentication for profile update");
                    jsonResponse(['success' => false, 'message' => 'Tizimga kiring'], 401);
                }

                // Handle avatar upload if provided
                $avatar = null;
                if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
                    $uploadDir = __DIR__ . '/../uploads/avatars/';
                    if (!is_dir($uploadDir)) {
                        mkdir($uploadDir, 0755, true);
                    }

                    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    $maxSize = 2 * 1024 * 1024; // 2MB

                    if (!in_array($_FILES['avatar']['type'], $allowedTypes)) {
                        logError("Invalid avatar file type", ['type' => $_FILES['avatar']['type']]);
                        jsonResponse(['success' => false, 'message' => 'Faqat JPG, PNG, GIF va WebP formatlar qabul qilinadi']);
                    }

                    if ($_FILES['avatar']['size'] > $maxSize) {
                        logError("Avatar file too large", ['size' => $_FILES['avatar']['size']]);
                        jsonResponse(['success' => false, 'message' => 'Rasm hajmi 2MB dan oshmasligi kerak']);
                    }

                    $avatarExtension = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
                    $avatarName = 'avatar_' . $userId . '_' . time() . '.' . $avatarExtension;
                    $avatarPath = $uploadDir . $avatarName;

                    if (move_uploaded_file($_FILES['avatar']['tmp_name'], $avatarPath)) {
                        $avatar = 'avatars/' . $avatarName;
                        logSuccess("Avatar uploaded successfully", ['avatar' => $avatarName]);

                        // Delete old avatar if exists
                        $stmt = $pdo->prepare("SELECT avatar FROM users WHERE id = ?");
                        $stmt->execute([$userId]);
                        $oldAvatar = $stmt->fetch()['avatar'];

                        if ($oldAvatar && file_exists(__DIR__ . '/../uploads/' . $oldAvatar)) {
                            unlink(__DIR__ . '/../uploads/' . $oldAvatar);
                        }
                    } else {
                        logError("Failed to move uploaded avatar");
                        jsonResponse(['success' => false, 'message' => 'Rasm yuklanishida xatolik yuz berdi']);
                    }
                }

                // Update user profile with all fields
                if ($avatar) {
                    $stmt = $pdo->prepare("UPDATE users SET bio = ?, location = ?, website = ?, avatar = ? WHERE id = ?");
                    $stmt->execute([$bio, $location, $website, $avatar, $userId]);
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET bio = ?, location = ?, website = ? WHERE id = ?");
                    $stmt->execute([$bio, $location, $website, $userId]);
                }

                // Get updated profile data
                $stmt = $pdo->prepare("SELECT id, username, email, bio, location, website, avatar FROM users WHERE id = ?");
                $stmt->execute([$userId]);
                $updatedProfile = $stmt->fetch();

                logSuccess("Profile updated successfully", ['user_id' => $userId]);
                jsonResponse(['success' => true, 'message' => 'Profil muvaffaqiyatli yangilandi', 'profile' => $updatedProfile]);
            }
            break;

        default:
            logError("Unknown API action", ['action' => $request, 'method' => $method]);
            jsonResponse(['success' => false, 'message' => 'Noto\'g\'ri so\'rov'], 404);
    }

} catch (Exception $e) {
    $errorDetails = [
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString(),
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
        'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'action' => $_GET['action'] ?? '',
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    error_log("CRITICAL API ERROR: " . json_encode($errorDetails));
    jsonResponse(['success' => false, 'message' => 'Server xatosi yuz berdi'], 500);
}
?>