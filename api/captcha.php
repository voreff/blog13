<?php
// Error reporting
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
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, Cookie, Authorization');
    header('Access-Control-Max-Age: 86400'); // Cache preflight for 24 hours
    http_response_code(204);
    exit;
}

// Set CORS headers for actual request - Allow all origins
header('Access-Control-Allow-Origin: ' . $allowedOrigin);
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, Cookie, Authorization');

// Enhanced session configuration for cross-origin requests
if (session_status() === PHP_SESSION_NONE) {
    // Configure session settings before starting
    ini_set('session.cookie_samesite', 'None');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_lifetime', '3600');
    ini_set('session.gc_maxlifetime', 3600);
    ini_set('session.use_cookies', '1');
    ini_set('session.use_only_cookies', '1');
    
    session_name('BLOG_SESSION');
    session_start();

    // Regenerate session ID for security on first access
    if (!isset($_SESSION['captcha_initialized'])) {
        session_regenerate_id(true);
        $_SESSION['captcha_initialized'] = true;
        error_log("[CAPTCHA] New session initialized: " . session_id());
    }
}

error_log("[CAPTCHA.PHP] Session started - ID: " . session_id() . " | Origin: " . $origin . " | Cookie params: " . json_encode(session_get_cookie_params()));

// Generate captcha image
function generateCaptcha() {
    $width = 120;
    $height = 40;
    $font_size = 5;
    
    // Generate random code
    $chars = 'abcdefghijklmnopqrstuvwxyz123456789';
    $captcha_code = '';
    for ($i = 0; $i < 6; $i++) {
        $captcha_code .= $chars[rand(0, strlen($chars) - 1)];
    }
    
    // Store in session with timestamp for security
    $_SESSION['captcha'] = $captcha_code;
    $_SESSION['captcha_time'] = time();
    
    // Detailed logging
    $logInfo = [
        'captcha_code' => $captcha_code,
        'session_id' => session_id(),
        'timestamp' => date('Y-m-d H:i:s'),
        'origin' => $_SERVER['HTTP_ORIGIN'] ?? 'none'
    ];
    error_log("[CAPTCHA GENERATED] " . json_encode($logInfo));
    
    // Create image
    $image = imagecreate($width, $height);
    
    // Colors
    $bg_color = imagecolorallocate($image, 255, 255, 255);
    $text_color = imagecolorallocate($image, 0, 0, 0);
    $line_color = imagecolorallocate($image, 200, 200, 200);
    
    // Add some noise lines
    for ($i = 0; $i < 5; $i++) {
        imageline($image, rand(0, $width), rand(0, $height), rand(0, $width), rand(0, $height), $line_color);
    }
    
    // Add text
    $x = intval(($width - strlen($captcha_code) * imagefontwidth($font_size)) / 2);
    $y = intval(($height - imagefontheight($font_size)) / 2);
    imagestring($image, $font_size, $x, $y, $captcha_code, $text_color);
    
    // Output image
    header('Content-Type: image/png');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    imagepng($image);
    imagedestroy($image);
}

generateCaptcha();
?>