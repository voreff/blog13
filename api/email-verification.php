<?php
// Import the email verification class from the attachment
class EmailVerification {
    private $db;
    private $smtpHost = 'ssl://smtp.gmail.com';
    private $smtpPort = 465;
    private $fromEmail = 'davronovdilshodbek90@gmail.com';
    private $appPass = 'rtpe bsud wzwu mjbg'; // Gmail App Password
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    // Generate verification code
    private function generateCode($length = 6) {
        $chars = '123456789';
        $code = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $code .= $chars[random_int(0, $max)];
        }
        return $code;
    }
    
    // Validate Gmail address
    public function validateGmail($email) {
        // Must be @gmail.com
        if (!str_ends_with(strtolower($email), '@gmail.com')) {
            return ['valid' => false, 'message' => 'Faqat @gmail.com manzillari qabul qilinadi'];
        }
        
        // No dots or plus signs allowed in username part
        $username = explode('@', $email)[0];
        if (strpos($username, '.') !== false || strpos($username, '+') !== false) {
            return ['valid' => false, 'message' => 'Gmail manzilida nuqta (.) va plus (+) belgilari ishlatilmasin'];
        }
        
        return ['valid' => true, 'message' => ''];
    }
    
    // Send verification email
    public function sendVerificationEmail($email, $type = 'registration') {
        $validation = $this->validateGmail($email);
        if (!$validation['valid']) {
            return ['success' => false, 'message' => $validation['message']];
        }
        
        try {
            // Clean up expired codes
            $this->db->query("DELETE FROM email_verifications WHERE expires_at < NOW()");
            
            // Generate new code
            $code = $this->generateCode(6);
            $expiresAt = date('Y-m-d H:i:s', time() + 300); // 5 minutes
            
            // Store verification code
            $stmt = $this->db->prepare("INSERT INTO email_verifications (email, verification_code, code_type, expires_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$email, $code, $type, $expiresAt]);
            
            // Send email
            $subject = $type === 'registration' ? '🔐 Ro\'yxatdan o\'tish kodi' : '🔑 Parolni tiklash kodi';
            $this->sendEmail($email, $subject, $code, $type);
            
            return ['success' => true, 'message' => 'Tasdiqlash kodi emailingizga yuborildi'];
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Email yuborishda xatolik: ' . $e->getMessage()];
        }
    }
    
    // Verify code
    public function verifyCode($email, $code, $type = 'registration') {
        try {
            $stmt = $this->db->prepare("SELECT * FROM email_verifications WHERE email = ? AND verification_code = ? AND code_type = ? AND expires_at > NOW() AND is_used = 0");
            $stmt->execute([$email, $code, $type]);
            $verification = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($verification) {
                // Mark as used
                $updateStmt = $this->db->prepare("UPDATE email_verifications SET is_used = 1 WHERE id = ?");
                $updateStmt->execute([$verification['id']]);
                
                return ['success' => true, 'message' => 'Kod tasdiqlandi'];
            } else {
                return ['success' => false, 'message' => 'Kod noto\'g\'ri yoki muddati tugagan'];
            }
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Tekshirishda xatolik: ' . $e->getMessage()];
        }
    }
    
    // Send email via SMTP
    private function sendEmail($to, $subject, $code, $type) {
        $imageUrl = 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSA2G-O58Nlu2hYy3QbN5BfIZMhfEx30TwXFg&s';
        $title = $type === 'registration' ? 'Ro\'yxatdan o\'tish' : 'Parolni tiklash';
        
        $body = <<<HTML
<html><body style="font-family:Arial,sans-serif;background:#f3f6fb;padding:24px;">
  <div style="max-width:640px;margin:auto;background:#fff;padding:26px;border-radius:12px;text-align:center;box-shadow:0 6px 18px rgba(0,0,0,0.08);">
    <img src="$imageUrl" alt="Verify" style="width:250px;margin-bottom:12px;border-radius:12px;">
    <h2 style="color:#0b63d6;margin:0 0 8px;">✅ $title kodi</h2>
    <p style="color:#555;margin:8px 0 16px;">Quyidagi kodni tizimga kiriting:</p>
    <div style="font-size:24px;font-weight:700;background:#eef6ff;padding:12px 18px;border-radius:8px;display:inline-block;letter-spacing:2px;">$code</div>
    <p style="color:#888;font-size:13px;margin-top:16px;">Kod 5 daqiqa ichida amal qiladi. Uni hech kimga bermang.</p>
  </div>
</body></html>
HTML;
        
        $this->smtpSend($to, $subject, $body);
    }
    
    // SMTP sending function
    private function smtpSend($to, $subject, $body) {
        $subjectEnc = '=?UTF-8?B?'.base64_encode($subject).'?=';
        $messageEnc = chunk_split(base64_encode($body));
        
        $fp = stream_socket_client($this->smtpHost . ':' . $this->smtpPort, $errno, $errstr, 30);
        if (!$fp) throw new Exception("Socket error: $errno - $errstr");
        
        $read = function() use ($fp) {
            $res = '';
            while ($line = fgets($fp, 515)) {
                $res .= $line;
                if (isset($line[3]) && $line[3] === ' ') break;
            }
            return $res;
        };
        
        $write = function($cmd) use ($fp) { fwrite($fp, $cmd . "\r\n"); };
        
        $read(); // banner
        $write("EHLO localhost"); $read();
        $write("AUTH LOGIN"); $read();
        $write(base64_encode($this->fromEmail)); $read();
        $write(base64_encode($this->appPass)); $auth = $read();
        
        if (strpos($auth, '235') !== 0) {
            throw new Exception("Authentication failed");
        }
        
        $write("MAIL FROM:<{$this->fromEmail}>"); $read();
        $write("RCPT TO:<$to>"); $read();
        $write("DATA"); $read();
        
        $headers = "Date: " . date('r') . "\r\n";
        $headers .= "From: Blog System <{$this->fromEmail}>\r\n";
        $headers .= "To: <$to>\r\n";
        $headers .= "Subject: $subjectEnc\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        $headers .= "Content-Transfer-Encoding: base64\r\n\r\n";
        
        $write($headers . $messageEnc . "\r\n.\r\n");
        $result = $read();
        
        $write("QUIT"); $read();
        fclose($fp);
        
        if (strpos($result, '250') !== 0) {
            throw new Exception("Sending failed");
        }
    }
}
?>
