<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
 * Endpoint formularza kontaktowego
 * Wrzucić do: api/send.php
 */

// Najpierw wczytaj autoload i config
require_once __DIR__ . '/vendor/autoload.php';
require_once 'config.php';

// Ustaw nagłówki JSON i CORS
header('Content-Type: application/json; charset=utf-8');

// Obsługa CORS
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
header('Access-Control-Allow-Credentials: true');

// Obsługa preflight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Sprawdź metodę HTTP
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Metoda niedozwolona']);
    exit();
}

writeLog("Nowe żądanie z IP: " . getClientIP());

try {
    // Pobierz dane JSON
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Nieprawidłowy format JSON');
    }
    
    // Sprawdź honeypot
    if (!empty($data[HONEYPOT_FIELD])) {
        writeLog("Bot wykryty - honeypot wypełniony z IP: " . getClientIP());
        // Udawaj sukces dla bota
        echo json_encode(['status' => 'ok']);
        exit();
    }
    
    // Walidacja danych
    $name = trim($data['name'] ?? '');
    $email = trim($data['email'] ?? '');
    $message = trim($data['message'] ?? '');
    $phone = trim($data['phone'] ?? '');
    
    $errors = [];
    
    if (empty($name) || strlen($name) < 2) {
        $errors[] = 'Imię i nazwisko jest wymagane (min. 2 znaki)';
    }
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Nieprawidłowy adres email';
    }
    
    if (empty($message) || strlen($message) < 10) {
        $errors[] = 'Wiadomość jest wymagana (min. 10 znaków)';
    }
    
    if (!empty($phone) && !preg_match('/^[0-9 +()-]{6,}$/', $phone)) {
        $errors[] = 'Nieprawidłowy format numeru telefonu';
    }
    
    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(['error' => implode(', ', $errors)]);
        exit();
    }
    
    // Sprawdź Turnstile (jeśli włączone)
    if (TURNSTILE_ENABLED) {
        $turnstileToken = $data['turnstile_token'] ?? '';
        if (!verifyTurnstile($turnstileToken)) {
            http_response_code(400);
            echo json_encode(['error' => 'Weryfikacja CAPTCHA nieudana']);
            exit();
        }
    }
    
    // Rate limiting
    if (!checkRateLimit()) {
        http_response_code(429);
        echo json_encode(['error' => 'Zbyt wiele wiadomości. Spróbuj ponownie za godzinę.']);
        exit();
    }
    
    // Wyślij email
    if (sendEmail($name, $email, $message, $phone)) {
        writeLog("Email wysłany pomyślnie dla: $email");
        echo json_encode(['status' => 'ok', 'message' => 'Wiadomość została wysłana pomyślnie']);
    } else {
        throw new Exception('Błąd wysyłania email');
    }
    
} catch (Exception $e) {
    writeLog("BŁĄD: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Wystąpił błąd serwera. Spróbuj ponownie później.']);
}

/**
 * Funkcja wysyłania email przez SMTP
 */
function sendEmail($name, $email, $message, $phone) {
    // Sprawdź czy PHPMailer jest dostępny
    if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        // Fallback na mail() jeśli PHPMailer niedostępny
        return sendEmailFallback($name, $email, $message, $phone);
    }
    
    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        
        // Konfiguracja SMTP
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION;
        $mail->Port = SMTP_PORT;
        $mail->CharSet = 'UTF-8';
        
        // Nadawca i odbiorca
        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME);
        $mail->addAddress(MAIL_TO, MAIL_TO_NAME);
        $mail->addReplyTo($email, $name);
        
        // Treść wiadomości
        $mail->isHTML(true);
        $mail->Subject = "Nowa wiadomość z formularza kontaktowego - $name";
        
        $htmlBody = "
        <h2>Nowa wiadomość z formularza kontaktowego</h2>
        <p><strong>Imię i nazwisko:</strong> " . htmlspecialchars($name) . "</p>
        <p><strong>Email:</strong> " . htmlspecialchars($email) . "</p>
        " . (!empty($phone) ? "<p><strong>Telefon:</strong> " . htmlspecialchars($phone) . "</p>" : "") . "
        <p><strong>Wiadomość:</strong></p>
        <div style='background: #f5f5f5; padding: 15px; border-radius: 5px;'>
            " . nl2br(htmlspecialchars($message)) . "
        </div>
        <hr>
        <p><small>Wysłano: " . date('d.m.Y H:i:s') . "<br>
        IP: " . getClientIP() . "</small></p>
        ";
        
        $mail->Body = $htmlBody;
        $mail->AltBody = strip_tags(str_replace('<br>', "\n", $htmlBody));
        
        return $mail->send();
        
    } catch (Exception $e) {
        writeLog("PHPMailer błąd: " . $e->getMessage());
        return false;
    }
}

/**
 * Fallback wysyłanie przez mail()
 */
function sendEmailFallback($name, $email, $message, $phone) {
    $to = MAIL_TO;
    $subject = "Nowa wiadomość z formularza kontaktowego - $name";
    
    $body = "Nowa wiadomość z formularza kontaktowego\n\n";
    $body .= "Imię i nazwisko: $name\n";
    $body .= "Email: $email\n";
    if (!empty($phone)) $body .= "Telefon: $phone\n";
    $body .= "\nWiadomość:\n$message\n\n";
    $body .= "---\n";
    $body .= "Wysłano: " . date('d.m.Y H:i:s') . "\n";
    $body .= "IP: " . getClientIP();
    
    $headers = [
        'From: ' . MAIL_FROM,
        'Reply-To: ' . $email,
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: PHP/' . phpversion()
    ];
    
    return mail($to, $subject, $body, implode("\r\n", $headers));
}

/**
 * Rate limiting - sprawdź liczbę wysłanych wiadomości
 */
function checkRateLimit() {
    $ip = getClientIP();
    $rateLimitFile = __DIR__ . '/logs/rate_limit.json';
    
    // Stwórz katalog jeśli nie istnieje
    $logDir = dirname($rateLimitFile);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $now = time();
    $oneHourAgo = $now - 3600;
    
    // Wczytaj dane rate limit
    $rateLimitData = [];
    if (file_exists($rateLimitFile)) {
        $json = file_get_contents($rateLimitFile);
        $rateLimitData = json_decode($json, true) ?: [];
    }
    
    // Usuń stare wpisy
    $rateLimitData = array_filter($rateLimitData, function($timestamp) use ($oneHourAgo) {
        return $timestamp > $oneHourAgo;
    });
    
    // Sprawdź limit dla IP
    $ipRequests = array_filter($rateLimitData, function($timestamp, $key) use ($ip) {
        return strpos($key, $ip . '_') === 0;
    }, ARRAY_FILTER_USE_BOTH);
    
    if (count($ipRequests) >= MAX_EMAILS_PER_HOUR) {
        return false;
    }
    
    // Dodaj nowe żądanie
    $rateLimitData[$ip . '_' . $now] = $now;
    
    // Zapisz dane
    file_put_contents($rateLimitFile, json_encode($rateLimitData), LOCK_EX);
    
    return true;
}

/**
 * Weryfikacja Cloudflare Turnstile
 */
function verifyTurnstile($token) {
    if (empty($token) || empty(TURNSTILE_SECRET)) {
        return false;
    }
    
    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $data = [
        'secret' => TURNSTILE_SECRET,
        'response' => $token,
        'remoteip' => getClientIP()
    ];
    
    $options = [
        'http' => [
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    
    if ($result === false) {
        return false;
    }
    
    $response = json_decode($result, true);
    return isset($response['success']) && $response['success'] === true;
}

/**
 * Pobierz prawdziwe IP klienta
 */
function getClientIP() {
    $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}
?>
