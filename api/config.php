<?php
/**
 * Konfiguracja backendu formularza kontaktowego
 * Plik: config.php
 */

// --- Funkcja do wczytywania pliku .env ---
function loadEnvFile(): void {
    $envFile = __DIR__ . '/.env';
    if (!file_exists($envFile)) return;

    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || strpos($line, '=') === false) continue;

        [$key, $value] = explode('=', $line, 2);
        $value = trim($value);
        // usuń otaczające cudzysłowy jeśli są
        $value = trim($value, "\"'");
        putenv(trim($key) . '=' . $value);
    }
}
loadEnvFile();

// --- Funkcja pomocnicza ---
function getEnvVar(string $key, $default = null) {
    $val = getenv($key);
    return ($val === false || $val === null || $val === '') ? $default : $val;
}

// --- Konfiguracja SMTP ---
define('SMTP_HOST',        getEnvVar('SMTP_SERVER', 'smtp.gmail.com'));
define('SMTP_PORT',       (int) getEnvVar('SMTP_PORT', 587));
define('SMTP_ENCRYPTION',  getEnvVar('SMTP_ENCRYPTION', 'tls')); // 'tls' lub 'ssl'
define('SMTP_USERNAME',    getEnvVar('EMAIL_USER'));
define('SMTP_PASSWORD',    getEnvVar('EMAIL_PASSWORD'));

// --- Dane nadawcy i odbiorcy ---
define('MAIL_FROM',        getEnvVar('EMAIL_USER'));
define('MAIL_FROM_NAME',   getEnvVar('MAIL_FROM_NAME', 'VECTOR Geodezja'));
define('MAIL_TO',          getEnvVar('MAIL_TO', 'biuro@vector-geodezja.pl'));
define('MAIL_TO_NAME',     getEnvVar('MAIL_TO_NAME', 'Biuro VECTOR'));

// --- Limity / antyspam ---
define('MAX_EMAILS_PER_HOUR', 5);
define('HONEYPOT_FIELD',      'website');

// --- CAPTCHA (Cloudflare Turnstile) ---
$turnstileFlag = strtolower((string) getEnvVar('TURNSTILE_ENABLED', 'false'));
define('TURNSTILE_ENABLED', in_array($turnstileFlag, ['1','true','yes'], true));
define('TURNSTILE_SECRET',  getEnvVar('TURNSTILE_SECRET', ''));


// --- Dozwolone źródła (CORS) ---
$allowed_origins = [
    'https://vector-geodezja.pl',
    'https://www.vector-geodezja.pl',
];

// --- Logowanie zdarzeń ---
function writeLog(string $message): void {
    $dir = __DIR__ . '/logs';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $file = $dir . '/app.log';
    $date = date('Y-m-d H:i:s');
    @file_put_contents($file, "[$date] $message\n", FILE_APPEND);
}
