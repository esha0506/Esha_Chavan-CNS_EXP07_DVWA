<?php
// improved.php - Secure session handling example
// NOTE: Remove debug output in production. Requires PHP 7.3+ for array cookie params.

// Harden session configuration at runtime (or set these in php.ini)
ini_set('session.use_strict_mode', '1');   // refuse uninitialized session IDs
ini_set('session.use_only_cookies', '1'); // prevent SID in URL
ini_set('session.cookie_httponly', '1');  // JavaScript cannot read the cookie
// Enable the next line when serving over HTTPS:
// ini_set('session.cookie_secure', '1');

// Cookie params - set before session_start()
$cookie_lifetime = 0; // session cookie (expires on browser close)
$cookie_path     = '/';
$cookie_domain   = ''; // e.g. '.example.com' if needed
$cookie_secure   = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$cookie_httponly = true;
$cookie_samesite = 'Lax'; // 'Strict' or 'Lax' recommended

session_set_cookie_params([
    'lifetime' => $cookie_lifetime,
    'path'     => $cookie_path,
    'domain'   => $cookie_domain,
    'secure'   => $cookie_secure,
    'httponly' => $cookie_httponly,
    'samesite' => $cookie_samesite
]);

session_name('DVWA_SESSID'); // optional: custom session cookie name
session_start();

// Helper: cryptographically secure token generator
function random_token(int $bytes = 32): string {
    return bin2hex(random_bytes($bytes)); // 64 hex chars for 32 bytes
}

// When a new session-like identity is created (e.g., on login), regenerate ID and set token
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Prevent session fixation by regenerating session id and deleting old session
    session_regenerate_id(true);

    // Store a server-side token in session
    $token = random_token(32);
    $_SESSION['dvwa_token'] = $token;
    $_SESSION['created_at'] = time();

    // Optional: set a cookie for compatibility (prefer HttpOnly & Secure)
    setcookie('dvwaSession', $token, [
        'expires'  => 0,                // session cookie
        'path'     => $cookie_path,
        'domain'   => $cookie_domain,
        'secure'   => $cookie_secure,   // requires HTTPS to be effective
        'httponly' => true,
        'samesite' => $cookie_samesite
    ]);

    // Optionally redirect to post-login page
    // header('Location: /'); exit;
}

// On every request validate dvwaSession cookie against server-side session token
$valid = false;
if (!empty($_COOKIE['dvwaSession']) && !empty($_SESSION['dvwa_token'])) {
    if (hash_equals($_SESSION['dvwa_token'], $_COOKIE['dvwaSession'])) {
        $valid = true;
    }
}

// If token invalid (possible tampering/fixation), rotate session and clear token
if (!$valid && isset($_COOKIE['dvwaSession'])) {
    session_regenerate_id(true);
    unset($_SESSION['dvwa_token']);
    setcookie('dvwaSession', '', [
        'expires' => time() - 3600,
        'path'    => $cookie_path,
        'domain'  => $cookie_domain,
        'secure'  => $cookie_secure,
        'httponly'=> true,
        'samesite'=> $cookie_samesite
    ]);
    // Optionally force re-authentication here
}

// DEBUG: remove in production
if (defined('DEBUG') && DEBUG) {
    echo '<pre>';
    echo 'Session ID: ' . session_id() . PHP_EOL;
    echo 'DVWA token in session: ' . ($_SESSION['dvwa_token'] ?? 'none') . PHP_EOL;
    echo 'Cookie dvwaSession: ' . ($_COOKIE['dvwaSession'] ?? 'none') . PHP_EOL;
    echo '</pre>';
}
?>