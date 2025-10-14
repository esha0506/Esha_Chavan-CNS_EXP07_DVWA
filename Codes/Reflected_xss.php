<?php
declare(strict_types=1);

// secure_reflected_xss.php - example to prevent reflected XSS

// --- Session and cookie hardening (optional if already configured globally) ---
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

// --- Generate CSP nonce for safe inline scripts (defense-in-depth) ---
if (empty($_SESSION['csp_nonce'])) {
    $_SESSION['csp_nonce'] = bin2hex(random_bytes(16));
}
$csp_nonce = $_SESSION['csp_nonce'];

// Set secure response headers
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Permissions-Policy: geolocation=()"); 
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$csp_nonce}'; object-src 'none'; base-uri 'self';");

// --- Output-encoding helper functions ---
function escape_html(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function escape_attr(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function js_literal($value): string {
    $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    return $json === false ? 'null' : $json;
}

// --- Input validation / allowlist ---
function validate_search_query($raw): ?string {
    if (!is_string($raw)) return null;
    $trimmed = trim($raw);
    if ($trimmed === '' || mb_strlen($trimmed, 'UTF-8') > 200) return null;
    if (preg_match('/^[\p{L}\p{N}\s\-\.\,\_@#&\(\)\'"]+$/u', $trimmed)) {
        return $trimmed;
    }
    return null;
}

// --- Process request ---
$search = null;
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = $_REQUEST['q'] ?? null;
    $validated = validate_search_query($raw);
    if ($validated === null) {
        if ($raw !== null && trim((string)$raw) !== '') {
            $errors[] = 'Your input contained invalid characters or was too long. Please change it.';
        }
    } else {
        $search = $validated;
        // Safe DB query placeholder: use prepared statements
        $results = [
            ['title' => 'Result 1 about ' . $search, 'summary' => "Summary for {$search}"],
            ['title' => 'Result 2', 'summary' => 'Another item']
        ];
    }
}

// --- HTML Output ---
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Secure Search (Reflected XSS protected)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body>
  <h1>Search</h1>

  <?php if (!empty($errors)): ?>
    <div role="alert">
      <ul>
        <?php foreach ($errors as $e): ?>
          <li><?php echo escape_html($e); ?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <form method="get" action="">
    <label for="q">Query:</label>
    <input id="q" name="q" type="text" maxlength="200"
           value="<?php echo $search !== null ? escape_attr($search) : ''; ?>">
    <button type="submit">Search</button>
  </form>

  <?php if ($search !== null): ?>
    <h2>Showing results for: <?php echo escape_html($search); ?></h2>
    <ul>
      <?php foreach ($results as $r): ?>
        <li>
          <strong><?php echo escape_html($r['title']); ?></strong><br>
          <small><?php echo escape_html($r['summary']); ?></small>
        </li>
      <?php endforeach; ?>
    </ul>
  <?php elseif ($_REQUEST['q'] ?? false): ?>
    <p>We couldn't use that input. Please try again with valid characters.</p>
  <?php endif; ?>

  <script nonce="<?php echo $csp_nonce; ?>">
    const serverData = <?php echo js_literal(['search' => $search ?? '', 'timestamp' => time()]); ?>;
    console.log('serverData:', serverData);
  </script>

</body>
</html>