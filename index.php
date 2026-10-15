<?php
declare(strict_types=1);

/**
 * Pluschat Protocol Gateway
 * Deploy this repository to https://прото.плюсчат.рф
 *
 * Routes:
 *   GET  /api/health                 gateway + upstream diagnostics
 *   GET  /api/v1/health              upstream API health
 *   Any  /api/v1/*                   authenticated-aware proxy to main server
 *
 * PHP 8.1+, PDO MySQL, cURL extension recommended.
 */

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
date_default_timezone_set('UTC');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

function jsonResponse(int $status, array $body): never {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function requestOrigin(): string {
    return (string)($_SERVER['HTTP_ORIGIN'] ?? '');
}

function config(): array {
    $path = __DIR__ . '/config.php';
    $provided = is_file($path) ? require $path : [];
    if (!is_array($provided)) $provided = [];
    $env = static fn(string $name, mixed $fallback = ''): mixed =>
        (($value = getenv($name)) !== false && $value !== '') ? $value : $fallback;

    return array_merge([
        'service_name' => 'pluschat-gateway',
        'base_url' => 'https://прото.плюсчат.рф',
        'main_api_base' => 'https://xn--80avljg2a1c.xn--p1ai/api/v1',
        'db_host' => 'localhost',
        'db_name' => 'Pluschat',
        'db_user' => 'Admin',
        'db_password' => '',
        'token_pepper' => '',
        'allowed_origins' => [
            'https://xn--80avljg2a1c.xn--p1ai',
            'https://xn--n1aabel.xn--80avljg2a1c.xn--p1ai',
            'https://прото.плюсчат.рф',
            'https://xn--n1aabel.xn--80avljg2a1c.xn--p1ai',
            'http://localhost',
            'http://127.0.0.1',
            'null'
        ],
        'connect_timeout' => 4,
        'request_timeout' => 20,
        'max_body_bytes' => 1048576,
        'rate_limit_per_minute' => 120,
    ], $provided, [
        'main_api_base' => (string)$env('PLUSCHAT_MAIN_API_BASE', $provided['main_api_base'] ?? 'https://xn--80avljg2a1c.xn--p1ai/api/v1'),
        'db_host' => (string)$env('PLUSCHAT_DB_HOST', $provided['db_host'] ?? 'localhost'),
        'db_name' => (string)$env('PLUSCHAT_DB_NAME', $provided['db_name'] ?? 'Pluschat'),
        'db_user' => (string)$env('PLUSCHAT_DB_USER', $provided['db_user'] ?? 'Admin'),
        'db_password' => (string)$env('PLUSCHAT_DB_PASSWORD', $provided['db_password'] ?? ''),
        'token_pepper' => (string)$env('PLUSCHAT_TOKEN_PEPPER', $provided['token_pepper'] ?? ''),
    ]);
}

function applyCors(array $cfg): void {
    $origin = requestOrigin();
    $allowed = $cfg['allowed_origins'] ?? [];
    if ($origin !== '' && in_array($origin, $allowed, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
        header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-Id');
        header('Access-Control-Max-Age: 600');
    }
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) === 'OPTIONS') {
        if ($origin !== '' && !in_array($origin, $allowed, true)) jsonResponse(403, ['ok'=>false,'error'=>'origin_not_allowed']);
        http_response_code(204);
        exit;
    }
}

function pathInfo(): string {
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);
    return '/' . trim(is_string($path) ? $path : '/', '/');
}

function requestBody(int $max): string {
    $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > $max) jsonResponse(413, ['ok'=>false,'error'=>'request_too_large']);
    $body = file_get_contents('php://input');
    if (!is_string($body)) return '';
    if (strlen($body) > $max) jsonResponse(413, ['ok'=>false,'error'=>'request_too_large']);
    return $body;
}

function pdo(array $cfg): PDO {
    static $connection = null;
    if ($connection instanceof PDO) return $connection;
    if (($cfg['db_password'] ?? '') === '') {
        throw new RuntimeException('Gateway database password is not configured on server');
    }
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $cfg['db_host'], $cfg['db_name']);
    $connection = new PDO($dsn, $cfg['db_user'], $cfg['db_password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $connection;
}

function checkRateLimit(array $cfg): void {
    // DB-backed per-IP limiter; no schema setup needed.
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $key = hash_hmac('sha256', $ip, (string)($cfg['token_pepper'] ?: $cfg['service_name']));
    $db = pdo($cfg);
    $db->exec("CREATE TABLE IF NOT EXISTS gateway_rate_limits (
        rate_key CHAR(64) NOT NULL PRIMARY KEY,
        window_start INT UNSIGNED NOT NULL,
        request_count INT UNSIGNED NOT NULL,
        INDEX idx_window_start (window_start)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    $now = time();
    $limit = max(30, (int)$cfg['rate_limit_per_minute']);
    $stmt = $db->prepare("INSERT INTO gateway_rate_limits(rate_key,window_start,request_count)
        VALUES(?,?,1) ON DUPLICATE KEY UPDATE
        request_count = IF(window_start < ?, 1, request_count + 1),
        window_start = IF(window_start < ?, ?, window_start)");
    $cutoff = $now - 60;
    $stmt->execute([$key, $now, $cutoff, $cutoff, $now]);
    $read = $db->prepare('SELECT request_count FROM gateway_rate_limits WHERE rate_key = ?');
    $read->execute([$key]);
    $count = (int)$read->fetchColumn();
    if ($count > $limit) {
        header('Retry-After: 60');
        jsonResponse(429, ['ok'=>false,'error'=>'rate_limit_exceeded','retry_after'=>60]);
    }
}

function upstream(array $cfg, string $route, string $method, string $body): never {
    if (!function_exists('curl_init')) jsonResponse(503, ['ok'=>false,'error'=>'curl_extension_missing']);
    $base = rtrim((string)$cfg['main_api_base'], '/');
    $url = $base . '/' . ltrim($route, '/');
    $query = (string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_QUERY) ?? '');
    if ($query !== '') $url .= '?' . $query;

    $headers = ['Accept: application/json', 'X-Forwarded-Proto: https'];
    $auth = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if ($auth !== '' && preg_match('/^Bearer [A-Za-z0-9._~+\/-]+=*$/', $auth)) {
        $headers[] = 'Authorization: ' . $auth;
    }
    $contentType = (string)($_SERVER['CONTENT_TYPE'] ?? '');
    if ($contentType !== '') $headers[] = 'Content-Type: ' . $contentType;
    $requestId = (string)($_SERVER['HTTP_X_REQUEST_ID'] ?? '');
    if ($requestId !== '' && preg_match('/^[A-Za-z0-9._-]{1,80}$/', $requestId)) $headers[] = 'X-Request-Id: ' . $requestId;

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CONNECTTIMEOUT => max(2, (int)$cfg['connect_timeout']),
        CURLOPT_TIMEOUT => max(5, (int)$cfg['request_timeout']),
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HEADER => false,
    ]);
    if ($body !== '' && !in_array($method, ['GET','HEAD'], true)) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $response = curl_exec($ch);
    $errorNo = curl_errno($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $responseType = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    if ($response === false || $errorNo !== 0) {
        error_log('Pluschat gateway upstream failure: curl=' . $errorNo);
        jsonResponse(502, ['ok'=>false,'error'=>'upstream_unavailable','request_id'=>bin2hex(random_bytes(8))]);
    }
    http_response_code($status > 0 ? $status : 502);
    if (stripos($responseType, 'application/json') !== false) header('Content-Type: application/json; charset=utf-8');
    echo $response;
    exit;
}

$cfg = config();
applyCors($cfg);
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$path = pathInfo();

if ($path === '/' || $path === '/api/health') {
    jsonResponse(200, [
        'ok'=>true,
        'service'=>'pluschat-gateway',
        'status'=>'available',
        'api_version'=>1,
        'time'=>gmdate('c'),
        'routes'=>['/api/health','/api/v1/*']
    ]);
}

if ($path === '/api/v1/health' && $method === 'GET') {
    upstream($cfg, 'health', 'GET', '');
}

if (str_starts_with($path, '/api/v1/')) {
    if (!in_array($method, ['GET','POST','PUT','PATCH','DELETE','HEAD'], true)) {
        header('Allow: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
        jsonResponse(405, ['ok'=>false,'error'=>'method_not_allowed']);
    }
    $body = requestBody((int)$cfg['max_body_bytes']);
    try {
        checkRateLimit($cfg);
    } catch (Throwable $e) {
        error_log('Pluschat gateway rate-limit storage unavailable: ' . get_class($e));
        jsonResponse(503, ['ok'=>false,'error'=>'gateway_storage_unavailable']);
    }
    upstream($cfg, substr($path, strlen('/api/v1/')), $method, $body);
}

jsonResponse(404, ['ok'=>false,'error'=>'route_not_found','service'=>'pluschat-gateway']);
