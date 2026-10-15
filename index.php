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

function checkRateLimit(array $cfg): void {
    // File-based rate limiter works on shared PHP hosting without requiring a
    // separate database connection or manual SQL setup.
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $key = hash('sha256', $ip);
    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'pluschat-gateway-limits';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Rate-limit storage unavailable');
    }
    @chmod($dir, 0700);
    $file = $dir . DIRECTORY_SEPARATOR . $key . '.json';
    $handle = @fopen($file, 'c+');
    if ($handle === false) throw new RuntimeException('Rate-limit storage unavailable');
    try {
        if (!flock($handle, LOCK_EX)) throw new RuntimeException('Rate-limit lock unavailable');
        $raw = stream_get_contents($handle);
        $state = is_string($raw) ? json_decode($raw, true) : null;
        $now = time();
        $window = is_array($state) ? (int)($state['window'] ?? 0) : 0;
        $count = is_array($state) ? (int)($state['count'] ?? 0) : 0;
        if ($window < $now - 60) {
            $window = $now;
            $count = 0;
        }
        $count++;
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode(['window'=>$window, 'count'=>$count]));
        fflush($handle);
        flock($handle, LOCK_UN);
        if ($count > max(30, (int)($cfg['rate_limit_per_minute'] ?? 120))) {
            header('Retry-After: 60');
            jsonResponse(429, ['ok'=>false,'error'=>'rate_limit_exceeded','retry_after'=>60]);
        }
    } finally {
        fclose($handle);
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
