<?php
declare(strict_types=1);

/*
 * Optional server-only config.php. Do not commit config.php.
 * Environment variables override these defaults.
 */
return [
    'service_name' => 'pluschat-gateway',
    'base_url' => 'https://прото.плюсчат.рф',
    'main_api_base' => 'https://xn--80avljg2a1c.xn--p1ai/api/v1',

    // The gateway's prepared MySQL database. Password must be set in hosting env.
    'db_host' => 'localhost',
    'db_name' => 'Pluschat',
    'db_user' => 'Admin',
    'db_password' => '',

    // Use a random secret of at least 64 characters for IP-key hashing.
    'token_pepper' => '',

    'allowed_origins' => [
        'https://xn--80avljg2a1c.xn--p1ai',
        'https://xn--n1aabel.xn--80avljg2a1c.xn--p1ai',
        'https://прото.плюсчат.рф',
        'https://xn--n1aabel.xn--80avljg2a1c.xn--p1ai',
        'http://localhost',
        'http://127.0.0.1',
        'null',
    ],
    'connect_timeout' => 4,
    'request_timeout' => 20,
    'max_body_bytes' => 1048576,
    'rate_limit_per_minute' => 120,
];
