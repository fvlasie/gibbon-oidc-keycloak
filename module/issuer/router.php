<?php

declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (is_file(__DIR__.$path) && !str_ends_with($path, '.php')) {
    return false;
}

require __DIR__.'/index.php';
