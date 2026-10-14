<?php

/**
 * auto_prepend_file entry point. Works with or without Composer's autoloader.
 *
 *   .user.ini / php.ini:  auto_prepend_file = "/home/USER/adel-waf/prepend.php"
 */

if (PHP_SAPI === 'cli') {
    return;
}

$adelWafAutoload = __DIR__ . '/vendor/autoload.php';
if (is_file($adelWafAutoload)) {
    require_once $adelWafAutoload;
} else {
    spl_autoload_register(static function (string $class): void {
        if (strncmp($class, 'AdelWAF\\', 8) === 0) {
            $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 8)) . '.php';
            if (is_file($file)) {
                require $file;
            }
        }
    });
}
unset($adelWafAutoload);

\AdelWAF\Integration\Bootstrap::run(null, __DIR__);
