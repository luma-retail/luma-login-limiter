<?php
/**
 * Plugin Name: Luma Login Limiter
 * Plugin URI: https://github.com/luma/luma-login-limiter
 * Description: Lightweight gateway-aware login protection for browser login, paywall flows, and XML-RPC.
 * Version: 0.2.1
 * Author: Luma Solutions
 * Author URI: https://www.luma-retail.com/
 * Requires at least: 6.4
 * Requires PHP: 8.0
 * Text Domain: luma-login-limiter
 * Domain Path: /languages
 * Network: true
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/class-settings.php';
require_once __DIR__ . '/includes/class-state-repository.php';
require_once __DIR__ . '/includes/class-logger-interface.php';
require_once __DIR__ . '/includes/class-logger.php';
require_once __DIR__ . '/includes/class-ip-resolver.php';
require_once __DIR__ . '/includes/class-gateway-context.php';
require_once __DIR__ . '/includes/class-rate-limiter.php';
require_once __DIR__ . '/includes/class-auth-guard.php';
require_once __DIR__ . '/includes/class-xmlrpc-manager.php';
require_once __DIR__ . '/includes/class-admin-page.php';
require_once __DIR__ . '/includes/class-plugin.php';

use Luma\LoginLimiter\Plugin;

function luma_login_limiter(): Plugin {
    return Plugin::instance();
}

register_activation_hook(__FILE__, array(Plugin::class, 'activate'));

add_action(
    'plugins_loaded',
    static function (): void {
        try {
            luma_login_limiter()->boot();
        } catch (\Throwable $throwable) {
            error_log(
                sprintf(
                    '[luma-login-limiter] bootstrap_failed: %s',
                    $throwable->getMessage()
                )
            );
        }
    }
);

function luma_login_limiter_mark_gateway(string $gateway = 'paywall'): void {
    luma_login_limiter()->mark_gateway($gateway);
}

function luma_login_limiter_authenticate_paywall_credentials(
    string $username,
    string $password,
    bool $remember = false
) {
    luma_login_limiter_mark_gateway('paywall');

    return wp_signon(
        array(
            'user_login'    => $username,
            'user_password' => $password,
            'remember'      => $remember,
        ),
        is_ssl()
    );
}
