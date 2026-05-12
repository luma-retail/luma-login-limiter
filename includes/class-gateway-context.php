<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Gateway_Context {
    private ?string $gateway = null;

    private ?string $xmlrpc_method = null;

    public function mark(string $gateway): void {
        $allowed = array('wp-login', 'paywall', 'xmlrpc');
        $this->gateway = in_array($gateway, $allowed, true) ? $gateway : 'paywall';
    }

    public function current(): string {
        if (\defined('XMLRPC_REQUEST') && true === \constant('XMLRPC_REQUEST')) {
            return 'xmlrpc';
        }

        if (null !== $this->gateway) {
            return $this->gateway;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $script_name = isset($_SERVER['SCRIPT_NAME']) ? (string) wp_unslash($_SERVER['SCRIPT_NAME']) : '';

        if (str_contains($request_uri, 'wp-login.php') || str_contains($script_name, 'wp-login.php')) {
            return 'wp-login';
        }

        return 'paywall';
    }

    public function set_xmlrpc_method(string $method): void {
        $this->xmlrpc_method = $method;
    }

    public function xmlrpc_method(): string {
        return $this->xmlrpc_method ?? '';
    }
}
