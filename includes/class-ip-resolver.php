<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Ip_Resolver {
    public function __construct(private readonly Settings $settings) {
    }

    public function resolve(): string {
        $header = $this->settings->trusted_ip_header();
        $value  = $this->read_server_value($header);

        if ('' === $value && 'REMOTE_ADDR' !== $header) {
            $value = $this->read_server_value('REMOTE_ADDR');
        }

        if ('' === $value) {
            return 'unknown';
        }

        if ('HTTP_X_FORWARDED_FOR' === $header) {
            $parts = array_map('trim', explode(',', $value));
            $value = (string) ($parts[0] ?? '');
        }

        return filter_var($value, FILTER_VALIDATE_IP) ? $value : 'unknown';
    }

    /**
     * @return array<string, string>
     */
    public function supported_headers(): array {
        return array(
            'REMOTE_ADDR'          => __('Direct connection (REMOTE_ADDR)', 'luma-login-limiter'),
            'HTTP_X_FORWARDED_FOR' => __('Trusted proxy chain (X-Forwarded-For)', 'luma-login-limiter'),
            'HTTP_X_REAL_IP'       => __('Reverse proxy single IP (X-Real-IP)', 'luma-login-limiter'),
            'HTTP_CF_CONNECTING_IP' => __('Cloudflare connecting IP', 'luma-login-limiter'),
        );
    }

    private function read_server_value(string $key): string {
        return isset($_SERVER[$key]) ? sanitize_text_field(wp_unslash((string) $_SERVER[$key])) : '';
    }
}
