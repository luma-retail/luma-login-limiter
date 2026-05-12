<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Settings {
    public const OPTION_NAME = 'luma_login_limiter_settings';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $settings = null;

    /**
     * @return array<string, mixed>
     */
    public function defaults(): array {
        return array(
            'threshold_wp_login'                  => 5,
            'threshold_paywall'                   => 5,
            'threshold_xmlrpc'                    => 3,
            'reset_window_minutes'                => 30,
            'base_lockout_minutes'                => 15,
            'escalation_window_minutes'           => 1440,
            'escalation_factor'                   => 2,
            'escalation_cap'                      => 8,
            'xmlrpc_allowlist_users'              => array(),
            'xmlrpc_allowlist_capabilities'       => array(),
            'xmlrpc_require_application_password' => true,
            'emergency_bypass_username'           => '',
            'log_level'                           => 'info',
            'trusted_ip_header'                   => 'REMOTE_ADDR',
            'max_log_entries'                     => 200,
        );
    }

    public function activate(): void {
        if (false === get_option(self::OPTION_NAME, false)) {
            add_option(self::OPTION_NAME, $this->defaults(), '', false);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array {
        if (null !== $this->settings) {
            return $this->settings;
        }

        $stored = get_option(self::OPTION_NAME, array());
        $stored = is_array($stored) ? $stored : array();
        $this->settings = array_merge($this->defaults(), $stored);

        return $this->settings;
    }

    /**
     * @param array<string, mixed> $raw
     */
    public function update(array $raw): void {
        $settings = $this->sanitize($raw);
        update_option(self::OPTION_NAME, $settings, false);
        $this->settings = $settings;
    }

    public function threshold_for(string $gateway): int {
        $settings = $this->all();

        return match ($gateway) {
            'xmlrpc'   => (int) $settings['threshold_xmlrpc'],
            'paywall'  => (int) $settings['threshold_paywall'],
            default    => (int) $settings['threshold_wp_login'],
        };
    }

    public function reset_window_seconds(): int {
        return max(5, (int) $this->all()['reset_window_minutes']) * MINUTE_IN_SECONDS;
    }

    public function base_lockout_seconds(): int {
        return max(1, (int) $this->all()['base_lockout_minutes']) * MINUTE_IN_SECONDS;
    }

    public function escalation_window_seconds(): int {
        return max(5, (int) $this->all()['escalation_window_minutes']) * MINUTE_IN_SECONDS;
    }

    public function escalation_factor(): int {
        return max(1, (int) $this->all()['escalation_factor']);
    }

    public function escalation_cap(): int {
        return max(1, (int) $this->all()['escalation_cap']);
    }

    /**
     * @return string[]
     */
    public function xmlrpc_allowlist_users(): array {
        return $this->normalize_string_list($this->all()['xmlrpc_allowlist_users']);
    }

    /**
     * @return string[]
     */
    public function xmlrpc_allowlist_capabilities(): array {
        return $this->normalize_string_list($this->all()['xmlrpc_allowlist_capabilities']);
    }

    public function xmlrpc_requires_application_password(): bool {
        return ! empty($this->all()['xmlrpc_require_application_password']);
    }

    public function emergency_bypass_username(): string {
        return (string) $this->all()['emergency_bypass_username'];
    }

    public function log_level(): string {
        return (string) $this->all()['log_level'];
    }

    public function trusted_ip_header(): string {
        return (string) $this->all()['trusted_ip_header'];
    }

    public function max_log_entries(): int {
        return max(50, (int) $this->all()['max_log_entries']);
    }

    /**
     * @param mixed $value
     * @return string[]
     */
    private function normalize_string_list($value): array {
        if (! is_array($value)) {
            return array();
        }

        $sanitized = array_map(
            static function ($item): string {
                return strtolower(trim(sanitize_text_field((string) $item)));
            },
            $value
        );

        return array_values(array_filter(array_unique($sanitized)));
    }

    /**
     * @param array<string, mixed> $raw
     * @return array<string, mixed>
     */
    private function sanitize(array $raw): array {
        $defaults = $this->defaults();

        $settings = array(
            'threshold_wp_login'                  => $this->sanitize_positive_int($raw['threshold_wp_login'] ?? $defaults['threshold_wp_login'], 2),
            'threshold_paywall'                   => $this->sanitize_positive_int($raw['threshold_paywall'] ?? $defaults['threshold_paywall'], 2),
            'threshold_xmlrpc'                    => $this->sanitize_positive_int($raw['threshold_xmlrpc'] ?? $defaults['threshold_xmlrpc'], 1),
            'reset_window_minutes'                => $this->sanitize_positive_int($raw['reset_window_minutes'] ?? $defaults['reset_window_minutes'], 5),
            'base_lockout_minutes'                => $this->sanitize_positive_int($raw['base_lockout_minutes'] ?? $defaults['base_lockout_minutes'], 1),
            'escalation_window_minutes'           => $this->sanitize_positive_int($raw['escalation_window_minutes'] ?? $defaults['escalation_window_minutes'], 5),
            'escalation_factor'                   => $this->sanitize_positive_int($raw['escalation_factor'] ?? $defaults['escalation_factor'], 1),
            'escalation_cap'                      => $this->sanitize_positive_int($raw['escalation_cap'] ?? $defaults['escalation_cap'], 1),
            'xmlrpc_allowlist_users'              => $this->sanitize_list_textarea($raw['xmlrpc_allowlist_users'] ?? array()),
            'xmlrpc_allowlist_capabilities'       => $this->sanitize_list_textarea($raw['xmlrpc_allowlist_capabilities'] ?? array()),
            'xmlrpc_require_application_password' => ! empty($raw['xmlrpc_require_application_password']),
            'emergency_bypass_username'           => sanitize_user((string) ($raw['emergency_bypass_username'] ?? ''), true),
            'log_level'                           => $this->sanitize_log_level((string) ($raw['log_level'] ?? $defaults['log_level'])),
            'trusted_ip_header'                   => $this->sanitize_ip_header((string) ($raw['trusted_ip_header'] ?? $defaults['trusted_ip_header'])),
            'max_log_entries'                     => (int) $defaults['max_log_entries'],
        );

        return $settings;
    }

    /**
     * @param mixed $value
     */
    private function sanitize_positive_int($value, int $minimum): int {
        $value = absint($value);

        return max($minimum, $value);
    }

    /**
     * @param mixed $value
     * @return string[]
     */
    private function sanitize_list_textarea($value): array {
        if (is_array($value)) {
            $value = implode("\n", array_map('strval', $value));
        }

        $items = preg_split('/[\r\n,]+/', (string) $value) ?: array();
        $items = array_map(
            static function (string $item): string {
                return strtolower(trim(sanitize_text_field($item)));
            },
            $items
        );

        return array_values(array_filter(array_unique($items)));
    }

    private function sanitize_log_level(string $value): string {
        $allowed = array('error', 'warning', 'info', 'debug');

        return in_array($value, $allowed, true) ? $value : 'info';
    }

    private function sanitize_ip_header(string $value): string {
        $allowed = array('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP');

        return in_array($value, $allowed, true) ? $value : 'REMOTE_ADDR';
    }
}
