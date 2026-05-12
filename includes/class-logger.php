<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Logger implements Logger_Interface {
    private const LEVELS = array(
        'debug'   => 10,
        'info'    => 20,
        'warning' => 30,
        'error'   => 40,
    );

    public function __construct(
        private readonly Settings $settings,
        private readonly State_Repository $state
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $event, array $context = array()): void {
        $level = isset(self::LEVELS[$level]) ? $level : 'info';

        if (! $this->should_log($level)) {
            return;
        }

        $entry = array(
            'timestamp'   => gmdate('c'),
            'plugin'      => 'luma-login-limiter',
            'component'   => (string) ($context['component'] ?? 'auth'),
            'event'       => $event,
            'gateway'     => (string) ($context['gateway'] ?? ''),
            'username'    => (string) ($context['username'] ?? ''),
            'ip'          => (string) ($context['ip'] ?? ''),
            'outcome'     => (string) ($context['outcome'] ?? ''),
            'reason_code' => (string) ($context['reason_code'] ?? ''),
            'level'       => $level,
            'context'     => $this->sanitize_context($context),
        );

        try {
            $this->state->add_log($entry, $this->settings->max_log_entries());
        } catch (\Throwable $throwable) {
            error_log(wp_json_encode($entry));
        }
    }

    private function should_log(string $level): bool {
        $configured = $this->settings->log_level();
        $configured = isset(self::LEVELS[$configured]) ? $configured : 'info';

        return self::LEVELS[$level] >= self::LEVELS[$configured];
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function sanitize_context(array $context): array {
        $sanitized = array();

        foreach ($context as $key => $value) {
            if ($this->is_secret_key((string) $key)) {
                continue;
            }

            if (is_scalar($value) || null === $value) {
                $sanitized[$key] = (string) $value;
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = $this->sanitize_array($value);
            }
        }

        return $sanitized;
    }

    /**
     * @param array<mixed> $values
     * @return array<mixed>
     */
    private function sanitize_array(array $values): array {
        $sanitized = array();

        foreach ($values as $key => $value) {
            if ($this->is_secret_key((string) $key)) {
                continue;
            }

            if (is_scalar($value) || null === $value) {
                $sanitized[$key] = (string) $value;
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = $this->sanitize_array($value);
            }
        }

        return $sanitized;
    }

    private function is_secret_key(string $key): bool {
        return (bool) preg_match('/pass(word)?|token|secret|authorization|app_password/i', $key);
    }
}
