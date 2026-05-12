<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Rate_Limiter {
    public function __construct(
        private readonly Settings $settings,
        private readonly State_Repository $state
    ) {
    }

    /**
     * @return array<string, mixed>|null
     */
    public function active_lockout(string $gateway, string $ip, string $username = ''): ?array {
        $matches = array();

        $ip_lockout = $this->state->get_lockout($gateway, 'ip', $ip);
        if (is_array($ip_lockout)) {
            $matches[] = array_merge($ip_lockout, array('scope' => 'ip', 'value' => $ip));
        }

        if ('' !== $username) {
            $user_lockout = $this->state->get_lockout($gateway, 'username', strtolower($username));
            if (is_array($user_lockout)) {
                $matches[] = array_merge($user_lockout, array('scope' => 'username', 'value' => strtolower($username)));
            }
        }

        if (empty($matches)) {
            return null;
        }

        usort(
            $matches,
            static fn (array $left, array $right): int => (int) ($right['until'] ?? 0) <=> (int) ($left['until'] ?? 0)
        );

        return $matches[0];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function register_failure(string $gateway, string $ip, string $username, string $reason): array {
        $created   = array();
        $threshold = $this->settings->threshold_for($gateway);
        $metadata  = array(
            'ip'       => $ip,
            'username' => $username,
            'reason'   => $reason,
        );

        $ip_counter = $this->state->increment_counter(
            $gateway,
            'ip',
            $ip,
            $reason,
            $metadata,
            $this->settings->reset_window_seconds()
        );

        if ((int) $ip_counter['count'] >= $threshold && null === $this->state->get_lockout($gateway, 'ip', $ip)) {
            $created[] = $this->create_lockout($gateway, 'ip', $ip, $reason, $ip, $username);
        }

        if ('' !== $username) {
            $username = strtolower($username);
            $user_counter = $this->state->increment_counter(
                $gateway,
                'username',
                $username,
                $reason,
                $metadata,
                $this->settings->reset_window_seconds()
            );

            if ((int) $user_counter['count'] >= $threshold && null === $this->state->get_lockout($gateway, 'username', $username)) {
                $created[] = $this->create_lockout($gateway, 'username', $username, $reason, $ip, $username);
            }
        }

        return $created;
    }

    public function clear_failures(string $gateway, string $ip, string $username = ''): void {
        $this->state->clear_counter($gateway, 'ip', $ip);

        if ('' !== $username) {
            $this->state->clear_counter($gateway, 'username', strtolower($username));
        }
    }

    public function unlock(string $gateway, string $scope, string $value): void {
        $normalized_value = 'username' === $scope ? strtolower($value) : $value;
        $this->state->clear_lockout($gateway, $scope, $normalized_value);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function active_lockouts(): array {
        return $this->state->active_lockouts();
    }

    /**
     * @return array<string, mixed>
     */
    private function create_lockout(
        string $gateway,
        string $scope,
        string $value,
        string $reason,
        string $ip,
        string $username
    ): array {
        $previous_count = $this->state->count_recent_lockouts(
            $gateway,
            $scope,
            $value,
            $this->settings->escalation_window_seconds()
        );

        $factor      = min($this->settings->escalation_cap(), (int) pow($this->settings->escalation_factor(), $previous_count));
        $duration    = $this->settings->base_lockout_seconds() * max(1, $factor);
        $created_at  = time();
        $lockout     = array(
            'created_at' => $created_at,
            'until'      => $created_at + $duration,
            'reason'     => $reason,
            'level'      => $previous_count + 1,
            'ip'         => $ip,
            'username'   => $username,
        );

        $this->state->set_lockout($gateway, $scope, $value, $lockout);
        $this->state->record_lockout_history($gateway, $scope, $value);

        return array_merge($lockout, array(
            'gateway' => $gateway,
            'scope'   => $scope,
            'value'   => $value,
        ));
    }
}
