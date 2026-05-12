<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class State_Repository {
    public const OPTION_NAME = 'luma_login_limiter_state';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $state = null;

    public function activate(): void {
        if (false === get_option(self::OPTION_NAME, false)) {
            add_option(self::OPTION_NAME, $this->default_state(), '', false);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array {
        if (null !== $this->state) {
            return $this->state;
        }

        $stored = get_option(self::OPTION_NAME, array());
        $stored = is_array($stored) ? $stored : array();
        $this->state = array_merge($this->default_state(), $stored);

        return $this->state;
    }

    public function cleanup(Settings $settings): void {
        $state   = $this->all();
        $now     = time();
        $changed = false;

        foreach ($state['counters'] as $gateway => $scopes) {
            foreach ($scopes as $scope => $entries) {
                foreach ($entries as $value => $entry) {
                    if (($entry['last_failure'] ?? 0) + $settings->reset_window_seconds() < $now) {
                        unset($state['counters'][$gateway][$scope][$value]);
                        $changed = true;
                    }
                }
            }
        }

        foreach ($state['lockouts'] as $gateway => $scopes) {
            foreach ($scopes as $scope => $entries) {
                foreach ($entries as $value => $entry) {
                    if (($entry['until'] ?? 0) <= $now) {
                        unset($state['lockouts'][$gateway][$scope][$value]);
                        $changed = true;
                    }
                }
            }
        }

        foreach ($state['history'] as $gateway => $scopes) {
            foreach ($scopes as $scope => $entries) {
                foreach ($entries as $value => $timestamps) {
                    $filtered = array_values(
                        array_filter(
                            is_array($timestamps) ? $timestamps : array(),
                            static fn ($timestamp): bool => (int) $timestamp + $settings->escalation_window_seconds() >= $now
                        )
                    );

                    if (empty($filtered)) {
                        unset($state['history'][$gateway][$scope][$value]);
                        $changed = true;
                        continue;
                    }

                    if ($filtered !== $timestamps) {
                        $state['history'][$gateway][$scope][$value] = $filtered;
                        $changed = true;
                    }
                }
            }
        }

        $max_log_entries = $settings->max_log_entries();
        if (count($state['logs']) > $max_log_entries) {
            $state['logs'] = array_slice($state['logs'], 0, $max_log_entries);
            $changed       = true;
        }

        if ($changed) {
            $this->state = $state;
            $this->persist();
        }
    }

    /**
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    public function increment_counter(
        string $gateway,
        string $scope,
        string $value,
        string $reason,
        array $metadata,
        int $reset_window_seconds
    ): array {
        $state = $this->all();
        $now   = time();

        if (! isset($state['counters'][$gateway][$scope][$value])) {
            $state['counters'][$gateway][$scope][$value] = array(
                'count'        => 0,
                'first_failure' => $now,
                'last_failure' => $now,
                'reason'       => $reason,
            );
        }

        $entry = $state['counters'][$gateway][$scope][$value];

        if (($entry['last_failure'] ?? 0) + $reset_window_seconds < $now) {
            $entry['count']         = 0;
            $entry['first_failure'] = $now;
        }

        $entry['count']        = ((int) ($entry['count'] ?? 0)) + 1;
        $entry['last_failure'] = $now;
        $entry['reason']       = $reason;
        $entry['metadata']     = $metadata;

        $state['counters'][$gateway][$scope][$value] = $entry;
        $this->state                                  = $state;
        $this->persist();

        return $entry;
    }

    public function clear_counter(string $gateway, string $scope, string $value): void {
        $state = $this->all();

        if (! isset($state['counters'][$gateway][$scope][$value])) {
            return;
        }

        unset($state['counters'][$gateway][$scope][$value]);
        $this->state = $state;
        $this->persist();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function get_lockout(string $gateway, string $scope, string $value): ?array {
        $state = $this->all();
        $entry = $state['lockouts'][$gateway][$scope][$value] ?? null;

        if (! is_array($entry)) {
            return null;
        }

        if (($entry['until'] ?? 0) <= time()) {
            unset($state['lockouts'][$gateway][$scope][$value]);
            $this->state = $state;
            $this->persist();

            return null;
        }

        return $entry;
    }

    /**
     * @param array<string, mixed> $entry
     */
    public function set_lockout(string $gateway, string $scope, string $value, array $entry): void {
        $state = $this->all();
        $state['lockouts'][$gateway][$scope][$value] = $entry;
        $this->state                                 = $state;
        $this->persist();
    }

    public function clear_lockout(string $gateway, string $scope, string $value): void {
        $state = $this->all();

        if (! isset($state['lockouts'][$gateway][$scope][$value])) {
            return;
        }

        unset($state['lockouts'][$gateway][$scope][$value]);
        $this->state = $state;
        $this->persist();
    }

    public function record_lockout_history(string $gateway, string $scope, string $value): int {
        $state = $this->all();

        if (! isset($state['history'][$gateway][$scope][$value]) || ! is_array($state['history'][$gateway][$scope][$value])) {
            $state['history'][$gateway][$scope][$value] = array();
        }

        $state['history'][$gateway][$scope][$value][] = time();
        $count                                         = count($state['history'][$gateway][$scope][$value]);
        $this->state                                   = $state;
        $this->persist();

        return $count;
    }

    public function count_recent_lockouts(string $gateway, string $scope, string $value, int $window_seconds): int {
        $state      = $this->all();
        $timestamps = $state['history'][$gateway][$scope][$value] ?? array();
        $cutoff     = time() - $window_seconds;

        if (! is_array($timestamps)) {
            return 0;
        }

        return count(
            array_filter(
                $timestamps,
                static fn ($timestamp): bool => (int) $timestamp >= $cutoff
            )
        );
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function active_lockouts(): array {
        $state    = $this->all();
        $lockouts = array();
        $now      = time();

        foreach ($state['lockouts'] as $gateway => $scopes) {
            foreach ($scopes as $scope => $entries) {
                foreach ($entries as $value => $entry) {
                    if (($entry['until'] ?? 0) <= $now) {
                        continue;
                    }

                    $lockouts[] = array_merge(
                        $entry,
                        array(
                            'gateway' => $gateway,
                            'scope'   => $scope,
                            'value'   => $value,
                        )
                    );
                }
            }
        }

        usort(
            $lockouts,
            static fn (array $left, array $right): int => (int) ($right['until'] ?? 0) <=> (int) ($left['until'] ?? 0)
        );

        return $lockouts;
    }

    /**
     * @param array<string, mixed> $entry
     */
    public function add_log(array $entry, int $max_entries): void {
        $state = $this->all();
        array_unshift($state['logs'], $entry);
        $state['logs'] = array_slice($state['logs'], 0, $max_entries);
        $this->state   = $state;
        $this->persist();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function logs(int $limit = 50): array {
        $logs = $this->all()['logs'];

        return array_slice(is_array($logs) ? $logs : array(), 0, $limit);
    }

    /**
     * @return array<string, mixed>
     */
    private function default_state(): array {
        return array(
            'counters' => array(),
            'lockouts' => array(),
            'history'  => array(),
            'logs'     => array(),
        );
    }

    private function persist(): void {
        update_option(self::OPTION_NAME, $this->state ?? $this->default_state(), false);
    }
}
