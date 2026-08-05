<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

use WP_Error;
use WP_User;

final class Auth_Guard {
    private bool $used_application_password = false;

    public function __construct(
        private readonly Settings $settings,
        private readonly Gateway_Context $context,
        private readonly Ip_Resolver $ip_resolver,
        private readonly Rate_Limiter $rate_limiter,
        private readonly Logger_Interface $logger
    ) {
    }

    public function register(): void {
        add_filter('authenticate', array($this, 'maybe_block_attempt'), 5, 3);
        add_filter('authenticate', array($this, 'handle_auth_result'), 200, 3);
        add_action('wp_login', array($this, 'handle_login_success'), 10, 2);
        add_action('application_password_did_authenticate', array($this, 'mark_application_password_used'), 10, 2);
    }

    /**
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function maybe_block_attempt($user, string $username, string $password) {
        if (! $this->is_auth_attempt($username, $password, $user)) {
            return $user;
        }

        $gateway = $this->context->current();
        $ip      = $this->ip_resolver->resolve();

        $lockout = $this->active_lockout_for_attempt($gateway, $ip, $username);
        if (is_array($lockout)) {
            $this->logger->log(
                'warning',
                'auth_locked',
                array(
                    'gateway'     => $gateway,
                    'username'    => $username,
                    'ip'          => $ip,
                    'outcome'     => 'locked',
                    'reason_code' => 'rate_limited',
                    'lockout'     => $lockout,
                )
            );

            return new WP_Error(
                'luma_rate_limited',
                $this->lockout_message($lockout)
            );
        }

        if ('xmlrpc' === $gateway && ! $this->is_xmlrpc_user_allowed($username)) {
            $tracking_username = $this->tracking_username($username);
            $lockouts          = $this->rate_limiter->register_failure($gateway, $ip, $tracking_username, 'xmlrpc_not_allowlisted');
            $this->log_created_lockouts($lockouts, $gateway, $ip, $tracking_username, 'xmlrpc_not_allowlisted');

            $this->logger->log(
                'warning',
                'xmlrpc_denied_allowlist',
                array(
                    'gateway'     => 'xmlrpc',
                    'username'    => $username,
                    'ip'          => $ip,
                    'outcome'     => 'denied',
                    'reason_code' => 'xmlrpc_not_allowlisted',
                )
            );

            return new WP_Error(
                'luma_xmlrpc_not_allowlisted',
                __('XML-RPC is not enabled for this account.', 'luma-login-limiter')
            );
        }

        return $user;
    }

    /**
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function handle_auth_result($user, string $username, string $password) {
        if (! $this->is_auth_attempt($username, $password, $user)) {
            return $user;
        }

        $gateway = $this->context->current();
        $ip      = $this->ip_resolver->resolve();

        if ($user instanceof WP_User) {
            $lockout = $this->active_lockout_for_attempt($gateway, $ip, $username);

            if (is_array($lockout)) {
                $this->logger->log(
                    'warning',
                    'auth_locked',
                    array(
                        'gateway'     => $gateway,
                        'username'    => $username,
                        'ip'          => $ip,
                        'outcome'     => 'locked',
                        'reason_code' => 'rate_limited',
                        'lockout'     => $lockout,
                    )
                );

                return new WP_Error(
                    'luma_rate_limited',
                    $this->lockout_message($lockout)
                );
            }

            if ('xmlrpc' === $gateway && $this->settings->xmlrpc_requires_application_password() && ! $this->used_application_password) {
                $tracking_username = $this->tracking_username($username);
                $lockouts          = $this->rate_limiter->register_failure('xmlrpc', $ip, $tracking_username, 'xmlrpc_application_password_required');
                $this->log_created_lockouts($lockouts, 'xmlrpc', $ip, $tracking_username, 'xmlrpc_application_password_required');

                $this->logger->log(
                    'warning',
                    'xmlrpc_denied_application_password',
                    array(
                        'gateway'     => 'xmlrpc',
                        'username'    => $username,
                        'ip'          => $ip,
                        'outcome'     => 'denied',
                        'reason_code' => 'xmlrpc_application_password_required',
                    )
                );

                return new WP_Error(
                    'luma_xmlrpc_application_password_required',
                    __('XML-RPC requires an application password for allowed users.', 'luma-login-limiter')
                );
            }

            if ('xmlrpc' === $gateway) {
                $this->rate_limiter->clear_failures('xmlrpc', $ip, $this->tracking_username($username));

                $this->logger->log(
                    'info',
                    'auth_success',
                    array(
                        'gateway'     => 'xmlrpc',
                        'username'    => $username,
                        'ip'          => $ip,
                        'outcome'     => 'success',
                        'reason_code' => 'authenticated',
                    )
                );
            }

            return $user;
        }

        if (! $user instanceof WP_Error || $this->is_own_error($user)) {
            return $user;
        }

        $reason            = $this->reason_code_from_error($user);
        $tracking_username = $this->tracking_username($username);
        $lockouts          = $this->rate_limiter->register_failure($gateway, $ip, $tracking_username, $reason);
        $this->log_created_lockouts($lockouts, $gateway, $ip, $tracking_username, $reason);

        $this->logger->log(
            'warning',
            'auth_failed',
            array(
                'gateway'     => $gateway,
                'username'    => $username,
                'ip'          => $ip,
                'outcome'     => 'failed',
                'reason_code' => $this->reason_code_from_error($user),
            )
        );

        return $user;
    }

    public function handle_login_success(string $user_login, WP_User $user): void {
        $gateway = $this->context->current();

        if ('xmlrpc' === $gateway) {
            return;
        }

        $ip = $this->ip_resolver->resolve();

        $this->rate_limiter->clear_failures($gateway, $ip, $this->tracking_username($user_login));

        $this->logger->log(
            'info',
            'auth_success',
            array(
                'gateway'     => $gateway,
                'username'    => $user_login,
                'ip'          => $ip,
                'outcome'     => 'success',
                'reason_code' => 'authenticated',
                'user_id'     => (string) $user->ID,
            )
        );
    }

    /**
     * @param array<string, mixed> $item
     */
    public function mark_application_password_used(WP_User $user, array $item): void {
        $this->used_application_password = true;
    }

    /**
     * @param WP_User|WP_Error|null $user
     */
    private function is_auth_attempt(string $username, string $password, $user): bool {
        if ('' !== $username || '' !== $password) {
            return true;
        }

        return $user instanceof WP_Error;
    }

    private function is_emergency_bypass(string $username): bool {
        $configured = strtolower($this->settings->emergency_bypass_username());

        return '' !== $configured && strtolower($username) === $configured;
    }

    private function tracking_username(string $username): string {
        if ($this->is_emergency_bypass($username)) {
            return '';
        }

        return $username;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function active_lockout_for_attempt(string $gateway, string $ip, string $username): ?array {
        if (! $this->is_emergency_bypass($username)) {
            return $this->rate_limiter->active_lockout($gateway, $ip, $username);
        }

        return $this->rate_limiter->active_ip_lockout($gateway, $ip);
    }

    private function is_xmlrpc_user_allowed(string $username): bool {
        $normalized_username = strtolower(trim($username));

        if ('' === $normalized_username) {
            return false;
        }

        if (in_array($normalized_username, $this->settings->xmlrpc_allowlist_users(), true)) {
            return true;
        }

        $capabilities = $this->settings->xmlrpc_allowlist_capabilities();
        if (empty($capabilities)) {
            return false;
        }

        $user = get_user_by('login', $normalized_username);
        if (! $user && is_email($normalized_username)) {
            $user = get_user_by('email', $normalized_username);
        }

        if (! $user instanceof WP_User) {
            return false;
        }

        foreach ($capabilities as $capability) {
            if (user_can($user, $capability)) {
                return true;
            }
        }

        return false;
    }

    private function is_own_error(WP_Error $error): bool {
        $codes = $error->get_error_codes();

        return in_array('luma_rate_limited', $codes, true)
            || in_array('luma_xmlrpc_not_allowlisted', $codes, true)
            || in_array('luma_xmlrpc_application_password_required', $codes, true);
    }

    private function reason_code_from_error(WP_Error $error): string {
        $codes = $error->get_error_codes();

        return (string) ($codes[0] ?? 'authentication_failed');
    }

    /**
     * @param array<string, mixed> $lockout
     */
    private function lockout_message(array $lockout): string {
        $until = (int) ($lockout['until'] ?? 0);

        if ($until <= time()) {
            return __('Too many recent login failures. Please try again shortly.', 'luma-login-limiter');
        }

        $remaining = $until - time();
        $wait_time = $remaining < MINUTE_IN_SECONDS
            ? __('less than a minute', 'luma-login-limiter')
            : human_time_diff(time(), $until);

        return sprintf(
            __('Too many recent login failures. Please try again in %s.', 'luma-login-limiter'),
            $wait_time
        );
    }

    /**
     * @param array<int, array<string, mixed>> $lockouts
     */
    private function log_created_lockouts(array $lockouts, string $gateway, string $ip, string $username, string $reason): void {
        foreach ($lockouts as $lockout) {
            $this->logger->log(
                'warning',
                'lockout_created',
                array(
                    'gateway'     => $gateway,
                    'username'    => $username,
                    'ip'          => $ip,
                    'outcome'     => 'locked',
                    'reason_code' => $reason,
                    'lockout'     => $lockout,
                )
            );
        }
    }
}
