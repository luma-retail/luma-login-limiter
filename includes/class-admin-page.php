<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Admin_Page {
    private const PAGE_SLUG = 'luma-login-limiter';

    public function __construct(
        private readonly Settings $settings,
        private readonly State_Repository $state,
        private readonly Rate_Limiter $rate_limiter,
        private readonly Ip_Resolver $ip_resolver
    ) {
    }

    public function register(): void {
        add_action('admin_menu', array($this, 'register_menu'));
        add_action('admin_post_luma_login_limiter_save_settings', array($this, 'handle_save_settings'));
        add_action('admin_post_luma_login_limiter_unlock', array($this, 'handle_unlock'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    public function register_menu(): void {
        add_options_page(
            __('Luma Login Limiter', 'luma-login-limiter'),
            __('Luma Login Limiter', 'luma-login-limiter'),
            $this->manage_capability(),
            self::PAGE_SLUG,
            array($this, 'render')
        );
    }

    public function enqueue_assets(string $hook): void {
        if ('settings_page_' . self::PAGE_SLUG !== $hook) {
            return;
        }

        wp_enqueue_style(
            'luma-login-limiter-admin',
            plugins_url('assets/admin.css', dirname(__DIR__) . '/luma-login-limiter.php'),
            array(),
            '0.1.0'
        );
    }

    public function handle_save_settings(): void {
        if (! current_user_can($this->manage_capability())) {
            wp_die(esc_html__('You do not have permission to manage login protection.', 'luma-login-limiter'));
        }

        check_admin_referer('luma_login_limiter_save_settings');

        $this->settings->update(array(
            'threshold_wp_login'                  => $_POST['threshold_wp_login'] ?? null,
            'threshold_paywall'                   => $_POST['threshold_paywall'] ?? null,
            'threshold_xmlrpc'                    => $_POST['threshold_xmlrpc'] ?? null,
            'reset_window_minutes'                => $_POST['reset_window_minutes'] ?? null,
            'base_lockout_minutes'                => $_POST['base_lockout_minutes'] ?? null,
            'escalation_window_minutes'           => $_POST['escalation_window_minutes'] ?? null,
            'escalation_factor'                   => $_POST['escalation_factor'] ?? null,
            'escalation_cap'                      => $_POST['escalation_cap'] ?? null,
            'xmlrpc_allowlist_users'              => $_POST['xmlrpc_allowlist_users'] ?? '',
            'xmlrpc_allowlist_capabilities'       => $_POST['xmlrpc_allowlist_capabilities'] ?? '',
            'xmlrpc_require_application_password' => $_POST['xmlrpc_require_application_password'] ?? '',
            'emergency_bypass_username'           => $_POST['emergency_bypass_username'] ?? '',
            'log_level'                           => $_POST['log_level'] ?? 'info',
            'trusted_ip_header'                   => $_POST['trusted_ip_header'] ?? 'REMOTE_ADDR',
        ));

        wp_safe_redirect($this->admin_url('saved'));
        exit;
    }

    public function handle_unlock(): void {
        if (! current_user_can($this->manage_capability())) {
            wp_die(esc_html__('You do not have permission to unlock requests.', 'luma-login-limiter'));
        }

        check_admin_referer('luma_login_limiter_unlock');

        $gateway = isset($_POST['gateway']) ? sanitize_text_field(wp_unslash((string) $_POST['gateway'])) : '';
        $scope   = isset($_POST['scope']) ? sanitize_text_field(wp_unslash((string) $_POST['scope'])) : '';
        $value   = isset($_POST['value']) ? sanitize_text_field(wp_unslash((string) $_POST['value'])) : '';

        if ('' !== $gateway && '' !== $scope && '' !== $value) {
            $this->rate_limiter->unlock($gateway, $scope, $value);
        }

        wp_safe_redirect($this->admin_url('unlocked'));
        exit;
    }

    public function render(): void {
        if (! current_user_can($this->manage_capability())) {
            wp_die(esc_html__('You do not have permission to view login protection settings.', 'luma-login-limiter'));
        }

        $this->state->cleanup($this->settings);

        $settings         = $this->settings->all();
        $lockouts         = $this->rate_limiter->active_lockouts();
        $logs             = $this->state->logs(25);
        $trusted_headers  = $this->ip_resolver->supported_headers();
        $denied_last_day  = $this->count_denied_in_last_day($logs);
        $gateway_counts   = $this->summarize_gateways($logs);
        ?>
        <div class="wrap luma-login-limiter-admin">
            <div class="luma-hero">
                <div>
                    <p class="luma-kicker"><?php esc_html_e('Authentication hardening', 'luma-login-limiter'); ?></p>
                    <h1><?php esc_html_e('Luma Login Limiter', 'luma-login-limiter'); ?></h1>
                    <p class="luma-intro"><?php esc_html_e('Keep browser login, paywall login, and XML-RPC protected separately with local state, readable logs, and explicit lockout controls.', 'luma-login-limiter'); ?></p>
                </div>
                <div class="luma-hero-badges">
                    <span class="luma-badge"><?php esc_html_e('No cloud dependency', 'luma-login-limiter'); ?></span>
                    <span class="luma-badge"><?php esc_html_e('Gateway-aware counters', 'luma-login-limiter'); ?></span>
                    <span class="luma-badge"><?php esc_html_e('XML-RPC allowlist', 'luma-login-limiter'); ?></span>
                </div>
            </div>

            <?php $this->render_notice(); ?>

            <div class="luma-summary-grid">
                <section class="luma-card">
                    <h2><?php esc_html_e('Current posture', 'luma-login-limiter'); ?></h2>
                    <dl class="luma-stat-list">
                        <div>
                            <dt><?php esc_html_e('Active lockouts', 'luma-login-limiter'); ?></dt>
                            <dd><?php echo esc_html((string) count($lockouts)); ?></dd>
                        </div>
                        <div>
                            <dt><?php esc_html_e('Denied or locked in 24h', 'luma-login-limiter'); ?></dt>
                            <dd><?php echo esc_html((string) $denied_last_day); ?></dd>
                        </div>
                        <div>
                            <dt><?php esc_html_e('Trusted IP source', 'luma-login-limiter'); ?></dt>
                            <dd><?php echo esc_html($trusted_headers[$settings['trusted_ip_header']] ?? $settings['trusted_ip_header']); ?></dd>
                        </div>
                        <div>
                            <dt><?php esc_html_e('XML-RPC password mode', 'luma-login-limiter'); ?></dt>
                            <dd><?php echo ! empty($settings['xmlrpc_require_application_password']) ? esc_html__('Application passwords only', 'luma-login-limiter') : esc_html__('Standard passwords allowed', 'luma-login-limiter'); ?></dd>
                        </div>
                    </dl>
                </section>

                <section class="luma-card">
                    <h2><?php esc_html_e('Recent gateway activity', 'luma-login-limiter'); ?></h2>
                    <ul class="luma-gateway-list">
                        <li>
                            <span><?php esc_html_e('Browser login', 'luma-login-limiter'); ?></span>
                            <strong><?php echo esc_html((string) ($gateway_counts['wp-login'] ?? 0)); ?></strong>
                        </li>
                        <li>
                            <span><?php esc_html_e('Paywall / custom login', 'luma-login-limiter'); ?></span>
                            <strong><?php echo esc_html((string) ($gateway_counts['paywall'] ?? 0)); ?></strong>
                        </li>
                        <li>
                            <span><?php esc_html_e('XML-RPC', 'luma-login-limiter'); ?></span>
                            <strong><?php echo esc_html((string) ($gateway_counts['xmlrpc'] ?? 0)); ?></strong>
                        </li>
                    </ul>
                    <p class="description"><?php esc_html_e('Counts are based on the recent event log kept locally by this plugin.', 'luma-login-limiter'); ?></p>
                </section>

                <section class="luma-card luma-card-help">
                    <h2><?php esc_html_e('Custom login integration', 'luma-login-limiter'); ?></h2>
                    <p><?php esc_html_e('For a paywall or frontend form, mark the request as paywall before authenticating. This keeps counters and logs separate from wp-login.php.', 'luma-login-limiter'); ?></p>
                    <pre><code>luma_login_limiter_mark_gateway( 'paywall' );
$user = wp_signon( $credentials );</code></pre>
                    <p><?php esc_html_e('Or use the helper function included by the plugin:', 'luma-login-limiter'); ?></p>
                    <pre><code>$user = luma_login_limiter_authenticate_paywall_credentials( $username, $password, true );</code></pre>
                </section>
            </div>

            <div class="luma-layout-grid">
                <section class="luma-card luma-card-form">
                    <h2><?php esc_html_e('Protection settings', 'luma-login-limiter'); ?></h2>
                    <p class="description"><?php esc_html_e('These settings control XML-RPC access, gateway-specific thresholds, lockout escalation, and the amount of detail stored in local logs.', 'luma-login-limiter'); ?></p>

                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="luma-settings-form">
                        <?php wp_nonce_field('luma_login_limiter_save_settings'); ?>
                        <input type="hidden" name="action" value="luma_login_limiter_save_settings" />

                        <div class="luma-form-section">
                            <h3><?php esc_html_e('XML-RPC access', 'luma-login-limiter'); ?></h3>
                            <?php $this->render_textarea_field('xmlrpc_allowlist_users', __('Allowlisted usernames or email-style logins', 'luma-login-limiter'), __('One per line or comma separated. Only these usernames are allowed to authenticate over XML-RPC unless an explicit capability below also matches.', 'luma-login-limiter'), implode("\n", $settings['xmlrpc_allowlist_users'])); ?>
                            <?php $this->render_textarea_field('xmlrpc_allowlist_capabilities', __('Explicit XML-RPC capabilities', 'luma-login-limiter'), __('Optional capability names such as manage_options or edit_others_posts. This is an explicit allowlist, not a role shortcut.', 'luma-login-limiter'), implode("\n", $settings['xmlrpc_allowlist_capabilities'])); ?>
                            <?php $this->render_checkbox_field('xmlrpc_require_application_password', __('Require application passwords for XML-RPC', 'luma-login-limiter'), __('Allowed XML-RPC users must authenticate with an application password instead of their standard account password.', 'luma-login-limiter'), ! empty($settings['xmlrpc_require_application_password'])); ?>
                        </div>

                        <div class="luma-form-section">
                            <h3><?php esc_html_e('Gateway thresholds', 'luma-login-limiter'); ?></h3>
                            <div class="luma-field-grid">
                                <?php $this->render_number_field('threshold_wp_login', __('wp-login threshold', 'luma-login-limiter'), __('Failures before browser login is locked.', 'luma-login-limiter'), (int) $settings['threshold_wp_login'], 2); ?>
                                <?php $this->render_number_field('threshold_paywall', __('Paywall threshold', 'luma-login-limiter'), __('Failures before paywall or frontend login is locked.', 'luma-login-limiter'), (int) $settings['threshold_paywall'], 2); ?>
                                <?php $this->render_number_field('threshold_xmlrpc', __('XML-RPC threshold', 'luma-login-limiter'), __('Failures before XML-RPC is locked for the matching IP or username.', 'luma-login-limiter'), (int) $settings['threshold_xmlrpc'], 1); ?>
                            </div>
                        </div>

                        <div class="luma-form-section">
                            <h3><?php esc_html_e('Lockout timing', 'luma-login-limiter'); ?></h3>
                            <div class="luma-field-grid">
                                <?php $this->render_number_field('reset_window_minutes', __('Failure reset window (minutes)', 'luma-login-limiter'), __('Failures expire after this window if no new failures arrive.', 'luma-login-limiter'), (int) $settings['reset_window_minutes'], 5); ?>
                                <?php $this->render_number_field('base_lockout_minutes', __('Base lockout (minutes)', 'luma-login-limiter'), __('The first lockout duration before escalation is applied.', 'luma-login-limiter'), (int) $settings['base_lockout_minutes'], 1); ?>
                                <?php $this->render_number_field('escalation_window_minutes', __('Escalation window (minutes)', 'luma-login-limiter'), __('Repeated lockouts inside this window will increase the duration.', 'luma-login-limiter'), (int) $settings['escalation_window_minutes'], 5); ?>
                                <?php $this->render_number_field('escalation_factor', __('Escalation factor', 'luma-login-limiter'), __('Each repeated lockout multiplies the duration by this factor.', 'luma-login-limiter'), (int) $settings['escalation_factor'], 1); ?>
                                <?php $this->render_number_field('escalation_cap', __('Escalation cap', 'luma-login-limiter'), __('Maximum duration multiplier applied to repeated lockouts.', 'luma-login-limiter'), (int) $settings['escalation_cap'], 1); ?>
                            </div>
                        </div>

                        <div class="luma-form-section">
                            <h3><?php esc_html_e('Operations and recovery', 'luma-login-limiter'); ?></h3>
                            <?php $this->render_text_field('emergency_bypass_username', __('Emergency bypass username', 'luma-login-limiter'), __('Optional trusted admin username that bypasses rate-limit counters and active lockouts. This does not bypass correct credentials or disabled XML-RPC methods.', 'luma-login-limiter'), (string) $settings['emergency_bypass_username']); ?>
                            <?php $this->render_select_field('trusted_ip_header', __('Trusted IP header', 'luma-login-limiter'), __('Default is REMOTE_ADDR. Change this only when you trust the upstream proxy that sets the selected header.', 'luma-login-limiter'), (string) $settings['trusted_ip_header'], $trusted_headers); ?>
                            <?php $this->render_select_field('log_level', __('Log level', 'luma-login-limiter'), __('Choose how much local event detail to keep. Debug stores the most detail and is best used temporarily.', 'luma-login-limiter'), (string) $settings['log_level'], array(
                                'error'   => __('Error', 'luma-login-limiter'),
                                'warning' => __('Warning', 'luma-login-limiter'),
                                'info'    => __('Info', 'luma-login-limiter'),
                                'debug'   => __('Debug', 'luma-login-limiter'),
                            )); ?>
                        </div>

                        <div class="luma-actions">
                            <button type="submit" class="button button-primary button-hero"><?php esc_html_e('Save protection settings', 'luma-login-limiter'); ?></button>
                        </div>
                    </form>
                </section>

                <div class="luma-side-column">
                    <section class="luma-card">
                        <div class="luma-card-header">
                            <h2><?php esc_html_e('Active lockouts', 'luma-login-limiter'); ?></h2>
                            <span class="luma-pill"><?php echo esc_html((string) count($lockouts)); ?></span>
                        </div>
                        <?php if (empty($lockouts)) : ?>
                            <p class="luma-empty-state"><?php esc_html_e('No active lockouts right now. When a threshold is exceeded, matching IP and username lockouts will appear here for local review and manual unlock.', 'luma-login-limiter'); ?></p>
                        <?php else : ?>
                            <div class="luma-table-wrap">
                                <table class="widefat striped luma-table">
                                    <thead>
                                        <tr>
                                            <th><?php esc_html_e('Gateway', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Scope', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Value', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Reason', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Unlocks in', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Action', 'luma-login-limiter'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($lockouts as $lockout) : ?>
                                            <tr>
                                                <td><?php echo esc_html($lockout['gateway']); ?></td>
                                                <td><?php echo esc_html($lockout['scope']); ?></td>
                                                <td><?php echo esc_html($lockout['value']); ?></td>
                                                <td><?php echo esc_html((string) ($lockout['reason'] ?? 'rate_limited')); ?></td>
                                                <td><?php echo esc_html($this->human_remaining_time((int) $lockout['until'])); ?></td>
                                                <td>
                                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                        <?php wp_nonce_field('luma_login_limiter_unlock'); ?>
                                                        <input type="hidden" name="action" value="luma_login_limiter_unlock" />
                                                        <input type="hidden" name="gateway" value="<?php echo esc_attr((string) $lockout['gateway']); ?>" />
                                                        <input type="hidden" name="scope" value="<?php echo esc_attr((string) $lockout['scope']); ?>" />
                                                        <input type="hidden" name="value" value="<?php echo esc_attr((string) $lockout['value']); ?>" />
                                                        <button type="submit" class="button"><?php esc_html_e('Unlock', 'luma-login-limiter'); ?></button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </section>

                    <section class="luma-card">
                        <div class="luma-card-header">
                            <h2><?php esc_html_e('Recent auth events', 'luma-login-limiter'); ?></h2>
                            <span class="luma-pill"><?php echo esc_html((string) count($logs)); ?></span>
                        </div>
                        <?php if (empty($logs)) : ?>
                            <p class="luma-empty-state"><?php esc_html_e('No events recorded yet. Login attempts, denials, disabled XML-RPC methods, and lockouts will appear here.', 'luma-login-limiter'); ?></p>
                        <?php else : ?>
                            <div class="luma-table-wrap">
                                <table class="widefat striped luma-table">
                                    <thead>
                                        <tr>
                                            <th><?php esc_html_e('Time', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Gateway', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('User', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('IP', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Outcome', 'luma-login-limiter'); ?></th>
                                            <th><?php esc_html_e('Reason', 'luma-login-limiter'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($logs as $log) : ?>
                                            <tr>
                                                <td><?php echo esc_html($this->format_timestamp((string) ($log['timestamp'] ?? ''))); ?></td>
                                                <td><?php echo esc_html((string) ($log['gateway'] ?? '')); ?></td>
                                                <td><?php echo esc_html((string) ($log['username'] ?: '—')); ?></td>
                                                <td><?php echo esc_html((string) ($log['ip'] ?: '—')); ?></td>
                                                <td><span class="luma-status luma-status-<?php echo esc_attr((string) ($log['outcome'] ?? 'info')); ?>"><?php echo esc_html((string) ($log['outcome'] ?? '')); ?></span></td>
                                                <td><?php echo esc_html((string) ($log['reason_code'] ?? '')); ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </section>
                </div>
            </div>
        </div>
        <?php
    }

    private function manage_capability(): string {
        return (string) apply_filters('luma_login_limiter_manage_capability', 'manage_options');
    }

    private function admin_url(string $notice): string {
        return add_query_arg(
            array(
                'page'   => self::PAGE_SLUG,
                'luma_notice' => $notice,
            ),
            admin_url('options-general.php')
        );
    }

    private function render_notice(): void {
        $notice = isset($_GET['luma_notice']) ? sanitize_key((string) wp_unslash($_GET['luma_notice'])) : '';

        if ('saved' === $notice) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Protection settings saved.', 'luma-login-limiter') . '</p></div>';
        }

        if ('unlocked' === $notice) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Selected lockout removed.', 'luma-login-limiter') . '</p></div>';
        }
    }

    private function render_number_field(string $name, string $label, string $description, int $value, int $min): void {
        ?>
        <label class="luma-field">
            <span class="luma-field-label"><?php echo esc_html($label); ?></span>
            <input type="number" min="<?php echo esc_attr((string) $min); ?>" name="<?php echo esc_attr($name); ?>" value="<?php echo esc_attr((string) $value); ?>" class="small-text" />
            <span class="luma-field-help"><?php echo esc_html($description); ?></span>
        </label>
        <?php
    }

    private function render_text_field(string $name, string $label, string $description, string $value): void {
        ?>
        <label class="luma-field">
            <span class="luma-field-label"><?php echo esc_html($label); ?></span>
            <input type="text" name="<?php echo esc_attr($name); ?>" value="<?php echo esc_attr($value); ?>" class="regular-text" />
            <span class="luma-field-help"><?php echo esc_html($description); ?></span>
        </label>
        <?php
    }

    private function render_textarea_field(string $name, string $label, string $description, string $value): void {
        ?>
        <label class="luma-field">
            <span class="luma-field-label"><?php echo esc_html($label); ?></span>
            <textarea name="<?php echo esc_attr($name); ?>" rows="5" class="large-text code"><?php echo esc_textarea($value); ?></textarea>
            <span class="luma-field-help"><?php echo esc_html($description); ?></span>
        </label>
        <?php
    }

    private function render_checkbox_field(string $name, string $label, string $description, bool $checked): void {
        ?>
        <label class="luma-checkbox-field">
            <input type="checkbox" name="<?php echo esc_attr($name); ?>" value="1" <?php checked($checked); ?> />
            <span>
                <strong><?php echo esc_html($label); ?></strong>
                <small><?php echo esc_html($description); ?></small>
            </span>
        </label>
        <?php
    }

    /**
     * @param array<string, string> $options
     */
    private function render_select_field(string $name, string $label, string $description, string $value, array $options): void {
        ?>
        <label class="luma-field">
            <span class="luma-field-label"><?php echo esc_html($label); ?></span>
            <select name="<?php echo esc_attr($name); ?>">
                <?php foreach ($options as $option_value => $option_label) : ?>
                    <option value="<?php echo esc_attr($option_value); ?>" <?php selected($option_value, $value); ?>><?php echo esc_html($option_label); ?></option>
                <?php endforeach; ?>
            </select>
            <span class="luma-field-help"><?php echo esc_html($description); ?></span>
        </label>
        <?php
    }

    private function human_remaining_time(int $until): string {
        $remaining = max(0, $until - time());

        if ($remaining < MINUTE_IN_SECONDS) {
            return __('less than a minute', 'luma-login-limiter');
        }

        return human_time_diff(time(), $until);
    }

    private function format_timestamp(string $timestamp): string {
        $unix = strtotime($timestamp);

        if (false === $unix) {
            return $timestamp;
        }

        return wp_date(get_option('date_format') . ' ' . get_option('time_format'), $unix);
    }

    /**
     * @param array<int, array<string, mixed>> $logs
     * @return array<string, int>
     */
    private function summarize_gateways(array $logs): array {
        $counts = array(
            'wp-login' => 0,
            'paywall'  => 0,
            'xmlrpc'   => 0,
        );

        foreach ($logs as $log) {
            $gateway = (string) ($log['gateway'] ?? '');
            if (isset($counts[$gateway])) {
                $counts[$gateway]++;
            }
        }

        return $counts;
    }

    /**
     * @param array<int, array<string, mixed>> $logs
     */
    private function count_denied_in_last_day(array $logs): int {
        $cutoff = time() - DAY_IN_SECONDS;
        $count  = 0;

        foreach ($logs as $log) {
            $timestamp = strtotime((string) ($log['timestamp'] ?? ''));
            $outcome   = (string) ($log['outcome'] ?? '');

            if (false === $timestamp || $timestamp < $cutoff) {
                continue;
            }

            if (in_array($outcome, array('denied', 'failed', 'locked'), true)) {
                $count++;
            }
        }

        return $count;
    }
}
