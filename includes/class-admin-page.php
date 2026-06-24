<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Admin_Page {
    private const PAGE_SLUG = 'luma-login-limiter';
    private const USERS_PAGE_SLUG = 'luma-login-limiter-activity';

    public function __construct(
        private readonly Settings $settings,
        private readonly State_Repository $state,
        private readonly Rate_Limiter $rate_limiter,
        private readonly Ip_Resolver $ip_resolver
    ) {
    }

    public function register(): void {
        add_action('admin_menu', array($this, 'register_site_menu'));
        add_action('network_admin_menu', array($this, 'register_network_menu'));
        add_action('admin_post_luma_login_limiter_save_settings', array($this, 'handle_save_settings'));
        add_action('admin_post_luma_login_limiter_unlock', array($this, 'handle_unlock'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    public function register_site_menu(): void {
        if (! is_multisite()) {
            add_options_page(
                __('Luma Login Limiter', 'luma-login-limiter'),
                __('Luma Login Limiter', 'luma-login-limiter'),
                $this->settings_manage_capability(),
                self::PAGE_SLUG,
                array($this, 'render_settings_page')
            );
        }

        add_users_page(
            __('Login Lockouts & Log', 'luma-login-limiter'),
            __('Login lockouts', 'luma-login-limiter'),
            $this->activity_manage_capability(),
            self::USERS_PAGE_SLUG,
            array($this, 'render_activity_page')
        );
    }

    public function register_network_menu(): void {
        if (! is_multisite()) {
            return;
        }

        add_submenu_page(
            'settings.php',
            __('Luma Login Limiter', 'luma-login-limiter'),
            __('Luma Login Limiter', 'luma-login-limiter'),
            $this->settings_manage_capability(),
            self::PAGE_SLUG,
            array($this, 'render_settings_page')
        );
    }

    public function enqueue_assets(string $hook): void {
        $allowed_hooks = array(
            'settings_page_' . self::PAGE_SLUG,
            'users_page_' . self::USERS_PAGE_SLUG,
        );

        if (! in_array($hook, $allowed_hooks, true)) {
            return;
        }

        wp_enqueue_style(
            'luma-login-limiter-admin',
            plugins_url('assets/admin.css', dirname(__DIR__) . '/luma-login-limiter.php'),
            array(),
            '0.2.1'
        );
    }

    public function handle_save_settings(): void {
        if (! current_user_can($this->settings_manage_capability())) {
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
        if (! current_user_can($this->activity_manage_capability())) {
            wp_die(esc_html__('You do not have permission to unlock requests.', 'luma-login-limiter'));
        }

        check_admin_referer('luma_login_limiter_unlock');

        $gateway = isset($_POST['gateway']) ? sanitize_text_field(wp_unslash((string) $_POST['gateway'])) : '';
        $scope   = isset($_POST['scope']) ? sanitize_text_field(wp_unslash((string) $_POST['scope'])) : '';
        $value   = isset($_POST['value']) ? sanitize_text_field(wp_unslash((string) $_POST['value'])) : '';

        if ('' !== $gateway && '' !== $scope && '' !== $value) {
            $this->unlock_matching_lockouts($gateway, $scope, $value);
        }

        wp_safe_redirect($this->users_admin_url('unlocked'));
        exit;
    }

    public function render_settings_page(): void {
        if (! current_user_can($this->settings_manage_capability())) {
            wp_die(esc_html__('You do not have permission to view login protection settings.', 'luma-login-limiter'));
        }

        $this->state->cleanup($this->settings);

        $settings        = $this->settings->all();
        $trusted_headers = $this->ip_resolver->supported_headers();
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
            <div class="luma-layout-grid">
                <section class="luma-card luma-card-form luma-card-full">
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
            </div>
        </div>
        <?php
    }

    public function render_activity_page(): void {
        if (! current_user_can($this->activity_manage_capability())) {
            wp_die(esc_html__('You do not have permission to view login protection activity.', 'luma-login-limiter'));
        }

        $this->state->cleanup($this->settings);

        $settings         = $this->settings->all();
        $lockouts         = $this->rate_limiter->active_lockouts();
        $all_logs         = $this->state->logs((int) $settings['max_log_entries']);
        $logs_per_page    = 25;
        $current_log_page = max(1, absint($_GET['luma_log_page'] ?? 1));
        $total_logs       = count($all_logs);
        $total_log_pages  = max(1, (int) ceil($total_logs / $logs_per_page));

        if ($current_log_page > $total_log_pages) {
            $current_log_page = $total_log_pages;
        }

        $logs_offset     = ($current_log_page - 1) * $logs_per_page;
        $logs            = array_slice($all_logs, $logs_offset, $logs_per_page);
        $trusted_headers = $this->ip_resolver->supported_headers();
        $failed_total    = $this->state->outcome_total('failed');
        $failed_last_day = $this->count_outcomes_in_last_day($all_logs, array('failed'));
        $locked_last_day = $this->count_outcomes_in_last_day($all_logs, array('locked'));
        $denied_last_day = $this->count_denied_in_last_day($all_logs);
        $gateway_counts  = $this->summarize_gateways($all_logs);
        ?>
        <div class="wrap luma-login-limiter-admin">
            <div class="luma-hero">
                <div>
                    <p class="luma-kicker"><?php esc_html_e('Authentication hardening', 'luma-login-limiter'); ?></p>
                    <h1><?php esc_html_e('Login Lockouts & Log', 'luma-login-limiter'); ?></h1>
                    <p class="luma-intro"><?php esc_html_e('Review current lockouts, recent auth events, and gateway activity.', 'luma-login-limiter'); ?></p>
                </div>
                <div class="luma-hero-badges">
                    <span class="luma-badge"><?php esc_html_e('Local audit trail', 'luma-login-limiter'); ?></span>
                    <span class="luma-badge"><?php esc_html_e('Manual unlock controls', 'luma-login-limiter'); ?></span>
                    <span class="luma-badge"><?php esc_html_e('Gateway visibility', 'luma-login-limiter'); ?></span>
                </div>
            </div>

            <?php $this->render_notice(); ?>

            <div class="luma-metric-grid">
                <section class="luma-card luma-card-metric">
                    <dt><?php esc_html_e('Active lockouts', 'luma-login-limiter'); ?></dt>
                    <dd><?php echo esc_html((string) count($lockouts)); ?></dd>
                </section>

                <section class="luma-card luma-card-metric">
                    <dt><?php esc_html_e('Total failed login attempts', 'luma-login-limiter'); ?></dt>
                    <dd><?php echo esc_html((string) $failed_total); ?></dd>
                </section>

                <section class="luma-card luma-card-metric">
                    <dt><?php esc_html_e('Failed logins in 24h', 'luma-login-limiter'); ?></dt>
                    <dd><?php echo esc_html((string) $failed_last_day); ?></dd>
                </section>

                <section class="luma-card luma-card-metric">
                    <dt><?php esc_html_e('Locked in 24h', 'luma-login-limiter'); ?></dt>
                    <dd><?php echo esc_html((string) $locked_last_day); ?></dd>
                </section>

                <section class="luma-card luma-card-metric">
                    <dt><?php esc_html_e('Denied or locked in 24h', 'luma-login-limiter'); ?></dt>
                    <dd><?php echo esc_html((string) $denied_last_day); ?></dd>
                </section>
            </div>

            <div class="luma-summary-grid">
                <section class="luma-card">
                    <h2><?php esc_html_e('Current configuration', 'luma-login-limiter'); ?></h2>
                    <dl class="luma-stat-list">
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
            </div>

            <section class="luma-card luma-card-full">
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
                                    <th><?php esc_html_e('Username', 'luma-login-limiter'); ?></th>
                                    <th><?php esc_html_e('IP', 'luma-login-limiter'); ?></th>
                                    <th><?php esc_html_e('Reason', 'luma-login-limiter'); ?></th>
                                    <th><?php esc_html_e('Unlocks in', 'luma-login-limiter'); ?></th>
                                    <th><?php esc_html_e('Actions', 'luma-login-limiter'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($lockouts as $lockout) : ?>
                                    <?php $lockout_username = (string) ($lockout['username'] ?? ''); ?>
                                    <?php $lockout_ip = (string) ($lockout['ip'] ?? ''); ?>
                                    <tr>
                                        <td><?php echo esc_html($lockout['gateway']); ?></td>
                                        <td><?php echo esc_html($lockout['scope']); ?></td>
                                        <td><?php echo esc_html($lockout['value']); ?></td>
                                        <td><?php echo esc_html($lockout_username ?: '—'); ?></td>
                                        <td><?php echo esc_html($lockout_ip ?: '—'); ?></td>
                                        <td><?php echo esc_html((string) ($lockout['reason'] ?? 'rate_limited')); ?></td>
                                        <td><?php echo esc_html($this->human_remaining_time((int) $lockout['until'])); ?></td>
                                        <td>
                                            <div class="luma-lockout-actions">
                                                <?php if ('username' === (string) $lockout['scope'] && '' !== $lockout_username) : ?>
                                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                        <?php wp_nonce_field('luma_login_limiter_unlock'); ?>
                                                        <input type="hidden" name="action" value="luma_login_limiter_unlock" />
                                                        <input type="hidden" name="gateway" value="<?php echo esc_attr((string) $lockout['gateway']); ?>" />
                                                        <input type="hidden" name="scope" value="username" />
                                                        <input type="hidden" name="value" value="<?php echo esc_attr($lockout_username); ?>" />
                                                        <button type="submit" class="button"><?php esc_html_e('Unlock user', 'luma-login-limiter'); ?></button>
                                                    </form>
                                                <?php endif; ?>
                                                <?php if ('ip' === (string) $lockout['scope'] && '' !== $lockout_ip) : ?>
                                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                        <?php wp_nonce_field('luma_login_limiter_unlock'); ?>
                                                        <input type="hidden" name="action" value="luma_login_limiter_unlock" />
                                                        <input type="hidden" name="gateway" value="<?php echo esc_attr((string) $lockout['gateway']); ?>" />
                                                        <input type="hidden" name="scope" value="ip" />
                                                        <input type="hidden" name="value" value="<?php echo esc_attr($lockout_ip); ?>" />
                                                        <button type="submit" class="button"><?php esc_html_e('Unlock IP', 'luma-login-limiter'); ?></button>
                                                    </form>
                                                <?php endif; ?>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </section>

            <div class="luma-layout-grid">
                <section class="luma-card luma-card-log luma-card-full">
                    <div class="luma-card-header">
                        <h2><?php esc_html_e('Recent auth events', 'luma-login-limiter'); ?></h2>
                        <span class="luma-pill"><?php echo esc_html((string) $total_logs); ?></span>
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
                                            <td><span class="luma-status luma-status-<?php echo esc_attr((string) ($log['outcome'] ?? 'info')); ?>"><?php echo esc_html($this->outcome_label((string) ($log['outcome'] ?? ''))); ?></span></td>
                                            <td><?php echo esc_html((string) ($log['reason_code'] ?? '')); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php if ($total_log_pages > 1) : ?>
                            <div class="tablenav bottom">
                                <div class="tablenav-pages">
                                    <?php
                                    $base_url = add_query_arg(
                                        array(
                                            'page'          => self::USERS_PAGE_SLUG,
                                            'luma_log_page' => '%#%',
                                        ),
                                        admin_url('users.php')
                                    );

                                    echo wp_kses_post(
                                        paginate_links(
                                            array(
                                                'base'      => $base_url,
                                                'format'    => '',
                                                'current'   => $current_log_page,
                                                'total'     => $total_log_pages,
                                                'prev_text' => __('&laquo; Previous', 'luma-login-limiter'),
                                                'next_text' => __('Next &raquo;', 'luma-login-limiter'),
                                                'type'      => 'plain',
                                            )
                                        )
                                    );
                                    ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </section>
            </div>
        </div>
        <?php
    }

    private function activity_manage_capability(): string {
        return (string) apply_filters('luma_login_limiter_manage_capability', 'manage_options');
    }

    private function settings_manage_capability(): string {
        if (is_multisite()) {
            return (string) apply_filters('luma_login_limiter_network_manage_capability', 'manage_network_options');
        }

        return $this->activity_manage_capability();
    }

    private function unlock_matching_lockouts(string $gateway, string $scope, string $value): void {
        $this->rate_limiter->unlock($gateway, $scope, $value);
    }

    private function admin_url(string $notice): string {
        $base_url = is_multisite()
            ? network_admin_url('settings.php')
            : admin_url('options-general.php');

        return add_query_arg(
            array(
                'page'        => self::PAGE_SLUG,
                'luma_notice' => $notice,
            ),
            $base_url
        );
    }

    private function users_admin_url(string $notice): string {
        return add_query_arg(
            array(
                'page'        => self::USERS_PAGE_SLUG,
                'luma_notice' => $notice,
            ),
            admin_url('users.php')
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

    private function outcome_label(string $outcome): string {
        switch ($outcome) {
            case 'failed':
                return __('Failed', 'luma-login-limiter');

            case 'locked':
                return __('Locked', 'luma-login-limiter');

            case 'denied':
                return __('Denied', 'luma-login-limiter');

            case 'success':
                return __('Success', 'luma-login-limiter');
        }

        if ('' === $outcome) {
            return '';
        }

        return ucwords(str_replace('_', ' ', $outcome));
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
        return $this->count_outcomes_in_last_day($logs, array('denied', 'locked'));
    }

    /**
     * @param array<int, array<string, mixed>> $logs
     * @param array<int, string> $outcomes
     */
    private function count_outcomes_in_last_day(array $logs, array $outcomes): int {
        $cutoff = time() - DAY_IN_SECONDS;
        $count  = 0;

        foreach ($logs as $log) {
            $timestamp = strtotime((string) ($log['timestamp'] ?? ''));
            $outcome   = (string) ($log['outcome'] ?? '');

            if (false === $timestamp || $timestamp < $cutoff) {
                continue;
            }

            if (in_array($outcome, $outcomes, true)) {
                $count++;
            }
        }

        return $count;
    }
}
