<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Plugin {
    private static ?self $instance = null;

    private bool $booted = false;

    private readonly Settings $settings;

    private readonly State_Repository $state;

    private readonly Gateway_Context $context;

    private readonly Ip_Resolver $ip_resolver;

    private readonly Logger_Interface $logger;

    private readonly Rate_Limiter $rate_limiter;

    private readonly Auth_Guard $auth_guard;

    private readonly Xmlrpc_Manager $xmlrpc_manager;

    private readonly Admin_Page $admin_page;

    private function __construct() {
        $this->settings       = new Settings();
        $this->state          = new State_Repository();
        $this->context        = new Gateway_Context();
        $this->ip_resolver    = new Ip_Resolver($this->settings);
        $this->logger         = new Logger($this->settings, $this->state);
        $this->rate_limiter   = new Rate_Limiter($this->settings, $this->state);
        $this->auth_guard     = new Auth_Guard($this->settings, $this->context, $this->ip_resolver, $this->rate_limiter, $this->logger);
        $this->xmlrpc_manager = new Xmlrpc_Manager($this->context, $this->ip_resolver, $this->logger);
        $this->admin_page     = new Admin_Page($this->settings, $this->state, $this->rate_limiter, $this->ip_resolver);
    }

    public static function instance(): self {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function activate(): void {
        $plugin = self::instance();
        $plugin->settings->activate();
        $plugin->state->activate();
        $plugin->state->cleanup($plugin->settings);
    }

    public function boot(): void {
        if ($this->booted) {
            return;
        }

        $this->booted = true;

        load_plugin_textdomain('luma-login-limiter', false, dirname(plugin_basename(__DIR__ . '/../luma-login-limiter.php')) . '/languages');

        $this->settings->activate();
        $this->state->activate();

        add_action('init', array($this, 'cleanup_state'));

        $this->auth_guard->register();
        $this->xmlrpc_manager->register();

        if (is_admin()) {
            $this->admin_page->register();
        }
    }

    public function mark_gateway(string $gateway): void {
        $this->context->mark($gateway);
    }

    public function cleanup_state(): void {
        $this->state->cleanup($this->settings);
    }
}
