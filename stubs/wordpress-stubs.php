<?php

declare(strict_types=1);

if (! defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (! defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

if (! defined('XMLRPC_REQUEST')) {
    define('XMLRPC_REQUEST', false);
}

if (! class_exists('WP_Error')) {
    class WP_Error {
        /**
         * @var array<int, string>
         */
        private array $codes;

        public function __construct(string $code = '', string $message = '', $data = null) {
            $this->codes = '' === $code ? array() : array($code);
        }

        /**
         * @return array<int, string>
         */
        public function get_error_codes(): array {
            return $this->codes;
        }
    }
}

if (! class_exists('WP_User')) {
    class WP_User {
        public int $ID = 0;
    }
}

if (! class_exists('IXR_Error')) {
    class IXR_Error {
        public function __construct(int $code, string $message) {
        }
    }
}

if (! function_exists('__')) {
    function __(string $text, string $domain = ''): string {
        return $text;
    }
}

if (! function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = ''): string {
        return $text;
    }
}

if (! function_exists('register_activation_hook')) {
    function register_activation_hook(string $file, callable $callback): void {
    }
}

if (! function_exists('add_action')) {
    function add_action(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): void {
    }
}

if (! function_exists('add_filter')) {
    function add_filter(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): void {
    }
}

if (! function_exists('apply_filters')) {
    function apply_filters(string $hook_name, $value) {
        return $value;
    }
}

if (! function_exists('load_plugin_textdomain')) {
    function load_plugin_textdomain(string $domain, bool $deprecated = false, string $plugin_rel_path = ''): void {
    }
}

if (! function_exists('plugin_basename')) {
    function plugin_basename(string $file): string {
        return basename($file);
    }
}

if (! function_exists('plugins_url')) {
    function plugins_url(string $path = '', string $plugin = ''): string {
        return $path;
    }
}

if (! function_exists('wp_signon')) {
    function wp_signon(array $credentials = array(), bool $secure_cookie = false) {
        return null;
    }
}

if (! function_exists('is_ssl')) {
    function is_ssl(): bool {
        return false;
    }
}

if (! function_exists('get_option')) {
    function get_option(string $option, $default = false) {
        return $default;
    }
}

if (! function_exists('get_site_option')) {
    function get_site_option(string $option, $default = false) {
        return $default;
    }
}

if (! function_exists('add_option')) {
    function add_option(string $option, $value = '', string $deprecated = '', bool $autoload = true): bool {
        return true;
    }
}

if (! function_exists('add_site_option')) {
    function add_site_option(string $option, $value): bool {
        return true;
    }
}

if (! function_exists('update_option')) {
    function update_option(string $option, $value, $autoload = null): bool {
        return true;
    }
}

if (! function_exists('update_site_option')) {
    function update_site_option(string $option, $value): bool {
        return true;
    }
}

if (! function_exists('delete_option')) {
    function delete_option(string $option): bool {
        return true;
    }
}

if (! function_exists('delete_site_option')) {
    function delete_site_option(string $option): bool {
        return true;
    }
}

if (! function_exists('sanitize_user')) {
    function sanitize_user(string $username, bool $strict = false): string {
        return $username;
    }
}

if (! function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string {
        return $str;
    }
}

if (! function_exists('sanitize_key')) {
    function sanitize_key(string $key): string {
        return $key;
    }
}

if (! function_exists('wp_unslash')) {
    function wp_unslash($value) {
        return $value;
    }
}

if (! function_exists('absint')) {
    function absint($maybeint): int {
        return abs((int) $maybeint);
    }
}

if (! function_exists('wp_json_encode')) {
    function wp_json_encode($value, int $flags = 0, int $depth = 512): string|false {
        return json_encode($value, $flags, $depth);
    }
}

if (! function_exists('get_user_by')) {
    function get_user_by(string $field, $value): WP_User|false {
        return false;
    }
}

if (! function_exists('is_email')) {
    function is_email(string $email): string|false {
        return $email;
    }
}

if (! function_exists('user_can')) {
    function user_can($user, string $capability): bool {
        return false;
    }
}

if (! function_exists('current_user_can')) {
    function current_user_can(string $capability): bool {
        return true;
    }
}

if (! function_exists('wp_die')) {
    function wp_die(string $message = ''): void {
        throw new RuntimeException($message);
    }
}

if (! function_exists('check_admin_referer')) {
    function check_admin_referer(string $action = '', string $query_arg = '_wpnonce'): bool {
        return true;
    }
}

if (! function_exists('wp_safe_redirect')) {
    function wp_safe_redirect(string $location, int $status = 302, string $x_redirect_by = 'WordPress'): bool {
        return true;
    }
}

if (! function_exists('admin_url')) {
    function admin_url(string $path = '', string $scheme = 'admin'): string {
        return $path;
    }
}

if (! function_exists('network_admin_url')) {
    function network_admin_url(string $path = '', string $scheme = 'admin'): string {
        return $path;
    }
}

if (! function_exists('add_query_arg')) {
    function add_query_arg(array $args, string $url = ''): string {
        return $url;
    }
}

if (! function_exists('add_options_page')) {
    function add_options_page(string $page_title, string $menu_title, string $capability, string $menu_slug, callable $callback = null): string|false {
        return $menu_slug;
    }
}

if (! function_exists('add_submenu_page')) {
    function add_submenu_page(string $parent_slug, string $page_title, string $menu_title, string $capability, string $menu_slug, callable $callback = null): string|false {
        return $menu_slug;
    }
}

if (! function_exists('add_users_page')) {
    function add_users_page(string $page_title, string $menu_title, string $capability, string $menu_slug, callable $callback = null): string|false {
        return $menu_slug;
    }
}

if (! function_exists('wp_enqueue_style')) {
    function wp_enqueue_style(string $handle, string $src = '', array $deps = array(), $ver = false, string $media = 'all'): void {
    }
}

if (! function_exists('wp_nonce_field')) {
    function wp_nonce_field(string $action = '-1', string $name = '_wpnonce', bool $referer = true, bool $display = true): string {
        return '';
    }
}

if (! function_exists('esc_html_e')) {
    function esc_html_e(string $text, string $domain = ''): void {
        echo $text;
    }
}

if (! function_exists('esc_html')) {
    function esc_html(string $text): string {
        return $text;
    }
}

if (! function_exists('esc_url')) {
    function esc_url(string $url): string {
        return $url;
    }
}

if (! function_exists('esc_attr')) {
    function esc_attr(string $text): string {
        return $text;
    }
}

if (! function_exists('esc_textarea')) {
    function esc_textarea(string $text): string {
        return $text;
    }
}

if (! function_exists('checked')) {
    function checked($checked, $current = true, bool $display = true): string {
        return (string) ($checked === $current ? 'checked' : '');
    }
}

if (! function_exists('selected')) {
    function selected($selected, $current = true, bool $display = true): string {
        return (string) ($selected === $current ? 'selected' : '');
    }
}

if (! function_exists('human_time_diff')) {
    function human_time_diff(int $from, int $to = 0): string {
        return (string) abs($to - $from);
    }
}

if (! function_exists('wp_date')) {
    function wp_date(string $format, ?int $timestamp = null, $timezone = null): string {
        return date($format, $timestamp ?? time());
    }
}

if (! function_exists('is_admin')) {
    function is_admin(): bool {
        return false;
    }
}

if (! function_exists('is_network_admin')) {
    function is_network_admin(): bool {
        return false;
    }
}

if (! function_exists('get_sites')) {
    function get_sites(array $args = array()): array {
        return array();
    }
}

if (! function_exists('is_multisite')) {
    function is_multisite(): bool {
        return false;
    }
}

if (! function_exists('switch_to_blog')) {
    function switch_to_blog(int $new_blog_id, bool $deprecated = true): bool {
        return true;
    }
}

if (! function_exists('restore_current_blog')) {
    function restore_current_blog(): bool {
        return true;
    }
}