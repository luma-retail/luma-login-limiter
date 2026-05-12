=== Luma Login Limiter ===
Contributors: luma
Tags: security, login, xml-rpc, rate-limit, authentication
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect browser login, paywall login, and XML-RPC separately with local rate limiting, XML-RPC allowlists, and readable lockout visibility.

== Description ==

Luma Login Limiter is a focused authentication hardening plugin for site owners who want a clear, local-first alternative to heavyweight security suites.

It protects three different login surfaces independently:

* `wp-login.php`
* custom or paywall login flows
* `xmlrpc.php`

Each gateway keeps separate counters, separate lockouts, and separate event logs so XML-RPC bot traffic does not create confusing browser login behavior.

Key features:

* XML-RPC authentication allowlist by username and or explicit capability
* application-password-only mode for XML-RPC
* `system.multicall` and pingback methods disabled
* rate limiting by both IP and username
* escalating lockouts with configurable timing
* recent auth events stored locally in WordPress
* active lockout screen with manual unlock buttons
* trusted IP header control for proxy-aware setups
* emergency bypass username for one trusted admin account

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate the plugin through the `Plugins` screen in WordPress.
3. Visit `Settings > Luma Login Limiter`.
4. Configure XML-RPC allowlists, thresholds, and trusted IP handling.

== Frequently Asked Questions ==

= Will this disable XML-RPC entirely? =

No. The plugin keeps XML-RPC available, but authentication is restricted to explicitly approved users and can be limited to application passwords only.

= How do I mark a frontend login as paywall traffic? =

Call `luma_login_limiter_mark_gateway( 'paywall' );` before `wp_signon()`, or use `luma_login_limiter_authenticate_paywall_credentials()`.

= Where is the plugin state stored? =

The plugin stores its settings and local state in the WordPress options table using `luma_login_limiter_settings` and `luma_login_limiter_state`.

= Does this bypass super admins automatically on multisite? =

No. Super admins are not automatically bypassed. If you want a recovery path, configure the emergency bypass username explicitly.

== Changelog ==

= 0.1.0 =

* Initial public release.
* Separate gateway-aware protection for browser, paywall, and XML-RPC login flows.
* XML-RPC allowlist and application password enforcement.
* Local lockout visibility and recent event log.
