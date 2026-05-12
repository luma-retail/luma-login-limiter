# Luma Login Limiter

Luma Login Limiter is a lightweight WordPress plugin for protecting the authentication surfaces that usually matter most: browser login, custom or paywall login, and XML-RPC.

The plugin is intentionally local-first. It stores counters, lockouts, and event history in WordPress options so site owners can inspect what is happening without depending on a cloud security service.

## What it does

- Keeps `wp-login.php`, paywall or frontend login, and XML-RPC isolated from each other.
- Rate-limits by both IP address and username.
- Applies short lockouts first and escalates when repeated lockouts happen inside a configured window.
- Restricts XML-RPC authentication to an explicit allowlist of usernames and or capabilities.
- Requires application passwords for XML-RPC when enabled.
- Disables `system.multicall` and pingback-related XML-RPC methods.
- Provides a styled admin screen with active lockouts, recent auth events, and explicit local unlock actions.
- Falls back to `error_log()` if local log persistence fails.

## Installation

1. Copy the plugin folder into `wp-content/plugins/`.
2. Activate **Luma Login Limiter** in WordPress admin.
3. Open **Settings > Luma Login Limiter**.
4. Configure XML-RPC allowlists, thresholds, and trusted IP handling before exposing the site publicly.

## Custom login and paywall integration

If your site uses a custom login form, mark the request as a paywall login before calling `wp_signon()`.

```php
luma_login_limiter_mark_gateway( 'paywall' );
$user = wp_signon( $credentials );
```

Or use the helper function that wraps that flow for you:

```php
$user = luma_login_limiter_authenticate_paywall_credentials( $username, $password, true );
```

Without that hint, WordPress auth requests outside `wp-login.php` are treated as `paywall` by default.

## XML-RPC behavior

- XML-RPC stays enabled only so required integrations can keep working.
- Authentication is denied unless the username is explicitly allowlisted, or the matched user has one of the explicitly allowlisted capabilities.
- Application-password-only enforcement can be enabled from the admin UI.
- `system.multicall`, `pingback.ping`, and `pingback.extensions.getPingbacks` are blocked.

## Data storage

State is stored in two local options:

- `luma_login_limiter_settings`
- `luma_login_limiter_state`

The state option contains:

- retry counters per gateway, IP, and username
- active lockouts per gateway, IP, and username
- lockout history used for escalation
- recent structured log entries

## Operational guidance

- Leave the trusted IP source at `REMOTE_ADDR` unless you are behind a proxy you control and trust.
- Set an emergency bypass username for one trusted administrator so lockout recovery does not require disabling the plugin.
- Use `debug` log level temporarily during rollout, then move back to `info` or `warning`.
- Review active lockouts and recent events from the plugin settings screen instead of guessing from server logs alone.

## Scope and non-goals

This plugin is not a general security suite. It does not do malware scanning, cloud analytics, geoblocking, or broad firewall behavior.
