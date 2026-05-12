# Luma Login Limiter


This note captures a proposed lightweight authentication hardening plugin. The goal is to protect the actual login surfaces we use without adopting a broad, cloud-driven security product. The need came after seeing the LLAR plugin (Limit Login Attempts Reloaded) more or less demanding cloud enrollment to be effective, and the XML-RPC gateway being left wide open with no effective protection. Plus a lot of unnecessary features. So we want to create a Wordpress Plugin and publish it as open source. 

## Goals

- Protect browser login, paywall login, and XML-RPC as separate gateways.
- Allow XML-RPC only for a very small set of users.
- Keep the solution understandable, local, and easy to operate.
- Provide clear logging and lockout visibility.
- Work well on both single-site and multisite, without requiring super admin bypasses.
- Be extensible for future features without overcomplicating the initial version.
- Have as small performance impact as possible.

## Non-Goals

- Not a general security suite.
- No malware scanning.
- No cloud dependency for core protection.
- No large analytics/dashboard scope in v1.
- No country blocking in v1.

## Core Rules

### Scope

1. Protect only authentication surfaces.
2. Keep browser login, paywall login, and XML-RPC separate in both logic and logs.
3. Default to safe behavior with minimal settings.
4. Prefer server-side protection over JavaScript-dependent controls.
5. Include README.md with clear documentation and operational guidance, and README.txt with a text more directed towards site admins.

### XML-RPC

1. Keep `xmlrpc.php` enabled only because some integrations require it.
2. Deny XML-RPC authentication for all users except an explicit allowlist.
3. For allowed XML-RPC users, require application passwords only.
4. Disable dangerous or unnecessary XML-RPC methods such as `system.multicall`.
5. Disable pingbacks unless there is a verified business need.
6. Log denied XML-RPC attempts with gateway, username, IP, and reason.

### Rate Limiting

1. Rate-limit by both IP and username, not only IP.
2. Keep separate counters per gateway: `wp-login`, paywall login, and XML-RPC.
3. Failed XML-RPC attempts must not lock out normal browser login for the same user.
4. Use short lockouts first, then escalate if repeated within a time window.
5. Expire counters automatically after a configurable reset period.
6. Store lockout state in a simple, inspectable local format.

### User Rules

1. XML-RPC access should be granted by explicit user allowlist or capability.
2. Do not infer XML-RPC access from broad roles unless that is explicitly intended.
3. Super admins should not automatically bypass all controls unless explicitly configured.
4. Support a clear emergency bypass path for one trusted admin account.

### Logging

1. One logger interface per plugin.
2. Fallback to `error_log` if the shared logger service is unavailable.
3. Support per-plugin threshold: `error`, `warning`, `info`, `debug`.
4. Log structured events, not only freeform strings.
5. Every auth log should include gateway, username if present, IP, outcome, and reason code.
6. Never log secrets, passwords, tokens, or full application passwords.

### Admin UX

1. Show active lockouts clearly.
2. Make unlock actions explicit and local.
3. Show why a request was denied: not allowlisted, bad app password, rate limit, disabled method.
4. Keep settings small and understandable.
5. Avoid hidden failover modes.

### Operational Safety

1. Be explicit about trusted IP headers; default to `REMOTE_ADDR`.
2. Never let XML-RPC bot traffic create invisible lockouts.
3. Keep local state separate from optional external integrations.
4. Make lockout and retry state easy to inspect during debugging.

## Recommended v1 Scope

Keep the first version narrow:

1. XML-RPC allowlist by username or capability.
2. Application-password-only enforcement for XML-RPC.
3. Disable `system.multicall` and pingbacks.
4. Lightweight gateway-aware rate limiting.
5. Clear local lockout UI and logs.

## Suggested Design Shape

### Gateways

- Browser login via `wp-login.php`
- Paywall/custom frontend login
- XML-RPC authentication

Each gateway should:

- have separate counters
- emit separate logs
- have separate denial reasons

### Data Model

Store local state in a simple format that can be inspected from WordPress admin or directly in options:

- retries by gateway + IP + username
- active lockouts by gateway + IP + username
- last failure reason
- last activity timestamp

### Logging Model

Event fields should include:

- timestamp
- plugin/component
- gateway
- username if present
- IP address
- outcome: success, failed, denied, locked
- reason code
- optional context such as request path or method name

### Settings

Keep the settings page small:

- XML-RPC enabled/managed notice
- XML-RPC allowlist
- whether XML-RPC requires application passwords
- rate limit thresholds per gateway
- lockout duration and escalation rules
- log level threshold
- trusted IP origin configuration

## Notes From Current Incidents

- Normal users were able to log in once LLAR-related lockout confusion was removed from the immediate path.
- XML-RPC traffic showed repeated failed attempts with invalid application passwords, consistent with bot probing.
- Existing logging is noisy because successful auth logging currently happens too early in the auth lifecycle.
- Existing logging across plugins should later be normalized behind plugin-local logger wrappers with shared behavior.

## Deferred Work

Not part of the first pass:

- shared logging infrastructure across all plugins
- advanced analytics
- external service synchronization
- country rules
- broad firewall features
