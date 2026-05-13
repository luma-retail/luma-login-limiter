<?php

declare(strict_types=1);

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('luma_login_limiter_state');

if (is_multisite()) {
    delete_site_option('luma_login_limiter_settings');

    $site_ids = get_sites(array(
        'fields' => 'ids',
        'number' => 0,
    ));

    foreach ($site_ids as $site_id) {
        switch_to_blog((int) $site_id);
        delete_option('luma_login_limiter_settings');
        delete_option('luma_login_limiter_state');
        restore_current_blog();
    }
} else {
    delete_option('luma_login_limiter_settings');
}
