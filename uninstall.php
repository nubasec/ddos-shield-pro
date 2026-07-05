<?php
/**
 * Uninstall Nubasec Security Shield.
 *
 * @package NubasecSecurityShield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

$delete_data = (bool) get_option( 'nss_delete_data_on_uninstall', 0 );

if ( $delete_data ) {
    $table_name = $wpdb->prefix . 'nubasec_blocked_ips';
    $wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );

    $options = array(
        'nss_request_limit',
        'nss_block_hours_ddos',
        'nss_login_max_attempts',
        'nss_block_hours_login',
        'nss_log_retention_days',
        'nss_alert_email',
        'nss_whitelist',
        'nss_trusted_proxies',
        'nss_enable_trusted_proxy_headers',
        'nss_enable_geo_lookup',
        'nss_alert_rate_limit_minutes',
        'nss_exclude_admins',
        'nss_brand_logo_url',
        'nss_brand_color_primary',
        'nss_brand_color_secondary',
        'nss_delete_data_on_uninstall',
        'nss_db_version',
    );

    foreach ( $options as $option ) {
        delete_option( $option );
    }
}

wp_clear_scheduled_hook( 'nubasec_security_shield_daily_purge' );
