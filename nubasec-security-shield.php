<?php
/**
 * Plugin Name: Nubasec Security Shield
 * Plugin URI: https://nubasec.com/
 * Description: Protección básica contra abuso de solicitudes, intentos de fuerza bruta, bloqueo de IPs, alertas administrativas y monitoreo de eventos de seguridad.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Nubasec
 * Author URI: https://nubasec.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: nubasec-security-shield
 * Domain Path: /languages
 *
 * @package NubasecSecurityShield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'NUBASEC_SECURITY_SHIELD_VERSION', '1.0.0' );
define( 'NUBASEC_SECURITY_SHIELD_FILE', __FILE__ );
define( 'NUBASEC_SECURITY_SHIELD_DIR', plugin_dir_path( __FILE__ ) );
define( 'NUBASEC_SECURITY_SHIELD_URL', plugin_dir_url( __FILE__ ) );

final class Nubasec_Security_Shield {
    const DB_VERSION = '1.0.0';
    const CRON_HOOK = 'nubasec_security_shield_daily_purge';

    private static $instance = null;
    private $table_name;
    private $request_limit;
    private $time_window = 60;

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        global $wpdb;
        $this->table_name    = $wpdb->prefix . 'nubasec_blocked_ips';
        $this->request_limit = absint( get_option( 'nss_request_limit', 60 ) );

        add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
        add_action( 'plugins_loaded', array( $this, 'maybe_update_database' ) );
        add_action( self::CRON_HOOK, array( $this, 'cleanup_old_logs' ) );

        add_action( 'init', array( $this, 'firewall_monitor' ), 1 );
        add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );

        add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_init', array( $this, 'handle_csv_export' ) );
        add_action( 'admin_init', array( $this, 'handle_admin_actions' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
        add_filter( 'admin_body_class', array( $this, 'admin_body_class' ) );
    }

    public static function activate() {
        $plugin = self::instance();
        $plugin->install_database();
        $plugin->add_default_options();

        if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
        }
    }

    public static function deactivate() {
        wp_clear_scheduled_hook( self::CRON_HOOK );
    }

    public function load_textdomain() {
        load_plugin_textdomain(
            'nubasec-security-shield',
            false,
            dirname( plugin_basename( __FILE__ ) ) . '/languages'
        );
    }

    public function add_default_options() {
        $defaults = array(
            'nss_request_limit'               => 60,
            'nss_block_hours_ddos'            => 24,
            'nss_login_max_attempts'          => 5,
            'nss_block_hours_login'           => 24,
            'nss_log_retention_days'          => 30,
            'nss_alert_email'                 => get_option( 'admin_email' ),
            'nss_whitelist'                   => '',
            'nss_trusted_proxies'             => '',
            'nss_enable_trusted_proxy_headers'=> 0,
            'nss_enable_geo_lookup'           => 0,
            'nss_alert_rate_limit_minutes'    => 60,
            'nss_exclude_admins'              => 1,
            'nss_brand_logo_url'              => '',
            'nss_brand_color_primary'         => '#00c7ee',
            'nss_brand_color_secondary'       => '#061a33',
            'nss_delete_data_on_uninstall'    => 0,
        );

        foreach ( $defaults as $key => $value ) {
            if ( false === get_option( $key, false ) ) {
                add_option( $key, $value );
            }
        }
    }

    public function install_database() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();
        $table_name      = $this->table_name;

        $sql = "CREATE TABLE {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            country_code varchar(10) DEFAULT 'XX',
            country_name varchar(100) DEFAULT 'Unknown',
            user_agent varchar(255) DEFAULT '',
            request_uri varchar(255) DEFAULT '',
            reason varchar(80) DEFAULT 'Rate Limit',
            blocked_at datetime NOT NULL,
            expires_at datetime DEFAULT NULL,
            request_count int(11) DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY ip_address (ip_address),
            KEY reason (reason),
            KEY blocked_at (blocked_at),
            KEY expires_at (expires_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        update_option( 'nss_db_version', self::DB_VERSION );
    }

    public function maybe_update_database() {
        if ( get_option( 'nss_db_version' ) !== self::DB_VERSION ) {
            $this->install_database();
        }
    }

    public function cleanup_old_logs() {
        global $wpdb;

        $retention_days = max( 1, absint( get_option( 'nss_log_retention_days', 30 ) ) );
        $threshold      = gmdate( 'Y-m-d H:i:s', time() - ( $retention_days * DAY_IN_SECONDS ) );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table_name} WHERE blocked_at < %s",
                get_date_from_gmt( $threshold )
            )
        );
    }

    public function register_settings() {
        register_setting( 'nss_settings_group', 'nss_request_limit', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 60 ) );
        register_setting( 'nss_settings_group', 'nss_block_hours_ddos', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 24 ) );
        register_setting( 'nss_settings_group', 'nss_login_max_attempts', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 5 ) );
        register_setting( 'nss_settings_group', 'nss_block_hours_login', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 24 ) );
        register_setting( 'nss_settings_group', 'nss_log_retention_days', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 30 ) );
        register_setting( 'nss_settings_group', 'nss_alert_rate_limit_minutes', array( 'type' => 'integer', 'sanitize_callback' => array( $this, 'sanitize_positive_int' ), 'default' => 60 ) );
        register_setting( 'nss_settings_group', 'nss_alert_email', array( 'type' => 'string', 'sanitize_callback' => 'sanitize_email', 'default' => '' ) );
        register_setting( 'nss_settings_group', 'nss_whitelist', array( 'type' => 'string', 'sanitize_callback' => array( $this, 'sanitize_ip_list' ), 'default' => '' ) );
        register_setting( 'nss_settings_group', 'nss_trusted_proxies', array( 'type' => 'string', 'sanitize_callback' => array( $this, 'sanitize_ip_list' ), 'default' => '' ) );
        register_setting( 'nss_settings_group', 'nss_enable_trusted_proxy_headers', array( 'type' => 'boolean', 'sanitize_callback' => array( $this, 'sanitize_checkbox' ), 'default' => 0 ) );
        register_setting( 'nss_settings_group', 'nss_enable_geo_lookup', array( 'type' => 'boolean', 'sanitize_callback' => array( $this, 'sanitize_checkbox' ), 'default' => 0 ) );
        register_setting( 'nss_settings_group', 'nss_exclude_admins', array( 'type' => 'boolean', 'sanitize_callback' => array( $this, 'sanitize_checkbox' ), 'default' => 1 ) );
        register_setting( 'nss_settings_group', 'nss_delete_data_on_uninstall', array( 'type' => 'boolean', 'sanitize_callback' => array( $this, 'sanitize_checkbox' ), 'default' => 0 ) );
        register_setting( 'nss_settings_group', 'nss_brand_logo_url', array( 'type' => 'string', 'sanitize_callback' => 'esc_url_raw', 'default' => '' ) );
        register_setting( 'nss_settings_group', 'nss_brand_color_primary', array( 'type' => 'string', 'sanitize_callback' => 'sanitize_hex_color', 'default' => '#00c7ee' ) );
        register_setting( 'nss_settings_group', 'nss_brand_color_secondary', array( 'type' => 'string', 'sanitize_callback' => 'sanitize_hex_color', 'default' => '#061a33' ) );
    }

    public function sanitize_positive_int( $value ) {
        $value = absint( $value );
        return max( 1, $value );
    }

    public function sanitize_checkbox( $value ) {
        return empty( $value ) ? 0 : 1;
    }

    public function sanitize_ip_list( $value ) {
        $value = is_string( $value ) ? wp_unslash( $value ) : '';
        $lines = preg_split( '/\r\n|\r|\n/', $value );
        $clean = array();

        foreach ( $lines as $line ) {
            $line = trim( sanitize_text_field( $line ) );
            if ( '' === $line ) {
                continue;
            }

            if ( $this->is_valid_ip_or_cidr( $line ) ) {
                $clean[] = $line;
            }
        }

        return implode( "\n", array_unique( $clean ) );
    }

    private function is_valid_ip_or_cidr( $value ) {
        if ( false === strpos( $value, '/' ) ) {
            return (bool) filter_var( $value, FILTER_VALIDATE_IP );
        }

        list( $ip, $mask ) = array_pad( explode( '/', $value, 2 ), 2, null );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return false;
        }

        return is_numeric( $mask ) && (int) $mask >= 0 && (int) $mask <= 32;
    }

    private function ip_in_list( $ip, $list ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || empty( $list ) ) {
            return false;
        }

        $items = preg_split( '/\r\n|\r|\n/', (string) $list );
        foreach ( $items as $item ) {
            $item = trim( $item );
            if ( '' === $item ) {
                continue;
            }

            if ( false === strpos( $item, '/' ) ) {
                if ( hash_equals( $item, $ip ) ) {
                    return true;
                }
                continue;
            }

            if ( $this->ipv4_in_cidr( $ip, $item ) ) {
                return true;
            }
        }

        return false;
    }

    private function ipv4_in_cidr( $ip, $cidr ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return false;
        }

        list( $subnet, $mask ) = array_pad( explode( '/', $cidr, 2 ), 2, null );
        if ( ! filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || ! is_numeric( $mask ) ) {
            return false;
        }

        $mask = (int) $mask;
        if ( $mask < 0 || $mask > 32 ) {
            return false;
        }

        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        $mask_long   = -1 << ( 32 - $mask );
        $subnet_long = $subnet_long & $mask_long;

        return ( $ip_long & $mask_long ) === $subnet_long;
    }

    private function get_request_ip() {
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

        if ( ! filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
            return '0.0.0.0';
        }

        $trust_proxy_headers = (bool) get_option( 'nss_enable_trusted_proxy_headers', 0 );
        $trusted_proxies     = get_option( 'nss_trusted_proxies', '' );

        if ( $trust_proxy_headers && $this->ip_in_list( $remote_addr, $trusted_proxies ) ) {
            $forwarded = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';
            if ( '' !== $forwarded ) {
                $parts = array_map( 'trim', explode( ',', $forwarded ) );
                $candidate = reset( $parts );
                if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                    return $candidate;
                }
            }
        }

        return $remote_addr;
    }

    private function get_request_uri() {
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        return substr( $uri, 0, 250 );
    }

    private function get_user_agent() {
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown';
        return substr( $ua, 0, 250 );
    }

    public function firewall_monitor() {
        if ( wp_doing_cron() || wp_doing_ajax() ) {
            return;
        }

        if ( (bool) get_option( 'nss_exclude_admins', 1 ) && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            return;
        }

        $ip = $this->get_request_ip();
        if ( '0.0.0.0' === $ip || $this->ip_in_list( $ip, get_option( 'nss_whitelist', '' ) ) ) {
            return;
        }

        global $wpdb;
        $block = $wpdb->get_row(
            $wpdb->prepare( "SELECT * FROM {$this->table_name} WHERE ip_address = %s", $ip )
        );

        if ( $block ) {
            if ( ! empty( $block->expires_at ) && strtotime( $block->expires_at ) <= current_time( 'timestamp' ) ) {
                $wpdb->delete( $this->table_name, array( 'id' => absint( $block->id ) ), array( '%d' ) );
                return;
            }

            $this->render_blocked_response( $block->reason );
        }

        $transient_key = 'nss_rate_' . md5( $ip );
        $count         = (int) get_transient( $transient_key );
        $count++;
        set_transient( $transient_key, $count, $this->time_window );

        if ( $count > $this->request_limit ) {
            $this->block_ip( $ip, $count, 'Rate Limit' );
            $this->render_blocked_response( 'Rate Limit' );
        }
    }

    public function handle_failed_login( $username ) {
        $ip = $this->get_request_ip();
        if ( '0.0.0.0' === $ip || $this->ip_in_list( $ip, get_option( 'nss_whitelist', '' ) ) ) {
            return;
        }

        $transient_key = 'nss_login_fail_' . md5( $ip );
        $attempts      = (int) get_transient( $transient_key );
        $attempts++;
        set_transient( $transient_key, $attempts, 20 * MINUTE_IN_SECONDS );

        $limit = absint( get_option( 'nss_login_max_attempts', 5 ) );
        if ( $attempts >= $limit ) {
            $this->block_ip( $ip, $attempts, 'Brute Force Login' );
        }
    }

    private function render_blocked_response( $reason ) {
        wp_die(
            esc_html__( 'Tu IP ha sido bloqueada temporalmente por actividad sospechosa. Si consideras que esto es un error, contacta al administrador del sitio.', 'nubasec-security-shield' ),
            esc_html__( 'Acceso bloqueado', 'nubasec-security-shield' ),
            array(
                'response' => 403,
                'back_link'=> false,
            )
        );
    }

    private function block_ip( $ip, $count, $reason = 'Rate Limit' ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return;
        }

        global $wpdb;

        $existing = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$this->table_name} WHERE ip_address = %s", $ip ) );
        if ( $existing ) {
            return;
        }

        $hours = 'Brute Force Login' === $reason ? absint( get_option( 'nss_block_hours_login', 24 ) ) : absint( get_option( 'nss_block_hours_ddos', 24 ) );
        $expires_at = date_i18n( 'Y-m-d H:i:s', current_time( 'timestamp' ) + ( max( 1, $hours ) * HOUR_IN_SECONDS ) );

        $geo = $this->lookup_geo( $ip );
        $ua  = $this->get_user_agent();

        $inserted = $wpdb->insert(
            $this->table_name,
            array(
                'ip_address'    => $ip,
                'country_code'  => $geo['country_code'],
                'country_name'  => $geo['country_name'],
                'user_agent'    => $ua,
                'request_uri'   => $this->get_request_uri(),
                'reason'        => sanitize_text_field( $reason ),
                'blocked_at'    => current_time( 'mysql' ),
                'expires_at'    => $expires_at,
                'request_count' => absint( $count ),
            ),
            array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d' )
        );

        if ( false !== $inserted ) {
            $this->send_html_alert( $ip, $count, $geo['country_name'], $ua, $reason, $expires_at );
        }
    }

    private function lookup_geo( $ip ) {
        $geo = array(
            'country_code' => 'XX',
            'country_name' => __( 'Unknown', 'nubasec-security-shield' ),
        );

        if ( ! (bool) get_option( 'nss_enable_geo_lookup', 0 ) ) {
            return $geo;
        }

        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return $geo;
        }

        $url      = 'https://ipapi.co/' . rawurlencode( $ip ) . '/json/';
        $response = wp_remote_get(
            $url,
            array(
                'timeout' => 3,
                'headers' => array(
                    'Accept' => 'application/json',
                ),
            )
        );

        if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
            return $geo;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( is_array( $body ) ) {
            if ( ! empty( $body['country_code'] ) ) {
                $geo['country_code'] = sanitize_text_field( $body['country_code'] );
            }
            if ( ! empty( $body['country_name'] ) ) {
                $geo['country_name'] = sanitize_text_field( $body['country_name'] );
            }
        }

        return $geo;
    }

    private function send_html_alert( $ip, $count, $country, $ua, $reason, $expires_at ) {
        $email = get_option( 'nss_alert_email', '' );
        if ( ! is_email( $email ) ) {
            return;
        }

        $rate_limit_minutes = max( 1, absint( get_option( 'nss_alert_rate_limit_minutes', 60 ) ) );
        $alert_key          = 'nss_alert_' . md5( $ip . $reason );
        if ( get_transient( $alert_key ) ) {
            return;
        }
        set_transient( $alert_key, 1, $rate_limit_minutes * MINUTE_IN_SECONDS );

        $logo_url        = esc_url( get_option( 'nss_brand_logo_url', '' ) );
        $primary_color   = sanitize_hex_color( get_option( 'nss_brand_color_primary', '#00c7ee' ) );
        $secondary_color = sanitize_hex_color( get_option( 'nss_brand_color_secondary', '#061a33' ) );
        $site_name       = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
        $admin_link      = admin_url( 'admin.php?page=nubasec-security-shield' );
        $alert_title     = 'Brute Force Login' === $reason ? __( 'Intento de acceso sospechoso', 'nubasec-security-shield' ) : __( 'Tráfico anómalo detectado', 'nubasec-security-shield' );
        $subject         = sprintf( '[%s] %s - %s', $site_name, $reason, $ip );

        $message = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>' . esc_html__( 'Alerta de Seguridad', 'nubasec-security-shield' ) . '</title></head>';
        $message .= '<body style="margin:0;background:#f4f7fb;font-family:Arial,sans-serif;color:#172033;">';
        $message .= '<table width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:24px;"><tr><td align="center">';
        $message .= '<table width="640" cellspacing="0" cellpadding="0" style="background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 18px 45px rgba(6,26,51,.12);">';
        $message .= '<tr><td style="background:' . esc_attr( $secondary_color ) . ';padding:28px;text-align:center;">';
        if ( $logo_url ) {
            $message .= '<img src="' . esc_url( $logo_url ) . '" alt="' . esc_attr( $site_name ) . '" style="max-height:58px;display:block;margin:0 auto;">';
        } else {
            $message .= '<h1 style="margin:0;color:#ffffff;font-size:24px;">Nubasec Security Shield</h1>';
        }
        $message .= '</td></tr>';
        $message .= '<tr><td style="padding:34px 32px;">';
        $message .= '<div style="display:inline-block;background:#eafcff;color:' . esc_attr( $secondary_color ) . ';border-radius:999px;padding:8px 12px;font-size:12px;font-weight:bold;text-transform:uppercase;letter-spacing:.08em;">' . esc_html__( 'Alerta automática', 'nubasec-security-shield' ) . '</div>';
        $message .= '<h2 style="color:' . esc_attr( $secondary_color ) . ';font-size:26px;margin:18px 0 8px;">' . esc_html( $alert_title ) . '</h2>';
        $message .= '<p style="color:#526579;font-size:15px;line-height:1.6;margin:0 0 22px;">' . esc_html__( 'El sistema bloqueó temporalmente una IP para proteger tu sitio web.', 'nubasec-security-shield' ) . '</p>';
        $message .= '<table width="100%" cellspacing="0" cellpadding="12" style="background:#f8fbfe;border:1px solid #dce9f5;border-radius:14px;">';
        $rows = array(
            __( 'Dirección IP', 'nubasec-security-shield' ) => $ip,
            __( 'País', 'nubasec-security-shield' ) => $country,
            __( 'Motivo', 'nubasec-security-shield' ) => $reason,
            __( 'Intensidad', 'nubasec-security-shield' ) => absint( $count ) . ' ' . __( 'eventos', 'nubasec-security-shield' ),
            __( 'Expira', 'nubasec-security-shield' ) => $expires_at,
            __( 'User Agent', 'nubasec-security-shield' ) => substr( $ua, 0, 140 ),
        );
        foreach ( $rows as $label => $value ) {
            $message .= '<tr><td style="width:34%;font-weight:bold;color:#172033;border-bottom:1px solid #e5edf5;">' . esc_html( $label ) . '</td><td style="color:#526579;border-bottom:1px solid #e5edf5;font-family:Arial,sans-serif;">' . esc_html( $value ) . '</td></tr>';
        }
        $message .= '</table>';
        $message .= '<p style="text-align:center;margin:30px 0 0;"><a href="' . esc_url( $admin_link ) . '" style="background:' . esc_attr( $primary_color ) . ';color:#ffffff;text-decoration:none;border-radius:10px;padding:13px 20px;display:inline-block;font-weight:bold;">' . esc_html__( 'Ir al dashboard', 'nubasec-security-shield' ) . '</a></p>';
        $message .= '</td></tr><tr><td style="background:#f0f5fa;padding:18px;text-align:center;color:#6b7c8f;font-size:12px;">' . esc_html__( 'Generado automáticamente por Nubasec Security Shield.', 'nubasec-security-shield' ) . '</td></tr>';
        $message .= '</table></td></tr></table></body></html>';

        wp_mail( $email, $subject, $message, array( 'Content-Type: text/html; charset=UTF-8' ) );
    }

    public function handle_admin_actions() {
        if ( ! isset( $_GET['page'] ) || 'nubasec-security-shield' !== sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) {
            return;
        }

        if ( isset( $_GET['nss_action'], $_GET['id'], $_GET['_wpnonce'] ) && 'unblock' === sanitize_text_field( wp_unslash( $_GET['nss_action'] ) ) ) {
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'No tienes permisos suficientes.', 'nubasec-security-shield' ) );
            }

            $id = absint( $_GET['id'] );
            check_admin_referer( 'nss_unblock_ip_' . $id );

            global $wpdb;
            $wpdb->delete( $this->table_name, array( 'id' => $id ), array( '%d' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=nubasec-security-shield&nss_notice=unblocked' ) );
            exit;
        }
    }

    public function handle_csv_export() {
        if ( ! isset( $_POST['nss_export_csv'] ) ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'No tienes permisos suficientes.', 'nubasec-security-shield' ) );
        }

        check_admin_referer( 'nss_export_action', 'nss_nonce_field' );

        $filters = $this->get_dashboard_filters_from_post();
        $where   = $this->build_where_clause( $filters );

        global $wpdb;
        $results = $wpdb->get_results(
            $wpdb->prepare( "SELECT * FROM {$this->table_name} WHERE {$where['sql']} ORDER BY blocked_at DESC", $where['args'] ),
            ARRAY_A
        );

        $filename = sanitize_file_name( 'nubasec_security_report_' . $filters['type'] . '_' . $filters['start'] . '.csv' );

        nocache_headers();
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        $output = fopen( 'php://output', 'w' );
        fputcsv( $output, array( 'ID', 'IP', 'Reason', 'Country', 'Request URI', 'OS', 'Browser', 'Blocked At', 'Expires At', 'Count', 'User Agent' ) );

        foreach ( $results as $row ) {
            fputcsv(
                $output,
                array(
                    $this->csv_safe( $row['id'] ),
                    $this->csv_safe( $row['ip_address'] ),
                    $this->csv_safe( $row['reason'] ),
                    $this->csv_safe( $row['country_name'] ),
                    $this->csv_safe( $row['request_uri'] ),
                    $this->csv_safe( $this->get_os( $row['user_agent'] ) ),
                    $this->csv_safe( $this->get_browser( $row['user_agent'] ) ),
                    $this->csv_safe( $row['blocked_at'] ),
                    $this->csv_safe( $row['expires_at'] ),
                    $this->csv_safe( $row['request_count'] ),
                    $this->csv_safe( $row['user_agent'] ),
                )
            );
        }

        fclose( $output );
        exit;
    }

    private function csv_safe( $value ) {
        $value = (string) $value;
        if ( preg_match( '/^[=+\-@]/', $value ) ) {
            $value = "'" . $value;
        }
        return $value;
    }

    private function get_os( $ua ) {
        if ( preg_match( '/windows/i', $ua ) ) {
            return 'Windows';
        }
        if ( preg_match( '/macintosh|mac os x/i', $ua ) ) {
            return 'macOS';
        }
        if ( preg_match( '/android/i', $ua ) ) {
            return 'Android';
        }
        if ( preg_match( '/iphone|ipad/i', $ua ) ) {
            return 'iOS';
        }
        if ( preg_match( '/linux/i', $ua ) ) {
            return 'Linux';
        }
        return 'Unknown';
    }

    private function get_browser( $ua ) {
        if ( preg_match( '/edg/i', $ua ) ) {
            return 'Edge';
        }
        if ( preg_match( '/chrome|chromium/i', $ua ) ) {
            return 'Chrome';
        }
        if ( preg_match( '/firefox/i', $ua ) ) {
            return 'Firefox';
        }
        if ( preg_match( '/safari/i', $ua ) && ! preg_match( '/chrome|chromium/i', $ua ) ) {
            return 'Safari';
        }
        return 'Bot/Other';
    }

    public function register_admin_menu() {
        add_menu_page(
            esc_html__( 'Nubasec Security Shield', 'nubasec-security-shield' ),
            esc_html__( 'Nubasec Shield', 'nubasec-security-shield' ),
            'manage_options',
            'nubasec-security-shield',
            array( $this, 'render_dashboard' ),
            NUBASEC_SECURITY_SHIELD_URL . 'assets/icon-20x20.png',
            31
        );
    }

    public function enqueue_admin_assets( $hook ) {
        if ( 'toplevel_page_nubasec-security-shield' !== $hook ) {
            return;
        }

        wp_enqueue_style(
            'nubasec-security-shield-admin',
            NUBASEC_SECURITY_SHIELD_URL . 'admin/css/nubasec-security-shield-admin.css',
            array(),
            NUBASEC_SECURITY_SHIELD_VERSION
        );

        wp_enqueue_script(
            'nubasec-security-shield-admin',
            NUBASEC_SECURITY_SHIELD_URL . 'admin/js/nubasec-security-shield-admin.js',
            array(),
            NUBASEC_SECURITY_SHIELD_VERSION,
            true
        );
    }

    public function admin_body_class( $classes ) {
        $screen = get_current_screen();
        if ( $screen && 'toplevel_page_nubasec-security-shield' === $screen->id ) {
            $classes .= ' nubasec-shield-admin-ui';
        }
        return $classes;
    }

    private function get_dashboard_filters_from_post() {
        $today = current_time( 'Y-m-d' );

        return array(
            'start' => isset( $_POST['date_start'] ) ? sanitize_text_field( wp_unslash( $_POST['date_start'] ) ) : gmdate( 'Y-m-d', strtotime( '-7 days' ) ),
            'end'   => isset( $_POST['date_end'] ) ? sanitize_text_field( wp_unslash( $_POST['date_end'] ) ) : $today,
            'type'  => isset( $_POST['filter_type'] ) ? sanitize_text_field( wp_unslash( $_POST['filter_type'] ) ) : 'all',
        );
    }

    private function get_dashboard_filters_from_request() {
        $today = current_time( 'Y-m-d' );

        return array(
            'start' => isset( $_GET['date_start'] ) ? sanitize_text_field( wp_unslash( $_GET['date_start'] ) ) : gmdate( 'Y-m-d', strtotime( '-7 days' ) ),
            'end'   => isset( $_GET['date_end'] ) ? sanitize_text_field( wp_unslash( $_GET['date_end'] ) ) : $today,
            'type'  => isset( $_GET['filter_type'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_type'] ) ) : 'all',
        );
    }

    private function normalize_filters( $filters ) {
        $filters['start'] = preg_match( '/^\d{4}-\d{2}-\d{2}$/', $filters['start'] ) ? $filters['start'] : gmdate( 'Y-m-d', strtotime( '-7 days' ) );
        $filters['end']   = preg_match( '/^\d{4}-\d{2}-\d{2}$/', $filters['end'] ) ? $filters['end'] : current_time( 'Y-m-d' );

        if ( ! in_array( $filters['type'], array( 'all', 'rate', 'login' ), true ) ) {
            $filters['type'] = 'all';
        }

        return $filters;
    }

    private function build_where_clause( $filters ) {
        $filters = $this->normalize_filters( $filters );
        $sql     = 'blocked_at BETWEEN %s AND %s';
        $args    = array( $filters['start'] . ' 00:00:00', $filters['end'] . ' 23:59:59' );

        if ( 'rate' === $filters['type'] ) {
            $sql   .= ' AND reason = %s';
            $args[] = 'Rate Limit';
        } elseif ( 'login' === $filters['type'] ) {
            $sql   .= ' AND reason = %s';
            $args[] = 'Brute Force Login';
        }

        return array(
            'sql'  => $sql,
            'args' => $args,
        );
    }

    private function get_dashboard_data( $filters ) {
        global $wpdb;

        $where = $this->build_where_clause( $filters );

        $total = (int) $wpdb->get_var(
            $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table_name} WHERE {$where['sql']}", $where['args'] )
        );

        $rate = (int) $wpdb->get_var(
            $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table_name} WHERE {$where['sql']} AND reason = %s", array_merge( $where['args'], array( 'Rate Limit' ) ) )
        );

        $login = (int) $wpdb->get_var(
            $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table_name} WHERE {$where['sql']} AND reason = %s", array_merge( $where['args'], array( 'Brute Force Login' ) ) )
        );

        $active = (int) $wpdb->get_var(
            $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table_name} WHERE expires_at > %s", current_time( 'mysql' ) )
        );

        $timeline = $wpdb->get_results(
            $wpdb->prepare( "SELECT DATE(blocked_at) as event_day, COUNT(*) as total FROM {$this->table_name} WHERE {$where['sql']} GROUP BY DATE(blocked_at) ORDER BY event_day ASC", $where['args'] )
        );

        $countries = $wpdb->get_results(
            $wpdb->prepare( "SELECT country_name, COUNT(*) as total FROM {$this->table_name} WHERE {$where['sql']} GROUP BY country_name ORDER BY total DESC LIMIT 8", $where['args'] )
        );

        $recent = $wpdb->get_results(
            $wpdb->prepare( "SELECT * FROM {$this->table_name} WHERE {$where['sql']} ORDER BY blocked_at DESC LIMIT 50", $where['args'] )
        );

        return array(
            'total'     => $total,
            'rate'      => $rate,
            'login'     => $login,
            'active'    => $active,
            'timeline'  => $timeline,
            'countries' => $countries,
            'recent'    => $recent,
        );
    }

    public function render_dashboard() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'No tienes permisos suficientes para acceder a esta página.', 'nubasec-security-shield' ) );
        }

        $filters         = $this->normalize_filters( $this->get_dashboard_filters_from_request() );
        $data            = $this->get_dashboard_data( $filters );
        $logo_url        = esc_url( get_option( 'nss_brand_logo_url', '' ) );
        $primary_color   = sanitize_hex_color( get_option( 'nss_brand_color_primary', '#00c7ee' ) );
        $secondary_color = sanitize_hex_color( get_option( 'nss_brand_color_secondary', '#061a33' ) );
        ?>
        <div class="wrap nss-wrap" style="--nss-primary: <?php echo esc_attr( $primary_color ); ?>; --nss-secondary: <?php echo esc_attr( $secondary_color ); ?>;">
            <?php if ( isset( $_GET['nss_notice'] ) && 'unblocked' === sanitize_text_field( wp_unslash( $_GET['nss_notice'] ) ) ) : ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__( 'IP desbloqueada correctamente.', 'nubasec-security-shield' ); ?></p></div>
            <?php endif; ?>

            <section class="nss-hero">
                <div class="nss-hero__content">
                    <span class="nss-eyebrow"><?php echo esc_html__( 'Nubasec Security Shield', 'nubasec-security-shield' ); ?></span>
                    <h1><?php echo esc_html__( 'Monitoreo y protección básica contra abuso web', 'nubasec-security-shield' ); ?></h1>
                    <p><?php echo esc_html__( 'Controla eventos de rate limit, intentos de fuerza bruta, alertas administrativas y desbloqueo de IPs desde una interfaz alineada con la marca Nubasec.', 'nubasec-security-shield' ); ?></p>
                </div>
                <div class="nss-hero__brand">
                    <?php if ( $logo_url ) : ?>
                        <img src="<?php echo esc_url( $logo_url ); ?>" alt="<?php echo esc_attr__( 'Logo', 'nubasec-security-shield' ); ?>" />
                    <?php else : ?>
                        <img src="<?php echo esc_url( NUBASEC_SECURITY_SHIELD_URL . 'assets/icon-256x256.png' ); ?>" alt="<?php echo esc_attr__( 'Nubasec', 'nubasec-security-shield' ); ?>" />
                    <?php endif; ?>
                    <span class="nss-status-pill"><?php echo esc_html__( 'Monitor activo', 'nubasec-security-shield' ); ?></span>
                </div>
            </section>

            <section class="nss-stats-grid">
                <article class="nss-stat"><span class="dashicons dashicons-shield-alt"></span><div><strong><?php echo esc_html( number_format_i18n( $data['active'] ) ); ?></strong><p><?php echo esc_html__( 'Bloqueos activos', 'nubasec-security-shield' ); ?></p></div></article>
                <article class="nss-stat"><span class="dashicons dashicons-chart-area"></span><div><strong><?php echo esc_html( number_format_i18n( $data['total'] ) ); ?></strong><p><?php echo esc_html__( 'Eventos del periodo', 'nubasec-security-shield' ); ?></p></div></article>
                <article class="nss-stat"><span class="dashicons dashicons-performance"></span><div><strong><?php echo esc_html( number_format_i18n( $data['rate'] ) ); ?></strong><p><?php echo esc_html__( 'Rate limit', 'nubasec-security-shield' ); ?></p></div></article>
                <article class="nss-stat"><span class="dashicons dashicons-lock"></span><div><strong><?php echo esc_html( number_format_i18n( $data['login'] ) ); ?></strong><p><?php echo esc_html__( 'Fuerza bruta login', 'nubasec-security-shield' ); ?></p></div></article>
            </section>

            <section class="nss-card nss-filters-card">
                <form method="get" class="nss-filters-form">
                    <input type="hidden" name="page" value="nubasec-security-shield" />
                    <div><label><?php echo esc_html__( 'Tipo', 'nubasec-security-shield' ); ?></label><select name="filter_type"><option value="all" <?php selected( $filters['type'], 'all' ); ?>><?php echo esc_html__( 'Todos', 'nubasec-security-shield' ); ?></option><option value="rate" <?php selected( $filters['type'], 'rate' ); ?>><?php echo esc_html__( 'Rate limit', 'nubasec-security-shield' ); ?></option><option value="login" <?php selected( $filters['type'], 'login' ); ?>><?php echo esc_html__( 'Login', 'nubasec-security-shield' ); ?></option></select></div>
                    <div><label><?php echo esc_html__( 'Inicio', 'nubasec-security-shield' ); ?></label><input type="date" name="date_start" value="<?php echo esc_attr( $filters['start'] ); ?>" /></div>
                    <div><label><?php echo esc_html__( 'Fin', 'nubasec-security-shield' ); ?></label><input type="date" name="date_end" value="<?php echo esc_attr( $filters['end'] ); ?>" /></div>
                    <div class="nss-filter-actions"><button type="submit" class="button button-primary nss-button-primary"><?php echo esc_html__( 'Actualizar', 'nubasec-security-shield' ); ?></button></div>
                </form>
                <form method="post" class="nss-export-form">
                    <?php wp_nonce_field( 'nss_export_action', 'nss_nonce_field' ); ?>
                    <input type="hidden" name="date_start" value="<?php echo esc_attr( $filters['start'] ); ?>" />
                    <input type="hidden" name="date_end" value="<?php echo esc_attr( $filters['end'] ); ?>" />
                    <input type="hidden" name="filter_type" value="<?php echo esc_attr( $filters['type'] ); ?>" />
                    <button type="submit" name="nss_export_csv" value="1" class="button nss-button-secondary"><?php echo esc_html__( 'Exportar CSV', 'nubasec-security-shield' ); ?></button>
                </form>
            </section>

            <section class="nss-grid-2">
                <article class="nss-card">
                    <div class="nss-card-header"><h2><?php echo esc_html__( 'Tendencia de eventos', 'nubasec-security-shield' ); ?></h2></div>
                    <div class="nss-bars" aria-label="<?php echo esc_attr__( 'Tendencia de eventos', 'nubasec-security-shield' ); ?>">
                        <?php
                        $max = 1;
                        foreach ( $data['timeline'] as $item ) {
                            $max = max( $max, (int) $item->total );
                        }
                        if ( $data['timeline'] ) :
                            foreach ( $data['timeline'] as $item ) :
                                $height = max( 8, round( ( (int) $item->total / $max ) * 120 ) );
                                ?>
                                <div class="nss-bar-item"><div class="nss-bar" style="height: <?php echo esc_attr( $height ); ?>px;"><span><?php echo esc_html( number_format_i18n( $item->total ) ); ?></span></div><small><?php echo esc_html( mysql2date( 'd/m', $item->event_day ) ); ?></small></div>
                                <?php
                            endforeach;
                        else :
                            echo '<p class="nss-empty">' . esc_html__( 'Sin eventos para el periodo seleccionado.', 'nubasec-security-shield' ) . '</p>';
                        endif;
                        ?>
                    </div>
                </article>

                <article class="nss-card">
                    <div class="nss-card-header"><h2><?php echo esc_html__( 'Países / origen', 'nubasec-security-shield' ); ?></h2></div>
                    <div class="nss-country-list">
                        <?php if ( $data['countries'] ) : ?>
                            <?php foreach ( $data['countries'] as $country ) : ?>
                                <div class="nss-country-row"><span><?php echo esc_html( $country->country_name ); ?></span><strong><?php echo esc_html( number_format_i18n( $country->total ) ); ?></strong></div>
                            <?php endforeach; ?>
                        <?php else : ?>
                            <p class="nss-empty"><?php echo esc_html__( 'Sin datos de origen.', 'nubasec-security-shield' ); ?></p>
                        <?php endif; ?>
                    </div>
                </article>
            </section>

            <section class="nss-grid-main">
                <article class="nss-card nss-logs-card">
                    <div class="nss-card-header"><h2><?php echo esc_html__( 'Logs detallados', 'nubasec-security-shield' ); ?></h2></div>
                    <div class="nss-table-wrap">
                        <table class="widefat fixed striped nss-table">
                            <thead><tr><th><?php echo esc_html__( 'Amenaza', 'nubasec-security-shield' ); ?></th><th><?php echo esc_html__( 'IP / Origen', 'nubasec-security-shield' ); ?></th><th><?php echo esc_html__( 'URI', 'nubasec-security-shield' ); ?></th><th><?php echo esc_html__( 'Expira', 'nubasec-security-shield' ); ?></th><th><?php echo esc_html__( 'Acción', 'nubasec-security-shield' ); ?></th></tr></thead>
                            <tbody>
                            <?php if ( $data['recent'] ) : ?>
                                <?php foreach ( $data['recent'] as $row ) : ?>
                                    <?php
                                    $is_login = 'Brute Force Login' === $row->reason;
                                    $tag_cls  = $is_login ? 'nss-tag-login' : 'nss-tag-rate';
                                    $url      = wp_nonce_url( admin_url( 'admin.php?page=nubasec-security-shield&nss_action=unblock&id=' . absint( $row->id ) ), 'nss_unblock_ip_' . absint( $row->id ) );
                                    ?>
                                    <tr>
                                        <td><span class="nss-tag <?php echo esc_attr( $tag_cls ); ?>"><?php echo esc_html( $row->reason ); ?></span></td>
                                        <td><strong><?php echo esc_html( $row->ip_address ); ?></strong><br><small><?php echo esc_html( $row->country_name ); ?></small></td>
                                        <td><code><?php echo esc_html( $row->request_uri ); ?></code><br><small><?php echo esc_html( $this->get_browser( $row->user_agent ) . ' / ' . $this->get_os( $row->user_agent ) ); ?></small></td>
                                        <td><?php echo esc_html( mysql2date( 'd/m/Y H:i', $row->expires_at ) ); ?></td>
                                        <td><a class="nss-unblock" href="<?php echo esc_url( $url ); ?>"><?php echo esc_html__( 'Desbloquear', 'nubasec-security-shield' ); ?></a></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else : ?>
                                <tr><td colspan="5"><?php echo esc_html__( 'Sin registros para el periodo seleccionado.', 'nubasec-security-shield' ); ?></td></tr>
                            <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </article>

                <aside class="nss-card nss-settings-card">
                    <div class="nss-card-header"><h2><?php echo esc_html__( 'Configuración', 'nubasec-security-shield' ); ?></h2></div>
                    <form method="post" action="options.php" class="nss-settings-form">
                        <?php settings_fields( 'nss_settings_group' ); ?>
                        <h3><?php echo esc_html__( 'Marca Nubasec', 'nubasec-security-shield' ); ?></h3>
                        <div class="nss-color-row"><label><?php echo esc_html__( 'Primario', 'nubasec-security-shield' ); ?><input type="color" name="nss_brand_color_primary" value="<?php echo esc_attr( $primary_color ); ?>" /></label><label><?php echo esc_html__( 'Secundario', 'nubasec-security-shield' ); ?><input type="color" name="nss_brand_color_secondary" value="<?php echo esc_attr( $secondary_color ); ?>" /></label></div>
                        <label><?php echo esc_html__( 'URL del logo', 'nubasec-security-shield' ); ?><input type="url" name="nss_brand_logo_url" value="<?php echo esc_attr( get_option( 'nss_brand_logo_url', '' ) ); ?>" placeholder="https://" /></label>

                        <h3><?php echo esc_html__( 'Protección', 'nubasec-security-shield' ); ?></h3>
                        <label><?php echo esc_html__( 'Límite de solicitudes por minuto', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_request_limit" value="<?php echo esc_attr( get_option( 'nss_request_limit', 60 ) ); ?>" /></label>
                        <label><?php echo esc_html__( 'Horas de bloqueo por rate limit', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_block_hours_ddos" value="<?php echo esc_attr( get_option( 'nss_block_hours_ddos', 24 ) ); ?>" /></label>
                        <label><?php echo esc_html__( 'Intentos fallidos de login', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_login_max_attempts" value="<?php echo esc_attr( get_option( 'nss_login_max_attempts', 5 ) ); ?>" /></label>
                        <label><?php echo esc_html__( 'Horas de bloqueo por login', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_block_hours_login" value="<?php echo esc_attr( get_option( 'nss_block_hours_login', 24 ) ); ?>" /></label>
                        <label><?php echo esc_html__( 'Email de alertas', 'nubasec-security-shield' ); ?><input type="email" name="nss_alert_email" value="<?php echo esc_attr( get_option( 'nss_alert_email', '' ) ); ?>" /></label>
                        <label><?php echo esc_html__( 'Minutos mínimos entre alertas por IP/motivo', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_alert_rate_limit_minutes" value="<?php echo esc_attr( get_option( 'nss_alert_rate_limit_minutes', 60 ) ); ?>" /></label>

                        <h3><?php echo esc_html__( 'Listas y privacidad', 'nubasec-security-shield' ); ?></h3>
                        <label><?php echo esc_html__( 'Whitelist IPs / CIDR', 'nubasec-security-shield' ); ?><textarea name="nss_whitelist" rows="4" placeholder="192.168.1.10&#10;10.0.0.0/24"><?php echo esc_textarea( get_option( 'nss_whitelist', '' ) ); ?></textarea></label>
                        <label class="nss-checkbox"><input type="checkbox" name="nss_exclude_admins" value="1" <?php checked( get_option( 'nss_exclude_admins', 1 ), 1 ); ?> /> <?php echo esc_html__( 'Excluir administradores autenticados del monitoreo', 'nubasec-security-shield' ); ?></label>
                        <label class="nss-checkbox"><input type="checkbox" name="nss_enable_geo_lookup" value="1" <?php checked( get_option( 'nss_enable_geo_lookup', 0 ), 1 ); ?> /> <?php echo esc_html__( 'Activar geolocalización externa de IPs bloqueadas', 'nubasec-security-shield' ); ?></label>
                        <p class="description"><?php echo esc_html__( 'La geolocalización está desactivada por defecto. Al activarla, las IPs bloqueadas pueden consultarse contra ipapi.co para obtener país de origen.', 'nubasec-security-shield' ); ?></p>
                        <label class="nss-checkbox"><input type="checkbox" name="nss_enable_trusted_proxy_headers" value="1" <?php checked( get_option( 'nss_enable_trusted_proxy_headers', 0 ), 1 ); ?> /> <?php echo esc_html__( 'Confiar en X-Forwarded-For solo desde proxies permitidos', 'nubasec-security-shield' ); ?></label>
                        <label><?php echo esc_html__( 'Proxies confiables IPs / CIDR', 'nubasec-security-shield' ); ?><textarea name="nss_trusted_proxies" rows="3"><?php echo esc_textarea( get_option( 'nss_trusted_proxies', '' ) ); ?></textarea></label>
                        <label><?php echo esc_html__( 'Retención de logs en días', 'nubasec-security-shield' ); ?><input type="number" min="1" name="nss_log_retention_days" value="<?php echo esc_attr( get_option( 'nss_log_retention_days', 30 ) ); ?>" /></label>
                        <label class="nss-checkbox"><input type="checkbox" name="nss_delete_data_on_uninstall" value="1" <?php checked( get_option( 'nss_delete_data_on_uninstall', 0 ), 1 ); ?> /> <?php echo esc_html__( 'Eliminar datos al desinstalar', 'nubasec-security-shield' ); ?></label>
                        <p class="submit"><input type="submit" class="button button-primary nss-button-primary" value="<?php echo esc_attr__( 'Guardar cambios', 'nubasec-security-shield' ); ?>" /></p>
                    </form>
                </aside>
            </section>
        </div>
        <?php
    }
}

register_activation_hook( __FILE__, array( 'Nubasec_Security_Shield', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Nubasec_Security_Shield', 'deactivate' ) );
Nubasec_Security_Shield::instance();
