<?php
/*
Plugin Name: DDoS Shield Pro
Plugin URI: https://github.com/nubasec/ddos-shield-pro
Description: Protección básica contra abuso de solicitudes, intentos de fuerza bruta, bloqueo de IPs, alertas administrativas y monitoreo de eventos de seguridad.
Version: 1.0.0
Requires at least: 6.0
Requires PHP: 7.4
Author: Nubasec
Author URI: https://nubasec.com/
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: ddos-shield-pro
Domain Path: /languages
*/

if ( ! defined( 'ABSPATH' ) ) exit;

class DDoS_Shield_Pro {

    private $table_name;
    private $limit;
    private $time_window = 60;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'ddos_blocked_ips';
        $this->limit = (int) get_option('ddos_req_limit', 60);

        // --- HOOKS ---
        register_activation_hook(__FILE__, array($this, 'install_db'));
        add_action('plugins_loaded', array($this, 'update_db_check'));
        
        // Cron Limpieza
        if ( ! wp_next_scheduled( 'ddos_daily_purge_v12' ) ) {
            wp_schedule_event( time(), 'daily', 'ddos_daily_purge_v12' );
        }
        add_action( 'ddos_daily_purge_v12', array($this, 'cleanup_old_logs') );

        // Core
        add_action('init', array($this, 'firewall_monitor'));
        add_action('wp_login_failed', array($this, 'handle_failed_login'));
        
        // Admin
        add_action('admin_menu', array($this, 'register_admin_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_init', array($this, 'handle_csv_export'));
        add_action('admin_enqueue_scripts', array($this, 'load_scripts'));
    }

    /**
     * 1. BASE DE DATOS
     */
    public function install_db() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $this->table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            country_code varchar(10) DEFAULT 'XX',
            country_name varchar(100) DEFAULT 'Unknown',
            user_agent varchar(255) DEFAULT '',
            reason varchar(50) DEFAULT 'DDoS',
            blocked_at datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            request_count int(11) DEFAULT 0,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address),
            KEY blocked_at (blocked_at)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
        update_option('ddos_shield_db_ver', '12.0');
    }

    public function update_db_check() {
        if (get_option('ddos_shield_db_ver') != '12.0') {
            $this->install_db();
        }
    }

    public function cleanup_old_logs() {
        global $wpdb;
        $wpdb->query( "DELETE FROM $this->table_name WHERE blocked_at < NOW() - INTERVAL 30 DAY" );
    }

    /**
     * 2. DETECTOR DE FUERZA BRUTA
     */
    public function handle_failed_login($username) {
        $ip = $this->get_ip();
        $transient_key = 'bf_fail_' . md5($ip);
        $attempts = (int) get_transient($transient_key);
        $attempts++;
        set_transient($transient_key, $attempts, 20 * MINUTE_IN_SECONDS);

        $limit = (int) get_option('bf_max_attempts', 5);
        if ($attempts >= $limit) {
            $this->block_ip($ip, $attempts, 'Brute Force (Login)');
        }
    }

    /**
     * 3. FIREWALL MONITOR
     */
    public function firewall_monitor() {
        if ( is_admin() || current_user_can('manage_options') ) {
            $ip = $this->get_ip();
            $whitelist = get_option('ddos_whitelist', '');
            if (strpos($whitelist, $ip) !== false) return;
        } else {
            $ip = $this->get_ip();
        }

        $whitelist = get_option('ddos_whitelist', '');
        $allowed_ips = array_map('trim', explode("\n", $whitelist));
        if (in_array($ip, $allowed_ips)) return;

        global $wpdb;
        $block = $wpdb->get_row( $wpdb->prepare("SELECT * FROM $this->table_name WHERE ip_address = %s", $ip) );

        if ($block) {
            if (strpos($block->reason, 'Brute') !== false) {
                $hours = (int) get_option('bf_block_hours', 24);
                if ( (time() - strtotime($block->blocked_at)) > ($hours * 3600) ) {
                    $wpdb->delete($this->table_name, array('id' => $block->id));
                    return; 
                }
            }
            header('HTTP/1.1 403 Forbidden');
            die('<h1>403 Access Denied</h1><p>Your IP has been blocked due to suspicious activity (' . esc_html($block->reason) . ').</p>');
        }

        $transient_key = 'ddos_' . md5($ip);
        $count = (int) get_transient($transient_key);

        if ($count >= $this->limit) {
            $this->block_ip($ip, $count, 'DDoS Attack');
        } else {
            $ttl = ($count === 0) ? 1 : $count + 1;
            set_transient($transient_key, $ttl, $this->time_window);
        }
    }

    private function block_ip($ip, $count, $reason = 'DDoS') {
        global $wpdb;
        $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM $this->table_name WHERE ip_address = %s", $ip));
        if($exists) return;

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : 'Unknown';
        $country_code = 'XX'; $country_name = 'Unknown';
        
        $response = wp_remote_get("http://ip-api.com/json/{$ip}?fields=status,country,countryCode");
        if (!is_wp_error($response)) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            if (isset($body['status']) && $body['status'] == 'success') {
                $country_code = sanitize_text_field($body['countryCode']);
                $country_name = sanitize_text_field($body['country']);
            }
        }

        $wpdb->insert(
            $this->table_name,
            array('ip_address' => $ip, 'country_code' => $country_code, 'country_name' => $country_name, 'user_agent' => substr($ua, 0, 250), 'reason' => $reason, 'blocked_at' => current_time('mysql'), 'request_count' => $count),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%d')
        );

        // --- NUEVA FUNCIÓN DE ENVÍO HTML ---
        $this->send_html_alert($ip, $count, $country_name, $ua, $reason);
    }

    /**
     * ENVÍO DE CORREO HTML MEJORADO
     */
    private function send_html_alert($ip, $count, $country, $ua, $reason) {
        $email = get_option('ddos_alert_email');
        if (!is_email($email)) return;

        // Branding
        $logo_url = get_option('ddos_brand_logo_url');
        $primary_color = get_option('ddos_brand_color_primary', '#2271b1');
        $site_name = get_bloginfo('name');
        $admin_link = admin_url('options-general.php?page=ddos-shield');
        
        // Icono según tipo
        $alert_title = (strpos($reason, 'Brute') !== false) ? 'Intento de Acceso Ilegal' : 'Tráfico Sospechoso (DDoS)';
        $alert_color = (strpos($reason, 'Brute') !== false) ? '#e6a800' : '#d63638';

        $subject = "🚨 Alerta: $reason ($country) - $site_name";

        // Template HTML
        $message = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Alerta de Seguridad</title>
        </head>
        <body style="margin:0; padding:0; background-color:#f4f4f7; font-family:Arial, sans-serif;">
            <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#f4f4f7; padding: 20px;">
                <tr>
                    <td align="center">
                        <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff; border-radius:8px; overflow:hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                            <tr>
                                <td style="background-color:'. $primary_color .'; padding: 30px; text-align:center;">
                                    '. ($logo_url ? '<img src="'.$logo_url.'" alt="Logo" style="max-height:50px; display:block; margin:0 auto;">' : '<h2 style="color:#ffffff; margin:0;">'.$site_name.'</h2>') .'
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 40px 30px;">
                                    <h2 style="color:'. $alert_color .'; margin-top:0;">⚠️ '. $alert_title .'</h2>
                                    <p style="color:#555555; font-size:16px; line-height:1.5;">El sistema de seguridad ha bloqueado una IP automáticamente para proteger tu sitio web.</p>
                                    
                                    <table width="100%" border="0" cellspacing="0" cellpadding="10" style="background-color:#f9f9f9; border:1px solid #eee; margin: 20px 0; border-radius:4px;">
                                        <tr>
                                            <td width="30%" style="font-weight:bold; color:#333;">Dirección IP:</td>
                                            <td style="color:#333; font-family:monospace; font-size:14px;">'. $ip .'</td>
                                        </tr>
                                        <tr>
                                            <td style="font-weight:bold; color:#333;">Origen:</td>
                                            <td style="color:#333;">'. $country .'</td>
                                        </tr>
                                        <tr>
                                            <td style="font-weight:bold; color:#333;">Motivo:</td>
                                            <td style="color:#d63638; font-weight:bold;">'. $reason .'</td>
                                        </tr>
                                        <tr>
                                            <td style="font-weight:bold; color:#333;">Intensidad:</td>
                                            <td style="color:#333;">'. $count .' peticiones / min</td>
                                        </tr>
                                        <tr>
                                            <td style="font-weight:bold; color:#333;">Agente:</td>
                                            <td style="color:#666; font-size:12px;">'. substr($ua, 0, 100) .'...</td>
                                        </tr>
                                    </table>

                                    <div style="text-align:center; margin-top:30px;">
                                        <a href="'. $admin_link .'" style="background-color:'. $primary_color .'; color:#ffffff; padding: 12px 25px; text-decoration:none; border-radius:4px; font-weight:bold; display:inline-block;">Ir al Dashboard de Seguridad</a>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td style="background-color:#eeeeee; padding: 20px; text-align:center; font-size:12px; color:#888888;">
                                    <p style="margin:0;">Generado automáticamente por DDoS Shield Pro.</p>
                                    <p style="margin:5px 0 0;">'. date('Y') .' © '. $site_name .'</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        ';

        // Headers para HTML
        $headers = array('Content-Type: text/html; charset=UTF-8');
        wp_mail($email, $subject, $message, $headers);
    }

    /**
     * 4. EXPORTACIÓN CSV
     */
    public function handle_csv_export() {
        if ( isset($_POST['ddos_export_csv']) && current_user_can('manage_options') ) {
            check_admin_referer('ddos_export_action', 'ddos_nonce_field');
            global $wpdb;
            
            $start = isset($_POST['date_start']) ? sanitize_text_field($_POST['date_start']) : date('Y-m-d', strtotime('-30 days'));
            $end   = isset($_POST['date_end'])   ? sanitize_text_field($_POST['date_end'])   : date('Y-m-d');
            $filter = isset($_POST['filter_type']) ? sanitize_text_field($_POST['filter_type']) : 'all';

            $sql = "SELECT * FROM $this->table_name WHERE blocked_at BETWEEN %s AND %s";
            $args = array($start . ' 00:00:00', $end . ' 23:59:59');

            if ($filter === 'ddos') $sql .= " AND reason LIKE '%DDoS%'";
            elseif ($filter === 'login') $sql .= " AND reason LIKE '%Brute%'";
            $sql .= " ORDER BY blocked_at DESC";

            $results = $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
            
            $filename = 'security_report_' . $filter . '_' . $start . '.csv';
            header('Content-Type: text/csv'); header('Content-Disposition: attachment; filename="' . $filename . '"');
            $output = fopen('php://output', 'w');
            fputcsv($output, array('ID', 'IP', 'Reason', 'Country', 'OS', 'Browser', 'Date', 'Count', 'UA'));
            foreach ($results as $row) {
                fputcsv($output, array($row['id'], $row['ip_address'], $row['reason'], $row['country_name'], $this->get_os($row['user_agent']), $this->get_browser($row['user_agent']), $row['blocked_at'], $row['request_count'], $row['user_agent']));
            }
            fclose($output); exit();
        }
    }

    // Helpers
    private function get_os($ua) { if (preg_match('/windows/i', $ua)) return 'Windows'; if (preg_match('/macintosh|mac os x/i', $ua)) return 'Mac OS'; if (preg_match('/linux/i', $ua)) return 'Linux'; if (preg_match('/android/i', $ua)) return 'Android'; if (preg_match('/iphone|ipad/i', $ua)) return 'iOS'; return 'Unknown'; }
    private function get_browser($ua) { if (preg_match('/chrome/i', $ua) && !preg_match('/edge/i', $ua)) return 'Chrome'; if (preg_match('/firefox/i', $ua)) return 'Firefox'; if (preg_match('/safari/i', $ua) && !preg_match('/chrome/i', $ua)) return 'Safari'; if (preg_match('/edge/i', $ua)) return 'Edge'; return 'Bot/Other'; }
    private function get_ip() { $ip = $_SERVER['REMOTE_ADDR']; if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]); return sanitize_text_field($ip); }

    /**
     * 5. DASHBOARD VISUAL
     */
    public function register_admin_page() { add_options_page('Security Monitor', 'Security Monitor', 'manage_options', 'ddos-shield', array($this, 'render_dashboard')); }
    public function load_scripts($hook) { if ($hook != 'settings_page_ddos-shield') return; wp_enqueue_script('chartjs', 'https://cdn.jsdelivr.net/npm/chart.js', array(), '3.9.1', true); wp_enqueue_script('google-charts', 'https://www.gstatic.com/charts/loader.js', array(), null, false); }
    public function register_settings() { register_setting('ddos_settings_group', 'ddos_req_limit'); register_setting('ddos_settings_group', 'ddos_alert_email'); register_setting('ddos_settings_group', 'ddos_whitelist'); register_setting('ddos_settings_group', 'bf_max_attempts'); register_setting('ddos_settings_group', 'bf_block_hours'); register_setting('ddos_settings_group', 'ddos_brand_logo_url'); register_setting('ddos_settings_group', 'ddos_brand_color_primary'); register_setting('ddos_settings_group', 'ddos_brand_color_secondary'); }

    public function render_dashboard() {
        if (isset($_GET['action']) && $_GET['action'] == 'unblock') { check_admin_referer('unblock_ip_' . $_GET['id']); global $wpdb; $wpdb->delete($this->table_name, array('id' => intval($_GET['id']))); }
        
        $logo_url = get_option('ddos_brand_logo_url'); $primary_color = get_option('ddos_brand_color_primary', '#2271b1'); $secondary_color = get_option('ddos_brand_color_secondary', '#135e96');
        $today = current_time('Y-m-d'); $start_date = isset($_POST['date_start']) ? sanitize_text_field($_POST['date_start']) : date('Y-m-d', strtotime('-7 days')); $end_date = isset($_POST['date_end']) ? sanitize_text_field($_POST['date_end']) : $today; $filter_type = isset($_POST['filter_type']) ? sanitize_text_field($_POST['filter_type']) : 'all';

        global $wpdb;
        $where_sql = "blocked_at BETWEEN %s AND %s"; $args = array($start_date . ' 00:00:00', $end_date . ' 23:59:59');
        if ($filter_type === 'ddos') $where_sql .= " AND reason LIKE '%DDoS%'"; elseif ($filter_type === 'login') $where_sql .= " AND reason LIKE '%Brute%'";

        $timeline = $wpdb->get_results($wpdb->prepare("SELECT DATE(blocked_at) as d, COUNT(*) as c FROM $this->table_name WHERE $where_sql GROUP BY DATE(blocked_at) ORDER BY d ASC", $args));
        $lbl_time = []; $dat_time = []; if($timeline) { foreach($timeline as $t) { $lbl_time[] = $t->d; $dat_time[] = $t->c; } }

        $dist = $wpdb->get_results($wpdb->prepare("SELECT reason, COUNT(*) as c FROM $this->table_name WHERE $where_sql GROUP BY reason", $args));
        $lbl_dist = []; $dat_dist = []; if($dist) { foreach($dist as $d) { $lbl_dist[] = $d->reason; $dat_dist[] = $d->c; } }

        $geo = $wpdb->get_results($wpdb->prepare("SELECT country_name, COUNT(*) as c FROM $this->table_name WHERE $where_sql GROUP BY country_name", $args));
        $geo_data = [['Country', 'Ataques']]; if($geo) { foreach($geo as $g) { $geo_data[] = [$g->country_name, (int)$g->c]; } }

        $recent_ips = $wpdb->get_results($wpdb->prepare("SELECT * FROM $this->table_name WHERE $where_sql ORDER BY blocked_at DESC LIMIT 50", $args));
        ?>
        <style>
            :root { --brand-primary: <?php echo esc_attr($primary_color); ?>; --brand-secondary: <?php echo esc_attr($secondary_color); ?>; }
            .ddos-card { background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); padding: 20px; border: 1px solid #e5e7eb; margin-bottom: 20px; }
            .ddos-header { background: #fff; padding: 20px 0; margin-bottom: 20px; border-bottom: 3px solid var(--brand-primary); display: flex; align-items: center; justify-content: space-between; }
            .ddos-btn-primary { background-color: var(--brand-primary) !important; border-color: var(--brand-primary) !important; color: #fff !important; }
            .ddos-tag { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; display: inline-block; }
            .tag-ddos { background: #ffe6e6; color: #d63638; border: 1px solid #d63638; }
            .tag-bf { background: #fff8e5; color: #996800; border: 1px solid #f0c33c; }
        </style>
        <div class="wrap" style="background: #f8fafc; margin-left: -20px; padding: 0 20px 40px 20px; min-height: 100vh;">
            <div class="ddos-header">
                <div><?php if($logo_url): ?> <img src="<?php echo esc_url($logo_url); ?>" style="max-height: 50px;"> <?php else: ?> <h1 style="margin:0; color: var(--brand-primary);">🛡️ Security Dashboard</h1> <?php endif; ?></div>
                <div style="text-align:right;"><span class="ddos-tag" style="background:#e5faf2; color: #00a32a; border:1px solid #00a32a;">Monitor Activo</span></div>
            </div>
            <div class="ddos-card" style="display: flex; justify-content: space-between; align-items: flex-end;">
                <form method="post" style="display: flex; gap: 15px; align-items: flex-end;">
                    <?php wp_nonce_field('ddos_export_action', 'ddos_nonce_field'); ?>
                    <div><label style="font-weight:bold; font-size:11px; color:#666;">TIPO</label><br><select name="filter_type" style="color: var(--brand-primary); font-weight:bold;"><option value="all" <?php selected($filter_type, 'all'); ?>>🌐 Todos</option><option value="ddos" <?php selected($filter_type, 'ddos'); ?>>⚡ DDoS</option><option value="login" <?php selected($filter_type, 'login'); ?>>🔐 Login</option></select></div>
                    <div><label style="font-weight:bold; font-size:11px; color:#666;">INICIO</label><br><input type="date" name="date_start" value="<?php echo esc_attr($start_date); ?>"></div>
                    <div><label style="font-weight:bold; font-size:11px; color:#666;">FIN</label><br><input type="date" name="date_end" value="<?php echo esc_attr($end_date); ?>"></div>
                    <div><button type="submit" class="button button-secondary">Actualizar</button></div>
                </form>
                <form method="post"><input type="hidden" name="date_start" value="<?php echo esc_attr($start_date); ?>"><input type="hidden" name="date_end" value="<?php echo esc_attr($end_date); ?>"><input type="hidden" name="filter_type" value="<?php echo esc_attr($filter_type); ?>"><input type="hidden" name="ddos_nonce_field" value="<?php echo wp_create_nonce('ddos_export_action'); ?>"><button type="submit" name="ddos_export_csv" value="1" class="button ddos-btn-primary">📥 Exportar CSV</button></form>
            </div>
            <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px;">
                <div style="flex: 2; min-width: 400px;" class="ddos-card"><h3 style="margin-top:0;">🌍 Mapa de Ataques</h3><div id="regions_div" style="width: 100%; height: 300px;"></div></div>
                <div style="flex: 1; min-width: 300px; display:flex; flex-direction:column; gap: 20px;"><div class="ddos-card" style="flex:1; margin-bottom:0;"><h3 style="margin-top:0;">📊 Distribución</h3><canvas id="pieChart" height="150"></canvas></div><div class="ddos-card" style="flex:1; margin-bottom:0;"><h3 style="margin-top:0;">📈 Tendencia</h3><canvas id="lineChart" height="150"></canvas></div></div>
            </div>
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="flex: 2; min-width: 500px;" class="ddos-card"><h3 style="margin-top:0;">📋 Logs Detallados</h3><table class="wp-list-table widefat fixed striped" style="border:none;"><thead><tr><th width="15%">Amenaza</th><th>IP / Origen</th><th>Info</th><th>Fecha</th><th>Acción</th></tr></thead><tbody><?php if($recent_ips): foreach($recent_ips as $ip): $is_bf = (strpos($ip->reason, 'Brute') !== false); $tag = $is_bf ? 'Fuerza Bruta' : 'DDoS'; $cls = $is_bf ? 'tag-bf' : 'tag-ddos'; ?><tr><td><span class="ddos-tag <?php echo $cls; ?>"><?php echo $tag; ?></span></td><td><strong><?php echo esc_html($ip->ip_address); ?></strong><br><span style="color:#666; font-size:11px;"><?php echo esc_html($ip->country_name); ?></span></td><td><span style="font-size:11px;">Intensidad: <strong><?php echo $ip->request_count; ?></strong></span></td><td><?php echo date('d/m H:i', strtotime($ip->blocked_at)); ?></td><td><a href="<?php echo wp_nonce_url(admin_url('options-general.php?page=ddos-shield&action=unblock&id='.$ip->id), 'unblock_ip_'.$ip->id); ?>" style="color: #b32d2e;">Unblock</a></td></tr><?php endforeach; else: echo '<tr><td colspan="5">Sin registros.</td></tr>'; endif; ?></tbody></table></div>
                <div style="flex: 1; min-width: 300px;" class="ddos-card"><h3 style="margin-top:0;">🎨 Personalización & Ajustes</h3><form method="post" action="options.php"><?php settings_fields('ddos_settings_group'); ?><label style="font-weight:bold; color: var(--brand-primary);">Colores de Marca</label><div style="display: flex; gap: 10px; margin-bottom: 15px;"><div><small>Primario</small><br><input type="color" name="ddos_brand_color_primary" value="<?php echo esc_attr($primary_color); ?>"></div><div><small>Secundario</small><br><input type="color" name="ddos_brand_color_secondary" value="<?php echo esc_attr($secondary_color); ?>"></div></div><input type="text" name="ddos_brand_logo_url" value="<?php echo esc_attr($logo_url); ?>" style="width:100%; margin-bottom: 20px;" placeholder="URL del Logo"><hr><label style="font-weight:bold;">Parámetros</label><br><small>Límite DDoS:</small><input type="number" name="ddos_req_limit" value="<?php echo esc_attr(get_option('ddos_req_limit', 60)); ?>" style="width:100%; margin-bottom:5px;"><small>Login Intentos:</small><input type="number" name="bf_max_attempts" value="<?php echo esc_attr(get_option('bf_max_attempts', 5)); ?>" style="width:100%;"><br><br><input type="email" name="ddos_alert_email" value="<?php echo esc_attr(get_option('ddos_alert_email')); ?>" style="width:100%;" placeholder="Email Alertas"><textarea name="ddos_whitelist" rows="2" style="width:100%; margin-top:5px;" placeholder="Whitelist IPs"><?php echo esc_textarea(get_option('ddos_whitelist')); ?></textarea><p class="submit"><input type="submit" class="button ddos-btn-primary" value="Guardar Cambios"></p></form></div>
            </div>
        </div>
        <script>
        google.charts.load('current', {'packages':['geochart']}); google.charts.setOnLoadCallback(drawRegionsMap);
        function drawRegionsMap() { var data = google.visualization.arrayToDataTable(<?php echo json_encode($geo_data); ?>); var options = { colorAxis: {colors: ['<?php echo $secondary_color; ?>', '<?php echo $primary_color; ?>']}, backgroundColor: '#fff', datalessRegionColor: '#f5f5f5', defaultColor: '#f5f5f5', }; var chart = new google.visualization.GeoChart(document.getElementById('regions_div')); chart.draw(data, options); }
        document.addEventListener('DOMContentLoaded', function() { new Chart(document.getElementById('lineChart'), { type: 'line', data: { labels: <?php echo json_encode($lbl_time); ?>, datasets: [{ label: 'Eventos', data: <?php echo json_encode($dat_time); ?>, borderColor: '<?php echo $primary_color; ?>', backgroundColor: '<?php echo $primary_color; ?>20', borderWidth: 2, fill: true, tension: 0.3 }] }, options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } } }); new Chart(document.getElementById('pieChart'), { type: 'doughnut', data: { labels: <?php echo json_encode($lbl_dist); ?>, datasets: [{ data: <?php echo json_encode($dat_dist); ?>, backgroundColor: ['<?php echo $primary_color; ?>', '<?php echo $secondary_color; ?>', '#e5e7eb'] }] }, options: { responsive: true, plugins: { legend: { position: 'right' } } } }); });
        </script>
        <?php
    }
}
new DDoS_Shield_Pro();