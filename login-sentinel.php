<?php
/*
Plugin Name: Login Sentinel
Plugin URI: https://interintender.com/
Description: A lightweight watchdog that monitors and alerts for unusual login behavior like IP changes and odd hours.
Version: 1.0.0
Author: Amal P
Author URI: https://www.interintender.com
License: GPLv2 or later
Text Domain: login-sentinel
*/

defined('ABSPATH') or die('No script kiddies please!');

// Hook into successful login event
add_action('wp_login', 'login_sentinel_monitor_login', 10, 2);

function login_sentinel_monitor_login($user_login, $user) {
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $login_time = current_time('mysql');

    $log_entry = sprintf(
        "[%s] User '%s' logged in from IP: %s | Browser: %s\n",
        $login_time,
        $user_login,
        $ip_address,
        $user_agent
    );

    // Create plugin log directory if not exists
    $log_dir = plugin_dir_path(__FILE__) . 'logs/';
    if (!file_exists($log_dir)) {
        mkdir($log_dir, 0755, true);
    }

    // Append log entry to a file
    $log_file = $log_dir . 'login-log.txt';
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

add_action('wp_login', 'login_sentinel_check_ip_change', 20, 2);

function login_sentinel_check_ip_change($user_login, $user) {

    

    $current_ip = $_SERVER['REMOTE_ADDR'];
    $user_id = $user->ID;

    // Get last IP stored in user meta
    $last_ip = get_user_meta($user_id, '_login_sentinel_last_ip', true);

    // Update current IP as new known IP
    update_user_meta($user_id, '_login_sentinel_last_ip', $current_ip);

    // If no previous IP, skip comparison
    if (!$last_ip) return;

    // If IP changed, log it as suspicious
    if ($last_ip !== $current_ip) {
        $login_time = current_time('mysql');
        $log_entry = sprintf(
            "[%s] ⚠️ Suspicious Login: User '%s' logged in from NEW IP: %s (Old IP: %s)\n",
            $login_time,
            $user_login,
            $current_ip,
            $last_ip
        );

        $log_dir = plugin_dir_path(__FILE__) . 'logs/';
        if (!file_exists($log_dir)) {
            mkdir($log_dir, 0755, true);
        }

        if (get_option('login_sentinel_enable_logging')) {
            file_put_contents($log_dir . 'suspicious-logins.txt', $log_entry, FILE_APPEND);
        }

        // Send alert email to site admin
        $admin_email = get_option('admin_email');  // fetches admin email set in WordPress
        $subject = '⚠️ Suspicious Login Detected on Your Site';
        $message = "A suspicious login was detected on your WordPress site:\n\n"
            . "🧑 Username: $user_login\n"
            . "🌐 New IP: $current_ip\n"
            . "📍 Previous IP: $last_ip\n"
            . "⏰ Time: $login_time\n\n"
            . "Please verify if this login was expected.\n\n"
            . "– Login Sentinel";
        if (get_option('login_sentinel_enable_email')) {
            wp_mail($admin_email, $subject, $message);
        }
    }
}


register_activation_hook(__FILE__, 'login_sentinel_setup_logs');

function login_sentinel_setup_logs() {
    $log_dir = plugin_dir_path(__FILE__) . 'logs/';

    // If logs directory doesn't exist, try to create it
    if (!file_exists($log_dir)) {
        if (!mkdir($log_dir, 0755, true)) {
            error_log("Login Sentinel: ❌ Failed to create logs directory. Please check folder permissions.");
        }
    }

    // Create empty log files if they don’t exist
    $login_log = $log_dir . 'login-log.txt';
    $suspicious_log = $log_dir . 'suspicious-logins.txt';

    if (!file_exists($login_log)) {
        file_put_contents($login_log, "== Login Log Initialized ==\n");
    }

    if (!file_exists($suspicious_log)) {
        file_put_contents($suspicious_log, "== Suspicious Login Log Initialized ==\n");
    }
}


add_action('admin_menu', 'login_sentinel_add_settings_page');

function login_sentinel_add_settings_page() {
    add_options_page(
        'Login Sentinel Settings',
        'Login Sentinel',
        'manage_options',
        'login-sentinel-settings',
        'login_sentinel_render_settings_page'
    );
}

add_action('admin_init', 'login_sentinel_register_settings');

function login_sentinel_register_settings() {
    register_setting('login_sentinel_settings_group', 'login_sentinel_enable_email', 'sanitize_text_field');
    register_setting('login_sentinel_settings_group', 'login_sentinel_enable_logging', 'sanitize_text_field');

}

function login_sentinel_render_settings_page() {
    ?>
    <div class="wrap">
        <h1>Login Sentinel Settings</h1>
        <form method="post" action="options.php">
            <?php settings_fields('login_sentinel_settings_group'); ?>
            <?php do_settings_sections('login_sentinel_settings_group'); ?>

            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Enable Email Alerts</th>
                    <td><input type="checkbox" name="login_sentinel_enable_email" value="1" <?php checked(1, get_option('login_sentinel_enable_email'), true); ?> /></td>
                </tr>

                <tr valign="top">
                    <th scope="row">Enable File Logging</th>
                    <td><input type="checkbox" name="login_sentinel_enable_logging" value="1" <?php checked(1, get_option('login_sentinel_enable_logging'), true); ?> /></td>
                </tr>
            </table>

            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

add_action('wp_dashboard_setup', 'login_sentinel_register_dashboard_widget');

function login_sentinel_register_dashboard_widget() {
    wp_add_dashboard_widget(
        'login_sentinel_dashboard_widget',
        'Login Sentinel – Suspicious Activity',
        'login_sentinel_display_dashboard_widget'
    );
}

function login_sentinel_display_dashboard_widget() {
    $log_file = plugin_dir_path(__FILE__) . 'logs/suspicious-logins.txt';

    if (!file_exists($log_file)) {
        echo "<p>No suspicious login activity recorded yet.</p>";
        return;
    }

    $log_entries = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $total = count($log_entries);
    $last = $total > 0 ? $log_entries[$total - 1] : 'No recent entries';

    echo "<p><strong>Total Suspicious Logins:</strong> $total</p>";
    echo "<p><strong>Last Suspicious Login:</strong><br><code>" . esc_html($last) . "</code></p>";

    echo '<p><a href="' . esc_url(admin_url('plugins.php')) . '">Manage Login Sentinel</a></p>';
}



