<?php
/**
 * Plugin Name: NexifyMy Security
 * Plugin URI:  https://nexifymy.com/security
 * Description: A modern, lightweight, and powerful security plugin for WordPress.
 * Version:     1.0.0
 * Author:      NexifyMy
 * Author URI:  https://nexifymy.com
 * License:     GPL2
 * Text Domain: nexifymy-security
 * Domain Path: /languages
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define constants.
define( 'NEXIFYMY_SECURITY_VERSION', '1.0.0' );
define( 'NEXIFYMY_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'NEXIFYMY_SECURITY_URL', plugin_dir_url( __FILE__ ) );
define( 'NEXIFYMY_SECURITY_FILE', __FILE__ );

/*
 * =============================================================================
 * EARLY EXECUTION - WAF & Rate Limiter must run BEFORE plugins_loaded
 * =============================================================================
 */

// Load Logger early so WAF/Rate Limiter can log immediately.
require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
$GLOBALS['nexifymy_logger'] = new NexifyMy_Security_Logger();

// Load Email Alerts early so WAF events can trigger alerts.
require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-alerts.php';
$GLOBALS['nexifymy_alerts'] = new NexifyMy_Security_Alerts();
if ( empty( $GLOBALS['nexifymy_alerts_initialized'] ) ) {
	$GLOBALS['nexifymy_alerts']->init();
	$GLOBALS['nexifymy_alerts_initialized'] = true;
}

// Load WAF immediately (runs at PHP execution, not waiting for hooks).
require_once NEXIFYMY_SECURITY_PATH . 'modules/firewall.php';
$GLOBALS['nexifymy_waf'] = new NexifyMy_Security_Firewall();
$GLOBALS['nexifymy_waf']->run_firewall(); // Execute immediately!

// Load Rate Limiter for login protection (hooks into authenticate).
require_once NEXIFYMY_SECURITY_PATH . 'modules/rate-limiter.php';
$GLOBALS['nexifymy_rate_limiter'] = new NexifyMy_Security_RateLimiter();
$GLOBALS['nexifymy_rate_limiter']->init();

/*
 * =============================================================================
 * ACTIVATION / DEACTIVATION HOOKS (must be in main file)
 * =============================================================================
 */

register_activation_hook( __FILE__, 'nexifymy_security_activate' );
register_deactivation_hook( __FILE__, 'nexifymy_security_deactivate' );

/**
 * Plugin activation.
 */
function nexifymy_security_activate() {
	// Create database tables.
	require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
	$logger = new NexifyMy_Security_Logger();
	$logger->create_table();

	// Schedule background scans (default: daily).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$bg_scanner = new NexifyMy_Security_Background_Scanner();
	$bg_scanner->schedule_scan( 'daily' );

	// Store activation time.
	update_option( 'nexifymy_security_activated', time() );

	// Flush rewrite rules.
	flush_rewrite_rules();
}

/**
 * Plugin deactivation.
 */
function nexifymy_security_deactivate() {
	// Clear scheduled cron.
	wp_clear_scheduled_hook( 'nexifymy_scheduled_scan' );
	wp_clear_scheduled_hook( 'nexifymy_daily_summary' );
	wp_clear_scheduled_hook( 'nexifymy_log_cleanup' );
	wp_clear_scheduled_hook( 'nexifymy_scheduled_backup' );

	// Flush rewrite rules.
	flush_rewrite_rules();
}

/*
 * =============================================================================
 * CRON SCHEDULES - Must be registered unconditionally
 * =============================================================================
 */

add_filter( 'cron_schedules', 'nexifymy_security_add_cron_schedules' );

/**
 * Add custom cron schedules.
 */
function nexifymy_security_add_cron_schedules( $schedules ) {
	$schedules['weekly'] = array(
		'interval' => WEEK_IN_SECONDS,
		'display'  => __( 'Once Weekly', 'nexifymy-security' ),
	);
	return $schedules;
}

/*
 * =============================================================================
 * I18N - Load translations
 * =============================================================================
 */

add_action( 'init', 'nexifymy_security_load_textdomain' );

/**
 * Load plugin text domain for translations.
 */
function nexifymy_security_load_textdomain() {
	load_plugin_textdomain(
		'nexifymy-security',
		false,
		dirname( plugin_basename( __FILE__ ) ) . '/languages'
	);
}

/*
 * =============================================================================
 * MAIN INITIALIZATION - After WordPress is ready
 * =============================================================================
 */

add_action( 'plugins_loaded', 'nexifymy_security_init' );

/**
 * Initialize the plugin (admin, scanner, logger, background tasks).
 */
function nexifymy_security_init() {
	// Load Logger.
	if ( ! isset( $GLOBALS['nexifymy_logger'] ) || ! ( $GLOBALS['nexifymy_logger'] instanceof NexifyMy_Security_Logger ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
		$GLOBALS['nexifymy_logger'] = new NexifyMy_Security_Logger();
	}
	$GLOBALS['nexifymy_logger']->init();

	// Load Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/scanner.php';
	$GLOBALS['nexifymy_scanner'] = new NexifyMy_Security_Scanner();
	$GLOBALS['nexifymy_scanner']->init();

	// Load Cleanup.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/cleanup.php';
	$GLOBALS['nexifymy_cleanup'] = new NexifyMy_Security_Cleanup();
	$GLOBALS['nexifymy_cleanup']->init();

	// Load Database Security.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/database-security.php';
	$GLOBALS['nexifymy_database'] = new NexifyMy_Security_Database();
	$GLOBALS['nexifymy_database']->init();

	// Load Background Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$GLOBALS['nexifymy_bg_scanner'] = new NexifyMy_Security_Background_Scanner();
	$GLOBALS['nexifymy_bg_scanner']->init();

	// Load Email Alerts.
	if ( ! isset( $GLOBALS['nexifymy_alerts'] ) || ! ( $GLOBALS['nexifymy_alerts'] instanceof NexifyMy_Security_Alerts ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-alerts.php';
		$GLOBALS['nexifymy_alerts'] = new NexifyMy_Security_Alerts();
	}
	if ( empty( $GLOBALS['nexifymy_alerts_initialized'] ) ) {
		$GLOBALS['nexifymy_alerts']->init();
		$GLOBALS['nexifymy_alerts_initialized'] = true;
	}

	// Initialize Admin (only in admin context).
	if ( is_admin() ) {
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-admin.php';
		$GLOBALS['nexifymy_admin'] = new NexifyMy_Security_Admin();
		$GLOBALS['nexifymy_admin']->init();

		// Load Settings.
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-settings.php';
		$GLOBALS['nexifymy_settings'] = new NexifyMy_Security_Settings();
		$GLOBALS['nexifymy_settings']->init();
	}
}
