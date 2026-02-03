<?php
/**
 * Plugin Name: NexifyMy Security
 * Plugin URI:  https://nexifymy.com/
 * Description: A modern, lightweight, and powerful security plugin for WordPress.
 * Version:     2.0.5
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

// MINIMAL TEST VERSION - All features temporarily disabled for activation testing.
// Once activation succeeds, we will re-enable features one by one.

// Define constants.
define( 'NEXIFYMY_SECURITY_VERSION', '2.0.5' ); // Production release with security enhancements
define( 'NEXIFYMY_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'NEXIFYMY_SECURITY_URL', plugin_dir_url( __FILE__ ) );
define( 'NEXIFYMY_SECURITY_FILE', __FILE__ );

/*
 * =============================================================================
 * EARLY EXECUTION - WAF & Rate Limiter must run BEFORE plugins_loaded
 * =============================================================================
 */

// Safety check: Skip early WAF execution during plugin activation/deactivation.
// WordPress may not be fully loaded yet when uploading/activating via ZIP.
// Also check if core WordPress functions are available.
// Skip in admin area entirely - WAF/Rate Limiter are for frontend protection.
$nexifymy_skip_early_waf = (
	defined( 'WP_INSTALLING' ) ||
	! function_exists( 'get_option' ) ||
	! function_exists( 'is_admin' ) ||  // WordPress not loaded yet
	is_admin() ||  // Skip all admin requests
	( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], '/wp-admin' ) !== false ) ||  // Fallback admin check
	( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) ||  // Skip login page
	( isset( $_REQUEST['action'] ) && in_array( $_REQUEST['action'], array( 'activate', 'deactivate', 'upload-plugin', 'install-plugin' ), true ) ) ||
	( isset( $_REQUEST['plugin'] ) && strpos( $_REQUEST['plugin'], 'nexifymy-security' ) !== false && isset( $_REQUEST['action'] ) )
);

if ( ! $nexifymy_skip_early_waf ) {
	// Verify all required files exist before loading
	$required_files = array(
		NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php',
		NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-analytics.php',
		NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-alerts.php',
		NEXIFYMY_SECURITY_PATH . 'modules/firewall.php',
		NEXIFYMY_SECURITY_PATH . 'modules/rate-limiter.php',
	);

	$all_files_exist = true;
	foreach ( $required_files as $file ) {
		if ( ! file_exists( $file ) ) {
			$all_files_exist = false;
			break;
		}
	}

	if ( $all_files_exist ) {
		// Load Logger early so WAF/Rate Limiter can log immediately.
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-analytics.php';

		// Initialize Modules
		$GLOBALS['nexifymy_logger']     = new NexifyMy_Security_Logger();
		$GLOBALS['nexifymy_analytics']  = new NexifyMy_Security_Analytics();

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
	}
}

/*
 * =============================================================================
 * ACTIVATION / DEACTIVATION HOOKS (must be in main file)
 * =============================================================================
 */
function nexifymy_security_activate() {
	// Store activation time first (minimal operation).
	update_option( 'nexifymy_security_activated', time() );

	// Flush rewrite rules.
	flush_rewrite_rules();

	// Create database tables.
	require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
	$logger = new NexifyMy_Security_Logger();
	$logger->create_table();

	require_once NEXIFYMY_SECURITY_PATH . 'modules/live-traffic.php';
	NexifyMy_Security_Live_Traffic::create_table();

	// Schedule background scans (default: daily).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$bg_scanner = new NexifyMy_Security_Background_Scanner();
	$bg_scanner->schedule_scan( 'daily' );
}

/**
 * Plugin deactivation.
 */
function nexifymy_security_deactivate() {
	// Clear scheduled cron events if any exist.
	wp_clear_scheduled_hook( 'nexifymy_scheduled_scan' );
	wp_clear_scheduled_hook( 'nexifymy_daily_summary' );
	wp_clear_scheduled_hook( 'nexifymy_log_cleanup' );
	wp_clear_scheduled_hook( 'nexifymy_scheduled_backup' );
}

register_activation_hook( __FILE__, 'nexifymy_security_activate' );
register_deactivation_hook( __FILE__, 'nexifymy_security_deactivate' );

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

// Hook into plugins_loaded to initialize core functionality.
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

	// Load Notifications (admin alerts sourced from logs).
	require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-notifications.php';
	$GLOBALS['nexifymy_notifications'] = new NexifyMy_Security_Notifications();
	$GLOBALS['nexifymy_notifications']->init();

	// Load Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/scanner.php';
	$GLOBALS['nexifymy_scanner'] = new NexifyMy_Security_Scanner();
	$GLOBALS['nexifymy_scanner']->init();

	// Load Quarantine.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/quarantine.php';
	$GLOBALS['nexifymy_quarantine'] = new NexifyMy_Security_Quarantine();
	$GLOBALS['nexifymy_quarantine']->init();

	// Load Cleanup.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/cleanup.php';
	$GLOBALS['nexifymy_cleanup'] = new NexifyMy_Security_Cleanup();
	$GLOBALS['nexifymy_cleanup']->init();

	// Load Database Security.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/database-security.php';
	$GLOBALS['nexifymy_database'] = new NexifyMy_Security_Database();
	$GLOBALS['nexifymy_database']->init();

	// Load Live Traffic Monitoring.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/live-traffic.php';
	$GLOBALS['nexifymy_live_traffic'] = new NexifyMy_Security_Live_Traffic();
	$GLOBALS['nexifymy_live_traffic']->init();

	// Load Geo Blocking.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/geo-blocking.php';
	$GLOBALS['nexifymy_geo_blocking'] = new NexifyMy_Security_Geo_Blocking();
	$GLOBALS['nexifymy_geo_blocking']->init();

	// Load Security Hardening.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/hardening.php';
	$GLOBALS['nexifymy_hardening'] = new NexifyMy_Security_Hardening();
	$GLOBALS['nexifymy_hardening']->init();

	// Load Password Security.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/password-security.php';
	$GLOBALS['nexifymy_password'] = new NexifyMy_Security_Password();
	$GLOBALS['nexifymy_password']->init();

	// Load CDN Integration.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/cdn-integration.php';
	$GLOBALS['nexifymy_cdn'] = new NexifyMy_Security_CDN();
	$GLOBALS['nexifymy_cdn']->init();

	// Load Core Repair.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/core-repair.php';
	$GLOBALS['nexifymy_core_repair'] = new NexifyMy_Security_Core_Repair();
	$GLOBALS['nexifymy_core_repair']->init();

	// Load Signature Updater (before scanner).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/signature-updater.php';
	$GLOBALS['nexifymy_signatures'] = new NexifyMy_Security_Signature_Updater();
	$GLOBALS['nexifymy_signatures']->init();

	// Load Performance Optimizer (for caching and throttling).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/performance-optimizer.php';
	$GLOBALS['nexifymy_performance'] = new NexifyMy_Security_Performance();
	$GLOBALS['nexifymy_performance']->init();

	// Load Self-Protection (must load early).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/self-protection.php';
	$GLOBALS['nexifymy_self_protection'] = new NexifyMy_Security_Self_Protection();
	$GLOBALS['nexifymy_self_protection']->init();

	// Load Two-Factor Authentication.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/two-factor-auth.php';
	$GLOBALS['nexifymy_2fa'] = new NexifyMy_Security_Two_Factor();
	$GLOBALS['nexifymy_2fa']->init();

	// Load Hide Login URL.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/hide-login.php';
	$GLOBALS['nexifymy_hide_login'] = new NexifyMy_Security_Hide_Login();
	$GLOBALS['nexifymy_hide_login']->init();

	// Load Vulnerability Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/vulnerability-scanner.php';
	$GLOBALS['nexifymy_vuln_scanner'] = new NexifyMy_Security_Vulnerability_Scanner();
	$GLOBALS['nexifymy_vuln_scanner']->init();

	// Load Login Captcha.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/login-captcha.php';
	$GLOBALS['nexifymy_captcha'] = new NexifyMy_Security_Login_Captcha();
	$GLOBALS['nexifymy_captcha']->init();

	// Load Background Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$GLOBALS['nexifymy_bg_scanner'] = new NexifyMy_Security_Background_Scanner();
	$GLOBALS['nexifymy_bg_scanner']->init();

	// Load Supply Chain Security.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/supply-chain-security.php';
	$GLOBALS['nexifymy_supply_chain'] = new NexifyMy_Security_Supply_Chain();
	$GLOBALS['nexifymy_supply_chain']->init();

	// Load Proactive Security.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/proactive-security.php';
	$GLOBALS['nexifymy_proactive'] = new NexifyMy_Security_Proactive();
	$GLOBALS['nexifymy_proactive']->init();

	// Load AI Threat Detection.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/ai-threat-detection.php';
	$GLOBALS['nexifymy_ai_detection'] = new NexifyMy_Security_AI_Threat_Detection();
	$GLOBALS['nexifymy_ai_detection']->init();

	// Load Passkey/WebAuthn Authentication.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/passkey-auth.php';
	$GLOBALS['nexifymy_passkey'] = new NexifyMy_Security_Passkey();
	$GLOBALS['nexifymy_passkey']->init();

	// Load Compliance & Reporting.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/compliance-reporting.php';
	$GLOBALS['nexifymy_compliance'] = new NexifyMy_Security_Compliance();
	$GLOBALS['nexifymy_compliance']->init();

	// Load Developer API.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/developer-api.php';
	$GLOBALS['nexifymy_dev_api'] = new NexifyMy_Security_Developer_API();
	$GLOBALS['nexifymy_dev_api']->init();

	// Load Integrations (Slack, Discord, Teams, SIEM, Jira).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/integrations.php';
	$GLOBALS['nexifymy_integrations'] = new NexifyMy_Security_Integrations();
	$GLOBALS['nexifymy_integrations']->init();

	// Load Advanced API Security (REST API, JWT, headless WordPress).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/api-security.php';
	$GLOBALS['nexifymy_api_security'] = new NexifyMy_Security_API_Security();
	$GLOBALS['nexifymy_api_security']->init();

	// Load GraphQL Security (WPGraphQL protection).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/graphql-security.php';
	$GLOBALS['nexifymy_graphql_security'] = new NexifyMy_Security_GraphQL_Security();
	$GLOBALS['nexifymy_graphql_security']->init();

	// Load WP-CLI Commands (DevOps integration).
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-cli.php';
	}

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
