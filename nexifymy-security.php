<?php
/**
 * Plugin Name: SecureWP360
 * Plugin URI:  https://nexifymy.com/
 * Description: A modern, lightweight, and powerful security plugin for WordPress.
 * Version:     2.1.2
 * Author:      NexifyMy
 * Author URI:  https://nexifymy.com
 * License:     GPL2
 * Text Domain: nexifymy-security
 * Domain Path: /languages
 *
 * DEV NOTES:
 * This is the main plugin file that initializes all modules and handles activation/deactivation.
 * It ensures the WAF and Rate Limiter run as early as possible.
 * Last Updated: 2026-02-06
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// MINIMAL TEST VERSION - All features temporarily disabled for activation testing.
// Once activation succeeds, we will re-enable features one by one.

// Define constants.
define( 'NEXIFYMY_SECURITY_VERSION', '2.1.2' ); // Production release with security enhancements
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
$nexifymy_request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
$nexifymy_request_path = is_string( $nexifymy_request_uri ) ? (string) parse_url( $nexifymy_request_uri, PHP_URL_PATH ) : '';
$nexifymy_skip_early_waf = (
	defined( 'WP_INSTALLING' ) ||
	! function_exists( 'get_option' ) ||
	! function_exists( 'is_admin' ) || // WordPress not loaded yet
	is_admin() || // Skip all admin requests
	( '' !== $nexifymy_request_path && strpos( $nexifymy_request_path, '/wp-admin' ) !== false ) || // Fallback admin check
	( '' !== $nexifymy_request_path && strpos( $nexifymy_request_path, 'wp-login.php' ) !== false ) // Skip login page
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
		$GLOBALS['nexifymy_logger']    = new NexifyMy_Security_Logger();
		$GLOBALS['nexifymy_analytics'] = new NexifyMy_Security_Analytics();

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
		$GLOBALS['nexifymy_rate_limiter_initialized'] = true;
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

	// Set up default settings if they don't exist.
	$existing = get_option( 'nexifymy_security_settings' );
	if ( false === $existing ) {
		$defaults = array(
			'modules'                               => array(
				'waf_enabled'                   => 1,
				'scanner_enabled'               => 1,
				'rate_limiter_enabled'          => 1,
				'login_protection_enabled'      => 0,
				'background_scan_enabled'       => 1,
				'signatures_enabled'            => 1,
				'quarantine_enabled'            => 1,
				'database_enabled'              => 1,
				'cdn_enabled'                   => 1,
				'core_repair_enabled'           => 1,
				'vulnerability_scanner_enabled' => 1,
				'live_traffic_enabled'          => 1,
				'activity_log_enabled'          => 1,
				'hardening_enabled'             => 1,
				'geo_blocking_enabled'          => 0,
				'hide_login_enabled'            => 0,
				'captcha_enabled'               => 1,
				'two_factor_enabled'            => 1,
				'password_enabled'              => 1,
				'self_protection_enabled'       => 1,
				'performance_enabled'           => 1,
				'supply_chain_enabled'          => 1,
				'proactive_enabled'             => 1,
				'predictive_hunting_enabled'    => 1,
				'ai_detection_enabled'          => 1,
				'api_security_enabled'          => 1,
				'graphql_security_enabled'      => 1,
				'passkey_enabled'               => 1,
				'compliance_enabled'            => 1,
				'consent_enabled'               => 1,
				'developer_api_enabled'         => 1,
				'integrations_enabled'          => 1,
				'deception_enabled'             => true,
				'p2p_enabled'                   => false,
				'sandbox_enabled'               => false,
				'sandbox_console_enabled'       => false,
				'temp_permissions_enabled'      => 1,
			),
			'deception_enabled'                     => true,
			'deception_honeytrap_paths'             => "/secret-backup.zip\n/old-admin/",
			'deception_honeytrap_override_defaults' => false,
			'deception_enum_trap'                   => true,
			'deception_enum_block'                  => false,
			'deception_block_all_enum'              => false,
			'p2p_enabled'                           => false,
			'p2p_broadcast_enabled'                 => true,
			'p2p_trust_threshold'                   => 70,
			'sandbox_enabled'                       => false,
			'sandbox_timeout'                       => 5,
			'sandbox_dynamic_analysis'              => false,
			'sandbox_console_enabled'               => false,
			'predictive_threat_hunting'             => array(
				'enabled'               => true,
				'forecast_update'       => 'weekly',
				'simulation_enabled'    => true,
				'simulation_schedule'   => 'monthly',
				'simulation_run_hour'   => 3,
				'probability_threshold' => 25,
			),
			'firewall'                              => array(
				'enabled'         => true,
				'block_bad_bots'  => true,
				'block_fake_bots' => true,
			),
			'rate_limiter'                          => array(
				'enabled'          => true,
				'max_attempts'     => 5,
				'attempt_window'   => 300,
				'lockout_duration' => 1800,
			),
			'notifications'                         => array(
				'enabled' => true,
				'email'   => get_option( 'admin_email' ),
			),
		);
		update_option( 'nexifymy_security_settings', $defaults, false );
	}

	// Flush rewrite rules.
	flush_rewrite_rules();

	// Create database tables.
	require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-logger.php';
	$logger = new NexifyMy_Security_Logger();
	$logger->create_table();

	require_once NEXIFYMY_SECURITY_PATH . 'modules/live-traffic.php';
	NexifyMy_Security_Live_Traffic::create_table();

	// Create Activity Log table.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/user-activity-log.php';
	$activity_log = new NexifyMy_Security_Activity_Log();
	$activity_log->maybe_create_table();

	// Create Temp Permissions table.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/time-bound-permissions.php';
	$temp_perms = new NexifyMy_Security_Temp_Permissions();
	$temp_perms->create_table();

	// Create Supply Chain patch log table.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/supply-chain-security.php';
	$supply_chain = new NexifyMy_Security_Supply_Chain();
	$supply_chain->create_patch_log_table();

	// Create compliance/GDPR report tables.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/compliance-reporting.php';
	$compliance = new NexifyMy_Security_Compliance();
	$compliance->maybe_create_tables();

	// Create predictive threat-hunting tables.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/predictive-threat-hunting.php';
	$predictive_hunting = new NexifyMy_Security_Predictive_Threat_Hunting();
	$predictive_hunting->create_table();

	// Create P2P intelligence credits table.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/p2p-intelligence.php';
	NexifyMy_Security_P2P::create_credits_table();

	// Create consent records table.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/consent-management.php';
	$consent = new NexifyMy_Security_Consent_Management();
	$consent->maybe_create_table();

	// Create AI Threat Detection tables.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/ai-threat-detection.php';
	$ai_detection = new NexifyMy_Security_AI_Threat_Detection();
	$ai_detection->init();
	$ai_detection->create_tables();

	// Schedule background scans (default: daily).
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$bg_scanner = new NexifyMy_Security_Background_Scanner();
	$bg_scanner->schedule_scan( 'daily' );
}


/**
 * Plugin deactivation.
 */
function nexifymy_security_deactivate() {
	// Clear scheduled cron events across all modules.
	$cron_hooks = array(
		'nexifymy_scheduled_scan',
		'nexifymy_daily_summary',
		'nexifymy_log_cleanup',
		'nexifymy_scheduled_backup',
		'nexifymy_p2p_sync',
		'nexifymy_vulnerability_scan',
		'nexifymy_activity_log_cleanup',
		'nexifymy_supply_chain_scan',
		'nexifymy_update_signatures',
		'nexifymy_integrity_check',
		'nexifymy_security_benchmark',
		'nexifymy_auto_patch',
		'nexifymy_traffic_cleanup',
		'nexifymy_generate_report',
		'nexifymy_generate_data_map_report',
		'nexifymy_cleanup_reports',
		'nexifymy_learn_patterns',
		'nexifymy_update_threat_forecast',
		'nexifymy_monthly_attack_simulation',
		'nexifymy_revoke_expired_permissions',
	);
	foreach ( $cron_hooks as $cron_hook ) {
		wp_clear_scheduled_hook( $cron_hook );
	}

	// Allow modules to run their own deactivation cleanup.
	do_action( 'nexifymy_security_deactivate' );

	// Clean up sandbox transients.
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			'_transient_nexifymy_sbx_%',
			'_transient_timeout_nexifymy_sbx_%'
		)
	);
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
	$schedules['weekly']             = array(
		'interval' => WEEK_IN_SECONDS,
		'display'  => __( 'Once Weekly', 'nexifymy-security' ),
	);
	$schedules['monthly']            = array(
		'interval' => MONTH_IN_SECONDS,
		'display'  => __( 'Once Monthly', 'nexifymy-security' ),
	);
	$schedules['every_five_minutes'] = array(
		'interval' => 300,
		'display'  => __( 'Every 5 Minutes', 'nexifymy-security' ),
	);
	return $schedules;
}

/*
 * =============================================================================
 * I18N - Load translations
 * =============================================================================
 */

add_action( 'plugins_loaded', 'nexifymy_security_load_textdomain', 1 );

/**
 * Load plugin text domain for translations.
 */
function nexifymy_security_load_textdomain() {
	// Always register the filter as a safety net for JIT loading.
	add_filter( 'plugin_locale', 'nexifymy_security_plugin_locale', 10, 2 );

	// Check if the user set a custom plugin language.
	$settings    = get_option( 'nexifymy_security_settings', array() );
	$plugin_lang = ! empty( $settings['general']['language'] ) ? $settings['general']['language'] : 'site_default';

	if ( 'site_default' !== $plugin_lang ) {
		// Apply legacy locale mapping.
		$legacy_map = array(
			'tr_TR' => 'tr',
			'uk'    => 'uk_UA',
			'vi'    => 'vi_VN',
			'zh_CN' => 'zh_Hans',
		);
		if ( isset( $legacy_map[ $plugin_lang ] ) ) {
			$plugin_lang = $legacy_map[ $plugin_lang ];
		}

		$resolved = nexifymy_security_resolve_translation_locale( $plugin_lang );
		if ( '' !== $resolved ) {
			// Unload any previously (JIT) loaded textdomain with wrong locale.
			unload_textdomain( 'nexifymy-security' );

			// Load the MO file directly with explicit path.
			$mofile = NEXIFYMY_SECURITY_PATH . 'languages/nexifymy-security-' . $resolved . '.mo';
			if ( file_exists( $mofile ) ) {
				load_textdomain( 'nexifymy-security', $mofile );
				return;
			}
		}
	}

	// Site-default: use standard loading.
	load_plugin_textdomain(
		'nexifymy-security',
		false,
		dirname( plugin_basename( NEXIFYMY_SECURITY_FILE ) ) . '/languages'
	);
}

/**
 * Get available plugin translation locales based on bundled MO files.
 *
 * @return array<string>
 */
function nexifymy_security_get_available_translation_locales() {
	static $locales = null;

	if ( null !== $locales ) {
		return $locales;
	}

	$locales = array();
	$pattern = NEXIFYMY_SECURITY_PATH . 'languages/nexifymy-security-*.mo';
	$files   = glob( $pattern );

	if ( is_array( $files ) ) {
		foreach ( $files as $file ) {
			$base = basename( $file, '.mo' );
			if ( strpos( $base, 'nexifymy-security-' ) === 0 ) {
				$locales[] = substr( $base, strlen( 'nexifymy-security-' ) );
			}
		}
	}

	$locales = array_values( array_unique( array_filter( $locales ) ) );
	return $locales;
}

/**
 * Resolve a locale to the closest bundled translation locale.
 *
 * @param string $locale Requested locale.
 * @return string Resolved locale or empty string when not available.
 */
function nexifymy_security_resolve_translation_locale( $locale ) {
	$locale = sanitize_text_field( (string) $locale );
	if ( '' === $locale ) {
		return '';
	}

	$available = nexifymy_security_get_available_translation_locales();
	if ( empty( $available ) ) {
		return '';
	}

	$available_lc = array();
	foreach ( $available as $item ) {
		$available_lc[ strtolower( $item ) ] = $item;
	}

	$candidates   = array();
	$normalized   = str_replace( '-', '_', $locale );
	$candidates[] = $locale;
	$candidates[] = $normalized;

	$locale_aliases = array(
		'tr_TR'   => 'tr',
		'tr'      => 'tr_TR',
		'uk'      => 'uk_UA',
		'uk_UA'   => 'uk',
		'vi'      => 'vi_VN',
		'vi_VN'   => 'vi',
		'zh_CN'   => 'zh_Hans',
		'zh_Hans' => 'zh_CN',
	);

	if ( isset( $locale_aliases[ $locale ] ) ) {
		$candidates[] = $locale_aliases[ $locale ];
	}
	if ( isset( $locale_aliases[ $normalized ] ) ) {
		$candidates[] = $locale_aliases[ $normalized ];
	}

	$parts = explode( '_', $normalized );
	$lang  = strtolower( $parts[0] ?? '' );
	if ( '' !== $lang ) {
		$candidates[] = $lang;
	}
	if ( count( $parts ) > 1 ) {
		$candidates[] = $lang . '_' . strtoupper( $parts[1] );
	}

	$candidates = array_values( array_unique( array_filter( $candidates ) ) );
	foreach ( $candidates as $candidate ) {
		$key = strtolower( $candidate );
		if ( isset( $available_lc[ $key ] ) ) {
			return $available_lc[ $key ];
		}
	}

	if ( '' !== $lang ) {
		foreach ( $available as $item ) {
			$item_lc = strtolower( $item );
			if ( 0 === strpos( $item_lc, $lang . '_' ) ) {
				return $item;
			}
		}
	}

	return '';
}

/**
 * Filter the plugin locale.
 *
 * @param string $locale The plugin's current locale.
 * @param string $domain Text domain.
 * @return string Modified locale.
 */
function nexifymy_security_plugin_locale( $locale, $domain ) {
	if ( 'nexifymy-security' === $domain ) {
		$settings = get_option( 'nexifymy_security_settings', array() );
		if ( ! empty( $settings['general']['language'] ) && 'site_default' !== $settings['general']['language'] ) {
			$selected           = sanitize_text_field( $settings['general']['language'] );
			$legacy_setting_map = array(
				'tr_TR' => 'tr',
				'uk'    => 'uk_UA',
				'vi'    => 'vi_VN',
				'zh_CN' => 'zh_Hans',
			);
			if ( isset( $legacy_setting_map[ $selected ] ) ) {
				$selected = $legacy_setting_map[ $selected ];
			}

			if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
				$allowed = array_keys( NexifyMy_Security_Settings::get_available_languages() );
				if ( ! in_array( $selected, $allowed, true ) ) {
					return $locale;
				}
			}

			$resolved_selected = nexifymy_security_resolve_translation_locale( $selected );
			if ( '' !== $resolved_selected ) {
				return $resolved_selected;
			}
		}

		// Site-default locale can also be resolved to a closest bundled variant
		// (for example `th_TH` -> `th` when only a short locale file exists).
		$resolved_default = nexifymy_security_resolve_translation_locale( $locale );
		if ( '' !== $resolved_default ) {
			return $resolved_default;
		}
	}
	return $locale;
}

/**
 * Check whether a module is enabled in settings.
 *
 * @param array  $settings Full settings array.
 * @param string $module_option Option key inside settings['modules'].
 * @param bool   $default Default value if key is missing.
 * @return bool
 */
function nexifymy_security_is_module_enabled( $settings, $module_option, $default = true ) {
	if ( ! is_array( $settings ) ) {
		return (bool) $default;
	}

	if ( isset( $settings['modules'] ) && is_array( $settings['modules'] ) && array_key_exists( $module_option, $settings['modules'] ) ) {
		return (bool) $settings['modules'][ $module_option ];
	}

	// Backward compatibility with legacy top-level keys.
	if ( array_key_exists( $module_option, $settings ) ) {
		return (bool) $settings[ $module_option ];
	}

	return (bool) $default;
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
	// Load settings class early so all modules can read centralized settings reliably.
	require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-settings.php';

	$settings = get_option( 'nexifymy_security_settings', array() );

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

	// Load Signature Updater BEFORE scanner (scanner depends on signatures).
	if ( nexifymy_security_is_module_enabled( $settings, 'signatures_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/signature-updater.php';
		$GLOBALS['nexifymy_signatures'] = new NexifyMy_Security_Signature_Updater();
		$GLOBALS['nexifymy_signatures']->init();
	}

	// Ensure rate limiter is initialized when early bootstrap is skipped (for example on wp-login.php).
	if ( nexifymy_security_is_module_enabled( $settings, 'rate_limiter_enabled', true ) && empty( $GLOBALS['nexifymy_rate_limiter_initialized'] ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/rate-limiter.php';
		if ( ! isset( $GLOBALS['nexifymy_rate_limiter'] ) || ! ( $GLOBALS['nexifymy_rate_limiter'] instanceof NexifyMy_Security_RateLimiter ) ) {
			$GLOBALS['nexifymy_rate_limiter'] = new NexifyMy_Security_RateLimiter();
		}
		$GLOBALS['nexifymy_rate_limiter']->init();
		$GLOBALS['nexifymy_rate_limiter_initialized'] = true;
	}

	// Load Scanner (uses signatures from above).
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
	if ( nexifymy_security_is_module_enabled( $settings, 'database_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/database-security.php';
		$GLOBALS['nexifymy_database'] = new NexifyMy_Security_Database();
		$GLOBALS['nexifymy_database']->init();
	}

	// Load Live Traffic Monitoring.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/live-traffic.php';
	$GLOBALS['nexifymy_live_traffic'] = new NexifyMy_Security_Live_Traffic();
	$GLOBALS['nexifymy_live_traffic']->init();

	// Load User Activity Log.
	if ( nexifymy_security_is_module_enabled( $settings, 'activity_log_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/user-activity-log.php';
		$GLOBALS['nexifymy_activity_log'] = new NexifyMy_Security_Activity_Log();
		$GLOBALS['nexifymy_activity_log']->init();
	}

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
	if ( nexifymy_security_is_module_enabled( $settings, 'cdn_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/cdn-integration.php';
		$GLOBALS['nexifymy_cdn'] = new NexifyMy_Security_CDN();
		$GLOBALS['nexifymy_cdn']->init();
	}

	// Load Core Repair.
	if ( nexifymy_security_is_module_enabled( $settings, 'core_repair_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/core-repair.php';
		$GLOBALS['nexifymy_core_repair'] = new NexifyMy_Security_Core_Repair();
		$GLOBALS['nexifymy_core_repair']->init();
	}

	// Load Performance Optimizer (for caching and throttling).
	if ( nexifymy_security_is_module_enabled( $settings, 'performance_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/performance-optimizer.php';
		$GLOBALS['nexifymy_performance'] = new NexifyMy_Security_Performance();
		$GLOBALS['nexifymy_performance']->init();
	}

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
	if ( nexifymy_security_is_module_enabled( $settings, 'vulnerability_scanner_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/vulnerability-scanner.php';
		$GLOBALS['nexifymy_vuln_scanner'] = new NexifyMy_Security_Vulnerability_Scanner();
		$GLOBALS['nexifymy_vuln_scanner']->init();
	}

	// Load Login Captcha.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/login-captcha.php';
	$GLOBALS['nexifymy_captcha'] = new NexifyMy_Security_Login_Captcha();
	$GLOBALS['nexifymy_captcha']->init();

	// Load Background Scanner.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/background-scanner.php';
	$GLOBALS['nexifymy_bg_scanner'] = new NexifyMy_Security_Background_Scanner();
	$GLOBALS['nexifymy_bg_scanner']->init();

	// Load Supply Chain Security.
	if ( nexifymy_security_is_module_enabled( $settings, 'supply_chain_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/supply-chain-security.php';
		$GLOBALS['nexifymy_supply_chain'] = new NexifyMy_Security_Supply_Chain();
		$GLOBALS['nexifymy_supply_chain']->init();
	}

	// Load Proactive Security.
	if ( nexifymy_security_is_module_enabled( $settings, 'proactive_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/proactive-security.php';
		$GLOBALS['nexifymy_proactive'] = new NexifyMy_Security_Proactive();
		$GLOBALS['nexifymy_proactive']->init();
	}

	// Load Predictive Threat Hunting.
	if ( nexifymy_security_is_module_enabled( $settings, 'predictive_hunting_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/predictive-threat-hunting.php';
		$GLOBALS['nexifymy_predictive_hunting'] = new NexifyMy_Security_Predictive_Threat_Hunting();
		$GLOBALS['nexifymy_predictive_hunting']->init();
	}

	// Load AI Threat Detection.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/ai-threat-detection.php';
	$GLOBALS['nexifymy_ai_detection'] = new NexifyMy_Security_AI_Threat_Detection();
	$GLOBALS['nexifymy_ai_detection']->init();
	// Back-compat alias for older references.
	$GLOBALS['nexifymy_ai_threat'] = $GLOBALS['nexifymy_ai_detection'];

	// Load Passkey/WebAuthn Authentication.
	if ( nexifymy_security_is_module_enabled( $settings, 'passkey_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/passkey-auth.php';
		$GLOBALS['nexifymy_passkey'] = new NexifyMy_Security_Passkey();
		$GLOBALS['nexifymy_passkey']->init();
	}

	// Load Compliance & Reporting.
	if ( nexifymy_security_is_module_enabled( $settings, 'compliance_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/compliance-reporting.php';
		$GLOBALS['nexifymy_compliance'] = new NexifyMy_Security_Compliance();
		$GLOBALS['nexifymy_compliance']->init();
	}

	// Load Consent Management.
	if ( nexifymy_security_is_module_enabled( $settings, 'consent_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/consent-management.php';
		$GLOBALS['nexifymy_consent'] = new NexifyMy_Security_Consent_Management();
		$GLOBALS['nexifymy_consent']->init();
	}

	// Load Developer API.
	if ( nexifymy_security_is_module_enabled( $settings, 'developer_api_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/developer-api.php';
		$GLOBALS['nexifymy_dev_api'] = new NexifyMy_Security_Developer_API();
		$GLOBALS['nexifymy_dev_api']->init();
	}

	// Load Integrations (Slack, Discord, Teams, SIEM, Jira).
	if ( nexifymy_security_is_module_enabled( $settings, 'integrations_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/integrations.php';
		$GLOBALS['nexifymy_integrations'] = new NexifyMy_Security_Integrations();
		$GLOBALS['nexifymy_integrations']->init();
	}

	// Load Advanced API Security (REST API, JWT, headless WordPress).
	if ( nexifymy_security_is_module_enabled( $settings, 'api_security_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/api-security.php';
		$GLOBALS['nexifymy_api_security'] = new NexifyMy_Security_API_Security();
		$GLOBALS['nexifymy_api_security']->init();
	}

	// Load GraphQL Security (WPGraphQL protection).
	if ( nexifymy_security_is_module_enabled( $settings, 'graphql_security_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/graphql-security.php';
		$GLOBALS['nexifymy_graphql_security'] = new NexifyMy_Security_GraphQL_Security();
		$GLOBALS['nexifymy_graphql_security']->init();
	}

	// Load Deception Technology (Honeypots 2.0).
	if ( nexifymy_security_is_module_enabled( $settings, 'deception_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/deception.php';
		$GLOBALS['nexifymy_deception'] = new NexifyMy_Security_Deception();
		$GLOBALS['nexifymy_deception']->init();
	}

	// Always load the P2P class so the admin page can render settings/UI.
	require_once NEXIFYMY_SECURITY_PATH . 'modules/p2p-intelligence.php';

	// Only initialize runtime hooks when the module is enabled.
	if ( nexifymy_security_is_module_enabled( $settings, 'p2p_enabled', false ) ) {
		NexifyMy_Security_P2P::init();
	}

	// Load Shadow Runtime Sandbox.
	if ( nexifymy_security_is_module_enabled( $settings, 'sandbox_enabled', false ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/sandbox.php';
		NexifyMy_Security_Sandbox::init();
	}

	// Load Time-Bound Permissions.
	if ( nexifymy_security_is_module_enabled( $settings, 'temp_permissions_enabled', true ) ) {
		require_once NEXIFYMY_SECURITY_PATH . 'modules/time-bound-permissions.php';
		$GLOBALS['nexifymy_temp_permissions'] = new NexifyMy_Security_Temp_Permissions();
		$GLOBALS['nexifymy_temp_permissions']->init();
	}

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

		// Register AJAX hooks for admin functionality
		$GLOBALS['nexifymy_admin']->register_ajax_hooks();
		$GLOBALS['nexifymy_admin']->init();

		// Load Settings hooks/AJAX handlers in admin context.
		$GLOBALS['nexifymy_settings'] = new NexifyMy_Security_Settings();
		$GLOBALS['nexifymy_settings']->init();
	}
}

