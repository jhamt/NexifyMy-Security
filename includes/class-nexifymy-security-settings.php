<?php
/**
 * Settings Module.
 *
 * Provides centralized configuration for all security features.
 *
 * @package NexifyMy_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings class.
 *
 * Centralized settings management for all security features.
 */
class NexifyMy_Security_Settings {

	/**
	 * Option key for plugin settings.
	 */
	const OPTION_KEY = 'nexifymy_security_settings';

	/**
	 * Default settings.
	 *
	 * @var array<string, mixed>
	 */
	private static $defaults = array(
		// Module Toggles.
		'modules'                               => array(
			'waf_enabled'                   => true,
			'scanner_enabled'               => true,
			'rate_limiter_enabled'          => true,
			'login_protection_enabled'      => false,
			'background_scan_enabled'       => true,
			'signatures_enabled'            => true,
			'hardening_enabled'             => true,
			'geo_blocking_enabled'          => false,
			'hide_login_enabled'            => false,
			'live_traffic_enabled'          => true,
			'activity_log_enabled'          => true,
			'captcha_enabled'               => true,
			'two_factor_enabled'            => true,
			'password_enabled'              => true,
			'self_protection_enabled'       => true,
			'integrations_enabled'          => true,
			'quarantine_enabled'            => true,
			'database_enabled'              => true,
			'cdn_enabled'                   => true,
			'performance_enabled'           => true,
			'core_repair_enabled'           => true,
			'vulnerability_scanner_enabled' => true,
			'supply_chain_enabled'          => true,
			'proactive_enabled'             => true,
			'predictive_hunting_enabled'    => true,
			'ai_detection_enabled'          => true,
			'api_security_enabled'          => true,
			'graphql_security_enabled'      => true,
			'passkey_enabled'               => true,
			'compliance_enabled'            => true,
			'consent_enabled'               => true,
			'developer_api_enabled'         => true,
			'deception_enabled'             => true,
			'p2p_enabled'                   => false,
			'sandbox_enabled'               => false,
			'sandbox_console_enabled'       => false,
			'temp_permissions_enabled'      => true,
		),

		// General Settings.
		'general'                               => array(
			'language'            => 'site_default',
			'email_notifications' => true,
			'email_address'       => '', // Defaults to admin_email if empty
			'auto_updates'        => true,
		),

		// WAF Settings.
		'waf'                                   => array(
			'block_sqli'     => true,
			'block_xss'      => true,
			'block_lfi'      => true,
			'block_bad_bots' => true,
			'log_only_mode'  => false, // If true, log but don't block.
		),

		// Rate Limiter Settings.
		'rate_limiter'                          => array(
			'max_attempts'     => 5,
			'lockout_duration' => 900,  // 15 minutes.
			'attempt_window'   => 300,  // 5 minutes.
		),

		// Scanner Settings.
		'scanner'                               => array(
			'default_mode'            => 'standard',
			'max_file_size_kb'        => 2048,  // 2MB.
			'excluded_paths'          => array(),
			'excluded_extensions'     => array( 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip' ),
			'quarantine_mode'         => 'manual',
			'auto_quarantine_enabled' => false,
		),

		// IP Settings.
		'ip'                                    => array(
			'whitelist'       => array(),
			'trusted_proxies' => array(),
		),

		// Logging Settings.
		'logging'                               => array(
			'retention_days'     => 30,
			'log_waf_blocks'     => true,
			'log_login_attempts' => true,
			'log_scans'          => true,
		),

		// Background Scan Settings.
		'background_scan'                       => array(
			'schedule'  => 'daily',
			'scan_mode' => 'standard',
		),

		// Database Security Settings.
		'database'                              => array(
			'backup_enabled'     => true,
			'backup_schedule'    => 'weekly',
			'max_backups'        => 5,
			'include_transients' => false,
			'auto_optimize'      => false,
		),

		// Performance Optimizer Settings.
		'performance'                           => array(
			'enabled'             => true,
			'smart_caching'       => true,
			'cache_ttl'           => 3600,
			'throttle_scans'      => true,
			'max_scan_time'       => 30,
			'max_memory_percent'  => 50,
			'defer_heavy_tasks'   => true,
			'off_peak_start'      => 2,
			'off_peak_end'        => 6,
			'lazy_load_modules'   => true,
			'optimize_db_queries' => true,
		),

		// Core Repair Settings.
		'core_repair'                           => array(
			'enabled'       => true,
			'backup_before' => true,
			'notify_admin'  => true,
		),

		// Supply Chain Security Settings.
		'supply_chain'                          => array(
			'enabled'                  => true,
			'scan_plugins'             => true,
			'scan_themes'              => true,
			'scan_composer'            => true,
			'scan_npm'                 => true,
			'monitor_external_scripts' => true,
			'verify_cdn_integrity'     => true,
			'auto_scan_schedule'       => 'weekly',
			'notify_on_issues'         => true,
		),

		// Proactive Security Settings.
		'proactive'                             => array(
			'enabled'              => true,
			'auto_recommendations' => true,
			'auto_patch_plugins'   => false,
			'auto_patch_themes'    => false,
			'auto_patch_core'      => false,
			'patch_schedule'       => 'daily',
			'notify_before_patch'  => true,
			'keep_backups'         => 5,
			'benchmark_schedule'   => 'weekly',
		),

		// Predictive Threat Hunting settings.
		'predictive_threat_hunting'             => array(
			'enabled'               => true,
			'forecast_update'       => 'weekly',
			'simulation_enabled'    => true,
			'simulation_schedule'   => 'monthly',
			'simulation_run_hour'   => 3,
			'probability_threshold' => 25,
		),

		// AI Threat Detection Settings.
		'ai_detection'                          => array(
			'enabled'                    => true,
			'learning_mode'              => true,
			'learning_period_days'       => 7,
			'anomaly_threshold'          => 75,
			'auto_block_threshold'       => 90,
			'track_login_behavior'       => true,
			'track_request_patterns'     => true,
			'track_user_agents'          => true,
			'track_geo_patterns'         => true,
			'notify_on_anomaly'          => true,
			'session_risk_threshold'     => 60,
			'zero_trust_reauth_interval' => 900,
			'zero_trust_risk_spike_threshold' => 20,
			'insider_threat_enabled'     => true,
			'insider_threat_threshold'   => 60,
			'data_exfiltration_enabled'  => true,
			'exfiltration_threshold'     => 60,
			'exfiltration_baseline_days' => 30,
		),

		// Passkey/WebAuthn Settings.
		'passkey'                               => array(
			'enabled'              => true,
			'allow_passwordless'   => true,
			'require_for_admins'   => false,
			'auto_prompt_register' => true,
			'credential_timeout'   => 60000,
			'authenticator_type'   => 'platform',
			'user_verification'    => 'preferred',
		),

		// Compliance & Reporting Settings.
		'compliance'                            => array(
			'enabled'             => true,
			'auto_generate'       => true,
			'schedule'            => 'weekly',
			'email_reports'       => true,
			'include_gdpr'        => true,
			'include_security'    => true,
			'include_performance' => true,
			'include_threats'     => true,
			'report_format'       => 'html',
			'retention_days'      => 90,
		),

		// Consent Management Settings.
		'consent'                               => array(
			'enabled'              => true,
			'banner_enabled'       => true,
			'preference_page_slug' => 'privacy-preferences',
		),

		// Developer API Settings.
		'developer_api'                         => array(
			'enabled'                  => true,
			'rest_api_enabled'         => true,
			'graphql_protection'       => true,
			'webhooks_enabled'         => true,
			'require_api_key'          => true,
			'rate_limit_api'           => 100,
			'log_api_requests'         => true,
			'graphql_depth_limit'      => 10,
			'graphql_complexity_limit' => 500,
		),

		// Signature Updater Settings.
		'signatures'                            => array(
			'enabled'         => true,
			'auto_update'     => true,
			'update_interval' => 'daily',
		),

		// Security Hardening Settings.
		'hardening'                             => array(
			'disable_xmlrpc'      => true,
			'hide_wp_version'     => true,
			'disable_file_editor' => true,
			'security_headers'    => true,
			'disable_rest_api'    => false,
			'disable_rss'         => false,
			'remove_rsd_link'     => true,
			'remove_wlwmanifest'  => true,
			'remove_shortlink'    => true,
			'disable_embeds'      => false,
			'disable_pingback'    => true,
		),

		// Geo Blocking Settings.
		'geo_blocking'                          => array(
			'enabled'       => false,
			'mode'          => 'blacklist',
			'countries'     => array(),
			'block_message' => 'Access denied from your region.',
			'log_blocked'   => true,
		),

		// Hide Login Settings.
		'hide_login'                            => array(
			'enabled'       => false,
			'login_slug'    => 'secure-login',
			'redirect_slug' => '404',
			'redirect_url'  => '',
		),

		// Live Traffic Settings.
		'live_traffic'                          => array(
			'enabled'         => true,
			'log_admin'       => false,
			'log_ajax'        => false,
			'log_cron'        => false,
			'retention_hours' => 24,
			'exclude_ips'     => array(),
			'exclude_urls'    => array(),
		),

		// Captcha Settings.
		'captcha'                               => array(
			'enabled'             => true,
			'enable_login'        => true,
			'enable_registration' => true,
			'enable_reset'        => true,
			'enable_comment'      => false,
			'difficulty'          => 'easy',
			'failed_threshold'    => 3,
		),

		// Two-Factor Authentication Settings.
		'two_factor'                            => array(
			'enabled'       => true,
			'force_admin'   => false,
			'force_all'     => false,
			'email_backup'  => true,
			'remember_days' => 30,
		),

		// Integrations Settings.
		'integrations'                          => array(
			'enabled'                      => true,
			'slack_enabled'                => false,
			'slack_webhook_url'            => '',
			'slack_channel'                => '#security',
			'slack_events'                 => array( 'threat_detected', 'malware_found', 'login_failed' ),
			'discord_enabled'              => false,
			'discord_webhook_url'          => '',
			'discord_events'               => array( 'threat_detected', 'malware_found' ),
			'teams_enabled'                => false,
			'teams_webhook_url'            => '',
			'teams_events'                 => array( 'threat_detected', 'scan_completed' ),
			'siem_enabled'                 => false,
			'siem_type'                    => 'splunk',
			'siem_endpoint'                => '',
			'siem_token'                   => '',
			'siem_index'                   => 'wordpress_security',
			'siem_format'                  => 'json',
			'siem_ssl_verify'              => false,
			'siem_events'                  => array( 'all' ),
			'jira_enabled'                 => false,
			'jira_url'                     => '',
			'jira_email'                   => '',
			'jira_api_token'               => '',
			'jira_project_key'             => '',
			'jira_issue_type'              => 'Bug',
			'jira_priority'                => 'High',
			'jira_events'                  => array( 'malware_found', 'plugin_vulnerability' ),
			'servicenow_enabled'           => false,
			'servicenow_instance'          => '',
			'servicenow_username'          => '',
			'servicenow_password'          => '',
			'servicenow_table'             => 'incident',
			'servicenow_impact'            => '2',
			'servicenow_urgency'           => '2',
			'custom_webhooks_enabled'      => false,
			'custom_webhooks'              => array(),
			'cicd_enabled'                 => false,
			'cicd_webhook_url'             => '',
			'cicd_fail_on_malware'         => true,
			'cicd_fail_on_vulnerabilities' => true,
			'cicd_min_severity'            => 'high',
		),

		// Deception defaults (stored as top-level keys for legacy compatibility).
		'deception_enabled'                     => true,
		'deception_honeytrap_paths'             => "/secret-backup.zip\n/old-admin/",
		'deception_honeytrap_override_defaults' => false,
		'deception_enum_trap'                   => true,
		'deception_enum_block'                  => false,
		'deception_block_all_enum'              => false,

		// P2P defaults (stored as top-level keys for module compatibility).
		'p2p_enabled'                           => false,
		'p2p_broadcast_enabled'                 => true,
		'p2p_trust_threshold'                   => 70,

		// Sandbox defaults (stored as top-level keys for module compatibility).
		'sandbox_enabled'                       => false,
		'sandbox_timeout'                       => 5,
		'sandbox_dynamic_analysis'              => false,
		'sandbox_console_enabled'               => false,
	);

	/**
	 * Get available languages.
	 *
	 * @return array Key is locale, Value is label.
	 */
	public static function get_available_languages() {
		return array(
			'site_default' => __( 'Site Default', 'nexifymy-security' ),
			'en_US'        => 'English (US)',
			'en_GB'        => 'English (UK)',
			'es_ES'        => 'Espanol (Spanish)',
			'fr_FR'        => 'Francais (French)',
			'de_DE'        => 'Deutsch (German)',
			'it_IT'        => 'Italiano (Italian)',
			'pt_BR'        => 'Portugues (Brazilian)',
			'nl_NL'        => 'Nederlands (Dutch)',
			'ru_RU'        => 'Russian',
			'ja'           => 'Japanese',
			'zh_Hans'      => 'Chinese (Simplified)',
			'ar'           => 'Arabic',
			'hi_IN'        => 'Hindi',
			'ko_KR'        => 'Korean',
			'tr'           => 'Turkish',
			'pl_PL'        => 'Polski (Polish)',
			'id_ID'        => 'Bahasa Indonesia (Indonesian)',
			'uk_UA'        => 'Ukrainian',
			'vi_VN'        => 'Vietnamese',
			'th'           => 'Thai',
			'sv_SE'        => 'Svenska (Swedish)',
			'da_DK'        => 'Dansk (Danish)',
			'fi'           => 'Suomi (Finnish)',
			'no'           => 'Norsk Bokmal (Norwegian)',
			'cs_CZ'        => 'Cestina (Czech)',
			'el'           => 'Greek',
			'hu_HU'        => 'Magyar (Hungarian)',
			'ro_RO'        => 'Romana (Romanian)',
			'sk_SK'        => 'Slovencina (Slovak)',
			'bg_BG'        => 'Bulgarian',
			'hr'           => 'Hrvatski (Croatian)',
			'sr_RS'        => 'Serbian',
			'he_IL'        => 'Hebrew',
			'fa_IR'        => 'Persian',
		);
	}


	/**
	 * Initialize the settings module.
	 */
	public function init() {
		// Migrate legacy settings from old option keys (one-time).
		self::migrate_legacy_settings();

		// Register settings.
		add_action( 'admin_init', array( $this, 'register_settings' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_nexifymy_get_settings', array( $this, 'ajax_get_settings' ) );
		add_action( 'wp_ajax_nexifymy_reset_settings', array( $this, 'ajax_reset_settings' ) );
	}

	/**
	 * Register settings.
	 */
	public function register_settings() {
		register_setting(
			'nexifymy_security_settings',
			self::OPTION_KEY,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => self::$defaults,
			)
		);
	}

	/**
	 * Get all settings.
	 *
	 * @return array
	 */
	public static function get_all() {
		$settings = get_option( self::OPTION_KEY, array() );
		return wp_parse_args( $settings, self::$defaults );
	}

	/**
	 * Get a specific setting.
	 *
	 * @param string $group Setting group (e.g., 'waf', 'rate_limiter').
	 * @param string $key   Setting key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public static function get( $group, $key, $default = null ) {
		$settings = self::get_all();

		if ( isset( $settings[ $group ][ $key ] ) ) {
			return $settings[ $group ][ $key ];
		}

		if ( $default !== null ) {
			return $default;
		}

		// Return from defaults if exists.
		if ( isset( self::$defaults[ $group ][ $key ] ) ) {
			return self::$defaults[ $group ][ $key ];
		}

		return $default;
	}

	/**
	 * Update a setting.
	 *
	 * @param string $group Setting group.
	 * @param string $key   Setting key.
	 * @param mixed  $value New value.
	 * @return bool
	 */
	public static function set( $group, $key, $value ) {
		$settings                   = self::get_all();
		$settings[ $group ][ $key ] = $value;
		// Use autoload=false for security (like Sucuri/WP Defender)
		return update_option( self::OPTION_KEY, $settings, false );
	}

	/**
	 * Update multiple settings at once.
	 *
	 * @param array $new_settings Settings to update.
	 * @return bool
	 */
	public static function update( $new_settings ) {
		$settings = self::get_all();
		$settings = self::array_merge_recursive_distinct( $settings, $new_settings );
		// Use autoload=false for security (like Sucuri/WP Defender)
		return update_option( self::OPTION_KEY, $settings, false );
	}

	/**
	 * Reset settings to defaults.
	 *
	 * @return bool
	 */
	public static function reset() {
		return update_option( self::OPTION_KEY, self::$defaults, false );
	}

	/**
	 * Save settings securely (alias for update with sanitization).
	 *
	 * @param array $settings Settings to save.
	 * @return bool
	 */
	public static function save( $settings ) {
		// Sanitize before saving
		$instance  = new self();
		$sanitized = $instance->sanitize_settings( $settings );
		$current   = self::get_all();
		$merged    = self::array_merge_recursive_distinct( $current, $sanitized );
		return update_option( self::OPTION_KEY, $merged, false );
	}

	/**
	 * Sanitize settings.
	 *
	 * @param array $input Input settings.
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$sanitized = array();

		// General Settings.
		if ( isset( $input['general'] ) ) {
			$language          = sanitize_text_field( $input['general']['language'] ?? 'site_default' );
			$legacy_locale_map = array(
				'tr_TR' => 'tr',
				'uk'    => 'uk_UA',
				'vi'    => 'vi_VN',
				'zh_CN' => 'zh_Hans',
			);
			if ( isset( $legacy_locale_map[ $language ] ) ) {
				$language = $legacy_locale_map[ $language ];
			}
			$allowed_languages = array_keys( self::get_available_languages() );
			if ( ! in_array( $language, $allowed_languages, true ) ) {
				$language = 'site_default';
			}

			$sanitized['general'] = array(
				'language'            => $language,
				'email_notifications' => ! empty( $input['general']['email_notifications'] ),
				'email_address'       => sanitize_email( $input['general']['email_address'] ?? '' ),
				'auto_updates'        => ! empty( $input['general']['auto_updates'] ),
			);
		}

		// Modules.
		if ( isset( $input['modules'] ) ) {
			$current_modules      = self::get_all()['modules'] ?? self::$defaults['modules'];
			$sanitized['modules'] = array(
				'waf_enabled'                   => array_key_exists( 'waf_enabled', $input['modules'] ) ? ! empty( $input['modules']['waf_enabled'] ) : ! empty( $current_modules['waf_enabled'] ),
				'scanner_enabled'               => array_key_exists( 'scanner_enabled', $input['modules'] ) ? ! empty( $input['modules']['scanner_enabled'] ) : ! empty( $current_modules['scanner_enabled'] ),
				'rate_limiter_enabled'          => array_key_exists( 'rate_limiter_enabled', $input['modules'] ) ? ! empty( $input['modules']['rate_limiter_enabled'] ) : ! empty( $current_modules['rate_limiter_enabled'] ),
				'login_protection_enabled'      => array_key_exists( 'login_protection_enabled', $input['modules'] ) ? ! empty( $input['modules']['login_protection_enabled'] ) : ! empty( $current_modules['login_protection_enabled'] ?? false ),
				'background_scan_enabled'       => array_key_exists( 'background_scan_enabled', $input['modules'] ) ? ! empty( $input['modules']['background_scan_enabled'] ) : ! empty( $current_modules['background_scan_enabled'] ),
				'signatures_enabled'            => array_key_exists( 'signatures_enabled', $input['modules'] ) ? ! empty( $input['modules']['signatures_enabled'] ) : ! empty( $current_modules['signatures_enabled'] ),
				'hardening_enabled'             => array_key_exists( 'hardening_enabled', $input['modules'] ) ? ! empty( $input['modules']['hardening_enabled'] ) : ! empty( $current_modules['hardening_enabled'] ),
				'geo_blocking_enabled'          => array_key_exists( 'geo_blocking_enabled', $input['modules'] ) ? ! empty( $input['modules']['geo_blocking_enabled'] ) : ! empty( $current_modules['geo_blocking_enabled'] ),
				'hide_login_enabled'            => array_key_exists( 'hide_login_enabled', $input['modules'] ) ? ! empty( $input['modules']['hide_login_enabled'] ) : ! empty( $current_modules['hide_login_enabled'] ),
				'live_traffic_enabled'          => array_key_exists( 'live_traffic_enabled', $input['modules'] ) ? ! empty( $input['modules']['live_traffic_enabled'] ) : ! empty( $current_modules['live_traffic_enabled'] ),
				'activity_log_enabled'          => array_key_exists( 'activity_log_enabled', $input['modules'] ) ? ! empty( $input['modules']['activity_log_enabled'] ) : ! empty( $current_modules['activity_log_enabled'] ),
				'captcha_enabled'               => array_key_exists( 'captcha_enabled', $input['modules'] ) ? ! empty( $input['modules']['captcha_enabled'] ) : ! empty( $current_modules['captcha_enabled'] ),
				'two_factor_enabled'            => array_key_exists( 'two_factor_enabled', $input['modules'] ) ? ! empty( $input['modules']['two_factor_enabled'] ) : ! empty( $current_modules['two_factor_enabled'] ),
				'password_enabled'              => array_key_exists( 'password_enabled', $input['modules'] ) ? ! empty( $input['modules']['password_enabled'] ) : ! empty( $current_modules['password_enabled'] ),
				'self_protection_enabled'       => array_key_exists( 'self_protection_enabled', $input['modules'] ) ? ! empty( $input['modules']['self_protection_enabled'] ) : ! empty( $current_modules['self_protection_enabled'] ),
				'integrations_enabled'          => array_key_exists( 'integrations_enabled', $input['modules'] ) ? ! empty( $input['modules']['integrations_enabled'] ) : ! empty( $current_modules['integrations_enabled'] ),
				'quarantine_enabled'            => array_key_exists( 'quarantine_enabled', $input['modules'] ) ? ! empty( $input['modules']['quarantine_enabled'] ) : ! empty( $current_modules['quarantine_enabled'] ),
				'database_enabled'              => array_key_exists( 'database_enabled', $input['modules'] ) ? ! empty( $input['modules']['database_enabled'] ) : ! empty( $current_modules['database_enabled'] ),
				'cdn_enabled'                   => array_key_exists( 'cdn_enabled', $input['modules'] ) ? ! empty( $input['modules']['cdn_enabled'] ) : ! empty( $current_modules['cdn_enabled'] ),
				'performance_enabled'           => array_key_exists( 'performance_enabled', $input['modules'] ) ? ! empty( $input['modules']['performance_enabled'] ) : ! empty( $current_modules['performance_enabled'] ),
				'core_repair_enabled'           => array_key_exists( 'core_repair_enabled', $input['modules'] ) ? ! empty( $input['modules']['core_repair_enabled'] ) : ! empty( $current_modules['core_repair_enabled'] ),
				'vulnerability_scanner_enabled' => array_key_exists( 'vulnerability_scanner_enabled', $input['modules'] ) ? ! empty( $input['modules']['vulnerability_scanner_enabled'] ) : ! empty( $current_modules['vulnerability_scanner_enabled'] ),
				'supply_chain_enabled'          => array_key_exists( 'supply_chain_enabled', $input['modules'] ) ? ! empty( $input['modules']['supply_chain_enabled'] ) : ! empty( $current_modules['supply_chain_enabled'] ),
				'proactive_enabled'             => array_key_exists( 'proactive_enabled', $input['modules'] ) ? ! empty( $input['modules']['proactive_enabled'] ) : ! empty( $current_modules['proactive_enabled'] ),
				'predictive_hunting_enabled'    => array_key_exists( 'predictive_hunting_enabled', $input['modules'] ) ? ! empty( $input['modules']['predictive_hunting_enabled'] ) : ! empty( $current_modules['predictive_hunting_enabled'] ?? true ),
				'ai_detection_enabled'          => array_key_exists( 'ai_detection_enabled', $input['modules'] ) ? ! empty( $input['modules']['ai_detection_enabled'] ) : ! empty( $current_modules['ai_detection_enabled'] ),
				'api_security_enabled'          => array_key_exists( 'api_security_enabled', $input['modules'] ) ? ! empty( $input['modules']['api_security_enabled'] ) : ! empty( $current_modules['api_security_enabled'] ),
				'graphql_security_enabled'      => array_key_exists( 'graphql_security_enabled', $input['modules'] ) ? ! empty( $input['modules']['graphql_security_enabled'] ) : ! empty( $current_modules['graphql_security_enabled'] ),
				'passkey_enabled'               => array_key_exists( 'passkey_enabled', $input['modules'] ) ? ! empty( $input['modules']['passkey_enabled'] ) : ! empty( $current_modules['passkey_enabled'] ),
				'compliance_enabled'            => array_key_exists( 'compliance_enabled', $input['modules'] ) ? ! empty( $input['modules']['compliance_enabled'] ) : ! empty( $current_modules['compliance_enabled'] ),
				'consent_enabled'               => array_key_exists( 'consent_enabled', $input['modules'] ) ? ! empty( $input['modules']['consent_enabled'] ) : ! empty( $current_modules['consent_enabled'] ?? true ),
				'developer_api_enabled'         => array_key_exists( 'developer_api_enabled', $input['modules'] ) ? ! empty( $input['modules']['developer_api_enabled'] ) : ! empty( $current_modules['developer_api_enabled'] ),
				'deception_enabled'             => array_key_exists( 'deception_enabled', $input['modules'] ) ? ! empty( $input['modules']['deception_enabled'] ) : ! empty( $current_modules['deception_enabled'] ),
				'p2p_enabled'                   => array_key_exists( 'p2p_enabled', $input['modules'] ) ? ! empty( $input['modules']['p2p_enabled'] ) : ! empty( $current_modules['p2p_enabled'] ),
				'sandbox_enabled'               => array_key_exists( 'sandbox_enabled', $input['modules'] ) ? ! empty( $input['modules']['sandbox_enabled'] ) : ! empty( $current_modules['sandbox_enabled'] ),
				'sandbox_console_enabled'       => array_key_exists( 'sandbox_console_enabled', $input['modules'] ) ? ! empty( $input['modules']['sandbox_console_enabled'] ) : ! empty( $current_modules['sandbox_console_enabled'] ),
				'temp_permissions_enabled'      => array_key_exists( 'temp_permissions_enabled', $input['modules'] ) ? ! empty( $input['modules']['temp_permissions_enabled'] ) : ! empty( $current_modules['temp_permissions_enabled'] ?? true ),
			);

			// Keep top-level compatibility flags synchronized when module toggles are submitted.
			if ( array_key_exists( 'deception_enabled', $input['modules'] ) ) {
				$sanitized['deception_enabled'] = ! empty( $input['modules']['deception_enabled'] );
			}
			if ( array_key_exists( 'p2p_enabled', $input['modules'] ) ) {
				$sanitized['p2p_enabled'] = ! empty( $input['modules']['p2p_enabled'] );
			}
			if ( array_key_exists( 'sandbox_enabled', $input['modules'] ) ) {
				$sanitized['sandbox_enabled'] = ! empty( $input['modules']['sandbox_enabled'] );
			}
			if ( array_key_exists( 'sandbox_console_enabled', $input['modules'] ) ) {
				$sanitized['sandbox_console_enabled'] = ! empty( $input['modules']['sandbox_console_enabled'] );
			}
		}

		// Deception (top-level legacy/module compatibility).
		if (
			array_key_exists( 'deception_enabled', $input ) ||
			array_key_exists( 'deception_honeytrap_paths', $input ) ||
			array_key_exists( 'deception_honeytrap_override_defaults', $input ) ||
			array_key_exists( 'deception_enum_trap', $input ) ||
			array_key_exists( 'deception_enum_block', $input ) ||
			array_key_exists( 'deception_block_all_enum', $input )
		) {
			$sanitized['deception_enabled']                     = ! empty( $input['deception_enabled'] );
			$sanitized['deception_honeytrap_paths']             = sanitize_textarea_field( (string) ( $input['deception_honeytrap_paths'] ?? '' ) );
			$sanitized['deception_honeytrap_override_defaults'] = ! empty( $input['deception_honeytrap_override_defaults'] );
			$sanitized['deception_enum_trap']                   = ! empty( $input['deception_enum_trap'] );
			$sanitized['deception_enum_block']                  = ! empty( $input['deception_enum_block'] );
			$sanitized['deception_block_all_enum']              = ! empty( $input['deception_block_all_enum'] );
		}

		// P2P (top-level legacy/module compatibility).
		if (
			array_key_exists( 'p2p_enabled', $input ) ||
			array_key_exists( 'p2p_broadcast_enabled', $input ) ||
			array_key_exists( 'p2p_trust_threshold', $input )
		) {
			$sanitized['p2p_enabled']           = ! empty( $input['p2p_enabled'] );
			$sanitized['p2p_broadcast_enabled'] = ! empty( $input['p2p_broadcast_enabled'] );
			$sanitized['p2p_trust_threshold']   = max( 0, min( 100, absint( $input['p2p_trust_threshold'] ?? 70 ) ) );
		}

		// Sandbox (top-level legacy/module compatibility).
		if (
			array_key_exists( 'sandbox_enabled', $input ) ||
			array_key_exists( 'sandbox_timeout', $input ) ||
			array_key_exists( 'sandbox_dynamic_analysis', $input ) ||
			array_key_exists( 'sandbox_console_enabled', $input )
		) {
			$sanitized['sandbox_enabled']          = ! empty( $input['sandbox_enabled'] );
			$sanitized['sandbox_timeout']          = max( 1, min( 30, absint( $input['sandbox_timeout'] ?? 5 ) ) );
			$sanitized['sandbox_dynamic_analysis'] = ! empty( $input['sandbox_dynamic_analysis'] );
			$sanitized['sandbox_console_enabled']  = ! empty( $input['sandbox_console_enabled'] );
		}

		// WAF.
		if ( isset( $input['waf'] ) ) {
			$sanitized['waf'] = array(
				'block_sqli'     => ! empty( $input['waf']['block_sqli'] ),
				'block_xss'      => ! empty( $input['waf']['block_xss'] ),
				'block_lfi'      => ! empty( $input['waf']['block_lfi'] ),
				'block_bad_bots' => ! empty( $input['waf']['block_bad_bots'] ),
				'log_only_mode'  => ! empty( $input['waf']['log_only_mode'] ),
			);
		}

		// Rate Limiter.
		if ( isset( $input['rate_limiter'] ) ) {
			$max_attempts_raw     = absint( $input['rate_limiter']['max_attempts'] ?? 5 );
			$lockout_duration_raw = absint( $input['rate_limiter']['lockout_duration'] ?? 900 );
			$attempt_window_raw   = absint( $input['rate_limiter']['attempt_window'] ?? 300 );

			$sanitized['rate_limiter'] = array(
				'max_attempts'     => max( 1, $max_attempts_raw ?: 5 ),
				'lockout_duration' => max( 60, $lockout_duration_raw ?: 900 ),
				'attempt_window'   => max( 60, $attempt_window_raw ?: 300 ),
			);
		}

		// Scanner.
		if ( isset( $input['scanner'] ) ) {
			$default_mode         = sanitize_key( $input['scanner']['default_mode'] ?? 'standard' );
			$max_file_size_kb_raw = absint( $input['scanner']['max_file_size_kb'] ?? 2048 );
			$quarantine_mode      = sanitize_key( $input['scanner']['quarantine_mode'] ?? 'manual' );
			if ( ! in_array( $quarantine_mode, array( 'manual', 'auto' ), true ) ) {
				$quarantine_mode = 'manual';
			}
			$auto_quarantine = ! empty( $input['scanner']['auto_quarantine_enabled'] ) || ! empty( $input['scanner']['auto_quarantine'] ) || $quarantine_mode === 'auto';

			$sanitized['scanner'] = array(
				'default_mode'            => $default_mode ?: 'standard',
				'max_file_size_kb'        => max( 100, $max_file_size_kb_raw ?: 2048 ),
				'excluded_paths'          => $this->sanitize_list( $input['scanner']['excluded_paths'] ?? '' ),
				'excluded_extensions'     => $this->sanitize_list( $input['scanner']['excluded_extensions'] ?? '' ),
				'quarantine_mode'         => $quarantine_mode,
				'auto_quarantine_enabled' => (bool) $auto_quarantine,
			);
		}

		// IP Settings.
		if ( isset( $input['ip'] ) ) {
			$sanitized['ip'] = array(
				'whitelist'       => $this->sanitize_ip_list( $input['ip']['whitelist'] ?? '' ),
				'trusted_proxies' => $this->sanitize_ip_list( $input['ip']['trusted_proxies'] ?? '' ),
			);
		}

		// Logging.
		if ( isset( $input['logging'] ) ) {
			$sanitized['logging'] = array(
				'retention_days'     => absint( $input['logging']['retention_days'] ?: 30 ),
				'log_waf_blocks'     => ! empty( $input['logging']['log_waf_blocks'] ),
				'log_login_attempts' => ! empty( $input['logging']['log_login_attempts'] ),
				'log_scans'          => ! empty( $input['logging']['log_scans'] ),
			);
		}

		// Background Scan.
		if ( isset( $input['background_scan'] ) ) {
			$sanitized['background_scan'] = array(
				'schedule'  => sanitize_key( $input['background_scan']['schedule'] ?? 'daily' ) ?: 'daily',
				'scan_mode' => sanitize_key( $input['background_scan']['scan_mode'] ?? 'standard' ) ?: 'standard',
			);
		}

		// Database.
		if ( isset( $input['database'] ) ) {
			$sanitized['database'] = array(
				'backup_enabled'     => ! empty( $input['database']['backup_enabled'] ),
				'backup_schedule'    => sanitize_key( $input['database']['backup_schedule'] ?? 'weekly' ) ?: 'weekly',
				'max_backups'        => max( 1, absint( $input['database']['max_backups'] ?? 5 ) ?: 5 ),
				'include_transients' => ! empty( $input['database']['include_transients'] ),
				'auto_optimize'      => ! empty( $input['database']['auto_optimize'] ),
			);
		}

		// Performance.
		if ( isset( $input['performance'] ) ) {
			$sanitized['performance'] = array(
				'enabled'             => ! empty( $input['performance']['enabled'] ),
				'smart_caching'       => ! empty( $input['performance']['smart_caching'] ),
				'cache_ttl'           => max( 60, absint( $input['performance']['cache_ttl'] ?? 3600 ) ),
				'throttle_scans'      => ! empty( $input['performance']['throttle_scans'] ),
				'max_scan_time'       => max( 10, absint( $input['performance']['max_scan_time'] ?? 30 ) ),
				'max_memory_percent'  => max( 10, min( 90, absint( $input['performance']['max_memory_percent'] ?? 50 ) ) ),
				'defer_heavy_tasks'   => ! empty( $input['performance']['defer_heavy_tasks'] ),
				'off_peak_start'      => max( 0, min( 23, absint( $input['performance']['off_peak_start'] ?? 2 ) ) ),
				'off_peak_end'        => max( 0, min( 23, absint( $input['performance']['off_peak_end'] ?? 6 ) ) ),
				'lazy_load_modules'   => ! empty( $input['performance']['lazy_load_modules'] ),
				'optimize_db_queries' => ! empty( $input['performance']['optimize_db_queries'] ),
			);
		}

		// Core Repair.
		if ( isset( $input['core_repair'] ) ) {
			$sanitized['core_repair'] = array(
				'enabled'       => ! empty( $input['core_repair']['enabled'] ),
				'backup_before' => ! empty( $input['core_repair']['backup_before'] ),
				'notify_admin'  => ! empty( $input['core_repair']['notify_admin'] ),
			);
		}

		// Supply Chain.
		if ( isset( $input['supply_chain'] ) ) {
			$sanitized['supply_chain'] = array(
				'enabled'                  => ! empty( $input['supply_chain']['enabled'] ),
				'scan_plugins'             => ! empty( $input['supply_chain']['scan_plugins'] ),
				'scan_themes'              => ! empty( $input['supply_chain']['scan_themes'] ),
				'scan_composer'            => ! empty( $input['supply_chain']['scan_composer'] ),
				'scan_npm'                 => ! empty( $input['supply_chain']['scan_npm'] ),
				'monitor_external_scripts' => ! empty( $input['supply_chain']['monitor_external_scripts'] ),
				'verify_cdn_integrity'     => ! empty( $input['supply_chain']['verify_cdn_integrity'] ),
				'auto_scan_schedule'       => sanitize_key( $input['supply_chain']['auto_scan_schedule'] ?? 'weekly' ) ?: 'weekly',
				'notify_on_issues'         => ! empty( $input['supply_chain']['notify_on_issues'] ),
			);
		}

		// Proactive.
		if ( isset( $input['proactive'] ) ) {
			$sanitized['proactive'] = array(
				'enabled'              => ! empty( $input['proactive']['enabled'] ),
				'auto_recommendations' => ! empty( $input['proactive']['auto_recommendations'] ),
				'auto_patch_plugins'   => ! empty( $input['proactive']['auto_patch_plugins'] ),
				'auto_patch_themes'    => ! empty( $input['proactive']['auto_patch_themes'] ),
				'auto_patch_core'      => ! empty( $input['proactive']['auto_patch_core'] ),
				'patch_schedule'       => sanitize_key( $input['proactive']['patch_schedule'] ?? 'daily' ) ?: 'daily',
				'notify_before_patch'  => ! empty( $input['proactive']['notify_before_patch'] ),
				'keep_backups'         => max( 1, absint( $input['proactive']['keep_backups'] ?? 5 ) ),
				'benchmark_schedule'   => sanitize_key( $input['proactive']['benchmark_schedule'] ?? 'weekly' ) ?: 'weekly',
			);
		}

		// AI Detection.
		if ( isset( $input['ai_detection'] ) ) {
			$sanitized['ai_detection'] = array(
				'enabled'                    => ! empty( $input['ai_detection']['enabled'] ),
				'learning_mode'              => ! empty( $input['ai_detection']['learning_mode'] ),
				'learning_period_days'       => max( 1, absint( $input['ai_detection']['learning_period_days'] ?? 7 ) ),
				'anomaly_threshold'          => max( 0, min( 100, absint( $input['ai_detection']['anomaly_threshold'] ?? 75 ) ) ),
				'auto_block_threshold'       => max( 0, min( 100, absint( $input['ai_detection']['auto_block_threshold'] ?? 90 ) ) ),
				'track_login_behavior'       => ! empty( $input['ai_detection']['track_login_behavior'] ),
				'track_request_patterns'     => ! empty( $input['ai_detection']['track_request_patterns'] ),
				'track_user_agents'          => ! empty( $input['ai_detection']['track_user_agents'] ),
				'track_geo_patterns'         => ! empty( $input['ai_detection']['track_geo_patterns'] ),
				'notify_on_anomaly'          => ! empty( $input['ai_detection']['notify_on_anomaly'] ),
				'session_risk_threshold'     => max( 1, min( 100, absint( $input['ai_detection']['session_risk_threshold'] ?? 60 ) ) ),
				'zero_trust_reauth_interval' => max( 60, min( 86400, absint( $input['ai_detection']['zero_trust_reauth_interval'] ?? 900 ) ) ),
				'zero_trust_risk_spike_threshold' => max( 1, min( 100, absint( $input['ai_detection']['zero_trust_risk_spike_threshold'] ?? 20 ) ) ),
				'insider_threat_enabled'     => ! empty( $input['ai_detection']['insider_threat_enabled'] ),
				'insider_threat_threshold'   => max( 1, min( 100, absint( $input['ai_detection']['insider_threat_threshold'] ?? 60 ) ) ),
				'data_exfiltration_enabled'  => ! empty( $input['ai_detection']['data_exfiltration_enabled'] ),
				'exfiltration_threshold'     => max( 1, min( 100, absint( $input['ai_detection']['exfiltration_threshold'] ?? 60 ) ) ),
				'exfiltration_baseline_days' => max( 1, min( 365, absint( $input['ai_detection']['exfiltration_baseline_days'] ?? 30 ) ) ),
			);
		}

		// Passkey.
		if ( isset( $input['passkey'] ) ) {
			$authenticator_types = array( 'platform', 'cross-platform', 'any' );
			$verification_types  = array( 'required', 'preferred', 'discouraged' );

			$sanitized['passkey'] = array(
				'enabled'              => ! empty( $input['passkey']['enabled'] ),
				'allow_passwordless'   => ! empty( $input['passkey']['allow_passwordless'] ),
				'require_for_admins'   => ! empty( $input['passkey']['require_for_admins'] ),
				'auto_prompt_register' => ! empty( $input['passkey']['auto_prompt_register'] ),
				'credential_timeout'   => max( 10000, absint( $input['passkey']['credential_timeout'] ?? 60000 ) ),
				'authenticator_type'   => in_array( $input['passkey']['authenticator_type'] ?? 'platform', $authenticator_types, true ) ? $input['passkey']['authenticator_type'] : 'platform',
				'user_verification'    => in_array( $input['passkey']['user_verification'] ?? 'preferred', $verification_types, true ) ? $input['passkey']['user_verification'] : 'preferred',
			);
		}

		// Compliance.
		if ( isset( $input['compliance'] ) ) {
			$schedules = array( 'daily', 'weekly', 'monthly' );
			$formats   = array( 'html', 'pdf', 'csv' );

			$sanitized['compliance'] = array(
				'enabled'             => ! empty( $input['compliance']['enabled'] ),
				'auto_generate'       => ! empty( $input['compliance']['auto_generate'] ),
				'schedule'            => in_array( $input['compliance']['schedule'] ?? 'weekly', $schedules, true ) ? $input['compliance']['schedule'] : 'weekly',
				'email_reports'       => ! empty( $input['compliance']['email_reports'] ),
				'include_gdpr'        => ! empty( $input['compliance']['include_gdpr'] ),
				'include_security'    => ! empty( $input['compliance']['include_security'] ),
				'include_performance' => ! empty( $input['compliance']['include_performance'] ),
				'include_threats'     => ! empty( $input['compliance']['include_threats'] ),
				'report_format'       => in_array( $input['compliance']['report_format'] ?? 'html', $formats, true ) ? $input['compliance']['report_format'] : 'html',
				'retention_days'      => max( 7, absint( $input['compliance']['retention_days'] ?? 90 ) ),
			);
		}

		// Predictive Threat Hunting.
		if ( isset( $input['predictive_threat_hunting'] ) ) {
			$forecast_schedules   = array( 'daily', 'weekly' );
			$simulation_schedules = array( 'weekly', 'monthly' );

			$forecast_update = sanitize_key( $input['predictive_threat_hunting']['forecast_update'] ?? 'weekly' );
			if ( ! in_array( $forecast_update, $forecast_schedules, true ) ) {
				$forecast_update = 'weekly';
			}

			$simulation_schedule = sanitize_key( $input['predictive_threat_hunting']['simulation_schedule'] ?? 'monthly' );
			if ( ! in_array( $simulation_schedule, $simulation_schedules, true ) ) {
				$simulation_schedule = 'monthly';
			}

			$sanitized['predictive_threat_hunting'] = array(
				'enabled'               => ! empty( $input['predictive_threat_hunting']['enabled'] ),
				'forecast_update'       => $forecast_update,
				'simulation_enabled'    => ! empty( $input['predictive_threat_hunting']['simulation_enabled'] ),
				'simulation_schedule'   => $simulation_schedule,
				'simulation_run_hour'   => max( 0, min( 23, absint( $input['predictive_threat_hunting']['simulation_run_hour'] ?? 3 ) ) ),
				'probability_threshold' => max( 1, min( 100, absint( $input['predictive_threat_hunting']['probability_threshold'] ?? 25 ) ) ),
			);
		}

		// Consent.
		if ( isset( $input['consent'] ) ) {
			$slug = sanitize_title( $input['consent']['preference_page_slug'] ?? 'privacy-preferences' );
			if ( empty( $slug ) ) {
				$slug = 'privacy-preferences';
			}

			$sanitized['consent'] = array(
				'enabled'              => ! empty( $input['consent']['enabled'] ),
				'banner_enabled'       => ! empty( $input['consent']['banner_enabled'] ),
				'preference_page_slug' => $slug,
			);
		}

		// Developer API.
		if ( isset( $input['developer_api'] ) ) {
			$sanitized['developer_api'] = array(
				'enabled'                  => ! empty( $input['developer_api']['enabled'] ),
				'rest_api_enabled'         => ! empty( $input['developer_api']['rest_api_enabled'] ),
				'graphql_protection'       => ! empty( $input['developer_api']['graphql_protection'] ),
				'webhooks_enabled'         => ! empty( $input['developer_api']['webhooks_enabled'] ),
				'require_api_key'          => ! empty( $input['developer_api']['require_api_key'] ),
				'rate_limit_api'           => max( 1, absint( $input['developer_api']['rate_limit_api'] ?? 100 ) ),
				'log_api_requests'         => ! empty( $input['developer_api']['log_api_requests'] ),
				'graphql_depth_limit'      => max( 1, absint( $input['developer_api']['graphql_depth_limit'] ?? 10 ) ),
				'graphql_complexity_limit' => max( 1, absint( $input['developer_api']['graphql_complexity_limit'] ?? 500 ) ),
			);
		}

		// Signatures.
		if ( isset( $input['signatures'] ) ) {
			$intervals = array( 'hourly', 'twicedaily', 'daily', 'weekly' );

			$sanitized['signatures'] = array(
				'enabled'         => ! empty( $input['signatures']['enabled'] ),
				'auto_update'     => ! empty( $input['signatures']['auto_update'] ),
				'update_interval' => in_array( $input['signatures']['update_interval'] ?? 'daily', $intervals, true ) ? $input['signatures']['update_interval'] : 'daily',
			);
		}

		// Hardening.
		if ( isset( $input['hardening'] ) ) {
			$sanitized['hardening'] = array(
				'disable_xmlrpc'      => ! empty( $input['hardening']['disable_xmlrpc'] ),
				'hide_wp_version'     => ! empty( $input['hardening']['hide_wp_version'] ),
				'disable_file_editor' => ! empty( $input['hardening']['disable_file_editor'] ),
				'security_headers'    => ! empty( $input['hardening']['security_headers'] ),
				'disable_rest_api'    => ! empty( $input['hardening']['disable_rest_api'] ),
				'disable_rss'         => ! empty( $input['hardening']['disable_rss'] ),
				'remove_rsd_link'     => ! empty( $input['hardening']['remove_rsd_link'] ),
				'remove_wlwmanifest'  => ! empty( $input['hardening']['remove_wlwmanifest'] ),
				'remove_shortlink'    => ! empty( $input['hardening']['remove_shortlink'] ),
				'disable_embeds'      => ! empty( $input['hardening']['disable_embeds'] ),
				'disable_pingback'    => ! empty( $input['hardening']['disable_pingback'] ),
			);
		}

		// Geo Blocking.
		if ( isset( $input['geo_blocking'] ) ) {
			$modes = array( 'blacklist', 'whitelist' );

			$sanitized['geo_blocking'] = array(
				'enabled'       => ! empty( $input['geo_blocking']['enabled'] ),
				'mode'          => in_array( $input['geo_blocking']['mode'] ?? 'blacklist', $modes, true ) ? $input['geo_blocking']['mode'] : 'blacklist',
				'countries'     => isset( $input['geo_blocking']['countries'] ) ? array_map( 'sanitize_text_field', (array) $input['geo_blocking']['countries'] ) : array(),
				'block_message' => sanitize_text_field( $input['geo_blocking']['block_message'] ?? 'Access denied from your region.' ),
				'log_blocked'   => ! empty( $input['geo_blocking']['log_blocked'] ),
			);
		}

		// Hide Login.
		if ( isset( $input['hide_login'] ) ) {
			$sanitized['hide_login'] = array(
				'enabled'       => ! empty( $input['hide_login']['enabled'] ),
				'login_slug'    => sanitize_title( $input['hide_login']['login_slug'] ?? 'secure-login' ) ?: 'secure-login',
				'redirect_slug' => sanitize_text_field( $input['hide_login']['redirect_slug'] ?? '404' ),
				'redirect_url'  => esc_url_raw( $input['hide_login']['redirect_url'] ?? '' ),
			);
		}

		// Live Traffic.
		if ( isset( $input['live_traffic'] ) ) {
			$sanitized['live_traffic'] = array(
				'enabled'         => ! empty( $input['live_traffic']['enabled'] ),
				'log_admin'       => ! empty( $input['live_traffic']['log_admin'] ),
				'log_ajax'        => ! empty( $input['live_traffic']['log_ajax'] ),
				'log_cron'        => ! empty( $input['live_traffic']['log_cron'] ),
				'retention_hours' => max( 1, absint( $input['live_traffic']['retention_hours'] ?? 24 ) ),
				'exclude_ips'     => $this->sanitize_ip_list( $input['live_traffic']['exclude_ips'] ?? '' ),
				'exclude_urls'    => $this->sanitize_list( $input['live_traffic']['exclude_urls'] ?? '' ),
			);
		}

		// Captcha.
		if ( isset( $input['captcha'] ) ) {
			$difficulties = array( 'easy', 'medium', 'hard' );

			$sanitized['captcha'] = array(
				'enabled'             => ! empty( $input['captcha']['enabled'] ),
				'enable_login'        => ! empty( $input['captcha']['enable_login'] ),
				'enable_registration' => ! empty( $input['captcha']['enable_registration'] ),
				'enable_reset'        => ! empty( $input['captcha']['enable_reset'] ),
				'enable_comment'      => ! empty( $input['captcha']['enable_comment'] ),
				'difficulty'          => in_array( $input['captcha']['difficulty'] ?? 'easy', $difficulties, true ) ? $input['captcha']['difficulty'] : 'easy',
				'failed_threshold'    => max( 1, absint( $input['captcha']['failed_threshold'] ?? 3 ) ),
			);
		}

		// Two Factor.
		if ( isset( $input['two_factor'] ) ) {
			$sanitized['two_factor'] = array(
				'enabled'       => ! empty( $input['two_factor']['enabled'] ),
				'force_admin'   => ! empty( $input['two_factor']['force_admin'] ),
				'force_all'     => ! empty( $input['two_factor']['force_all'] ),
				'email_backup'  => ! empty( $input['two_factor']['email_backup'] ),
				'remember_days' => max( 1, absint( $input['two_factor']['remember_days'] ?? 30 ) ),
			);
		}

		// Integrations.
		if ( isset( $input['integrations'] ) ) {
			$siem_types       = array( 'splunk', 'elasticsearch', 'qradar', 'arcsight', 'sumo', 'datadog', 'generic' );
			$siem_formats     = array( 'json', 'cef', 'leef' );
			$severity_levels  = array( 'critical', 'high', 'medium', 'low' );
			$available_events = array( 'all', 'threat_detected', 'login_failed', 'user_locked', 'malware_found', 'scan_completed', 'plugin_vulnerability', 'settings_changed', 'core_file_modified' );

			$sanitized['integrations'] = array(
				'enabled'                      => ! empty( $input['integrations']['enabled'] ),

				// Slack.
				'slack_enabled'                => ! empty( $input['integrations']['slack_enabled'] ),
				'slack_webhook_url'            => esc_url_raw( $input['integrations']['slack_webhook_url'] ?? '' ),
				'slack_channel'                => sanitize_text_field( $input['integrations']['slack_channel'] ?? '#security' ),
				'slack_events'                 => array_values( array_intersect( (array) ( $input['integrations']['slack_events'] ?? array() ), $available_events ) ),

				// Discord.
				'discord_enabled'              => ! empty( $input['integrations']['discord_enabled'] ),
				'discord_webhook_url'          => esc_url_raw( $input['integrations']['discord_webhook_url'] ?? '' ),
				'discord_events'               => array_values( array_intersect( (array) ( $input['integrations']['discord_events'] ?? array() ), $available_events ) ),

				// Teams.
				'teams_enabled'                => ! empty( $input['integrations']['teams_enabled'] ),
				'teams_webhook_url'            => esc_url_raw( $input['integrations']['teams_webhook_url'] ?? '' ),
				'teams_events'                 => array_values( array_intersect( (array) ( $input['integrations']['teams_events'] ?? array() ), $available_events ) ),

				// SIEM.
				'siem_enabled'                 => ! empty( $input['integrations']['siem_enabled'] ),
				'siem_type'                    => in_array( $input['integrations']['siem_type'] ?? 'splunk', $siem_types, true ) ? $input['integrations']['siem_type'] : 'splunk',
				'siem_endpoint'                => esc_url_raw( $input['integrations']['siem_endpoint'] ?? '' ),
				'siem_token'                   => sanitize_text_field( $input['integrations']['siem_token'] ?? '' ),
				'siem_index'                   => sanitize_text_field( $input['integrations']['siem_index'] ?? 'wordpress_security' ),
				'siem_format'                  => in_array( $input['integrations']['siem_format'] ?? 'json', $siem_formats, true ) ? $input['integrations']['siem_format'] : 'json',
				'siem_ssl_verify'              => ! empty( $input['integrations']['siem_ssl_verify'] ),
				'siem_events'                  => array_values( array_intersect( (array) ( $input['integrations']['siem_events'] ?? array() ), $available_events ) ),

				// Jira.
				'jira_enabled'                 => ! empty( $input['integrations']['jira_enabled'] ),
				'jira_url'                     => esc_url_raw( $input['integrations']['jira_url'] ?? '' ),
				'jira_email'                   => sanitize_email( $input['integrations']['jira_email'] ?? '' ),
				'jira_api_token'               => sanitize_text_field( $input['integrations']['jira_api_token'] ?? '' ),
				'jira_project_key'             => sanitize_text_field( $input['integrations']['jira_project_key'] ?? '' ),
				'jira_issue_type'              => sanitize_text_field( $input['integrations']['jira_issue_type'] ?? 'Bug' ),
				'jira_priority'                => sanitize_text_field( $input['integrations']['jira_priority'] ?? 'High' ),
				'jira_events'                  => array_values( array_intersect( (array) ( $input['integrations']['jira_events'] ?? array() ), $available_events ) ),

				// ServiceNow.
				'servicenow_enabled'           => ! empty( $input['integrations']['servicenow_enabled'] ),
				'servicenow_instance'          => sanitize_text_field( $input['integrations']['servicenow_instance'] ?? '' ),
				'servicenow_username'          => sanitize_text_field( $input['integrations']['servicenow_username'] ?? '' ),
				'servicenow_password'          => sanitize_text_field( $input['integrations']['servicenow_password'] ?? '' ),
				'servicenow_table'             => sanitize_text_field( $input['integrations']['servicenow_table'] ?? 'incident' ),
				'servicenow_impact'            => in_array( (string) ( $input['integrations']['servicenow_impact'] ?? '2' ), array( '1', '2', '3' ), true ) ? (string) $input['integrations']['servicenow_impact'] : '2',
				'servicenow_urgency'           => in_array( (string) ( $input['integrations']['servicenow_urgency'] ?? '2' ), array( '1', '2', '3' ), true ) ? (string) $input['integrations']['servicenow_urgency'] : '2',

				// Custom webhooks.
				'custom_webhooks_enabled'      => ! empty( $input['integrations']['custom_webhooks_enabled'] ),
				'custom_webhooks'              => $this->sanitize_custom_webhooks( $input['integrations']['custom_webhooks'] ?? array(), $available_events ),

				// CI/CD integration.
				'cicd_enabled'                 => ! empty( $input['integrations']['cicd_enabled'] ),
				'cicd_webhook_url'             => esc_url_raw( $input['integrations']['cicd_webhook_url'] ?? '' ),
				'cicd_fail_on_malware'         => ! empty( $input['integrations']['cicd_fail_on_malware'] ),
				'cicd_fail_on_vulnerabilities' => ! empty( $input['integrations']['cicd_fail_on_vulnerabilities'] ),
				'cicd_min_severity'            => in_array( $input['integrations']['cicd_min_severity'] ?? 'high', $severity_levels, true ) ? $input['integrations']['cicd_min_severity'] : 'high',
			);
		}

		return $sanitized;
	}

	/**
	 * Sanitize a comma-separated list.
	 *
	 * @param string|array $input Input.
	 * @return array
	 */
	private function sanitize_list( $input ) {
		if ( is_array( $input ) ) {
			return array_map( 'sanitize_text_field', $input );
		}

		if ( empty( $input ) ) {
			return array();
		}

		$items = preg_split( '/[\r\n,]+/', (string) $input );
		$items = array_map( 'trim', $items );
		$items = array_map( 'sanitize_text_field', $items );
		$items = array_filter( $items );

		return array_values( $items );
	}

	/**
	 * Sanitize IP list.
	 *
	 * @param string|array $input Input.
	 * @return array
	 */
	private function sanitize_ip_list( $input ) {
		$items = $this->sanitize_list( $input );

		return array_filter(
			$items,
			function ( $ip ) {
				return filter_var( $ip, FILTER_VALIDATE_IP );
			}
		);
	}

	/**
	 * Sanitize custom webhook configurations.
	 *
	 * @param mixed $input Webhook input.
	 * @param array $available_events Allowed event keys.
	 * @return array
	 */
	private function sanitize_custom_webhooks( $input, $available_events ) {
		if ( ! is_array( $input ) ) {
			return array();
		}

		$sanitized       = array();
		$allowed_methods = array( 'POST', 'PUT', 'PATCH' );

		foreach ( $input as $webhook ) {
			if ( ! is_array( $webhook ) ) {
				continue;
			}

			$name = sanitize_text_field( $webhook['name'] ?? '' );
			$url  = esc_url_raw( $webhook['url'] ?? '' );
			if ( empty( $url ) ) {
				continue;
			}

			$method = strtoupper( sanitize_text_field( $webhook['method'] ?? 'POST' ) );
			if ( ! in_array( $method, $allowed_methods, true ) ) {
				$method = 'POST';
			}

			$headers = array();
			if ( isset( $webhook['headers'] ) ) {
				if ( is_string( $webhook['headers'] ) ) {
					$decoded = json_decode( wp_unslash( $webhook['headers'] ), true );
					if ( is_array( $decoded ) ) {
						$headers = $decoded;
					}
				} elseif ( is_array( $webhook['headers'] ) ) {
					$headers = $webhook['headers'];
				}
			}

			$clean_headers = array();
			foreach ( $headers as $header_key => $header_value ) {
				$clean_key = sanitize_text_field( (string) $header_key );
				if ( '' === $clean_key ) {
					continue;
				}
				$clean_headers[ $clean_key ] = sanitize_text_field( (string) $header_value );
			}

			$events = array_values(
				array_intersect(
					(array) ( $webhook['events'] ?? array() ),
					$available_events
				)
			);
			if ( empty( $events ) ) {
				$events = array( 'all' );
			}

			$sanitized[] = array(
				'name'    => $name,
				'url'     => $url,
				'method'  => $method,
				'headers' => $clean_headers,
				'events'  => $events,
			);
		}

		return $sanitized;
	}

	/**
	 * Merge arrays recursively without overwriting with empty values.
	 *
	 * @param array $array1 First array.
	 * @param array $array2 Second array.
	 * @return array
	 */
	private static function array_merge_recursive_distinct( array $array1, array $array2 ) {
		$merged = $array1;

		foreach ( $array2 as $key => $value ) {
			if ( is_array( $value ) && isset( $merged[ $key ] ) && is_array( $merged[ $key ] ) ) {
				$merged[ $key ] = self::array_merge_recursive_distinct( $merged[ $key ], $value );
			} else {
				$merged[ $key ] = $value;
			}
		}

		return $merged;
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	/**
	 * Save settings via AJAX.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via sanitize_settings() method below
		$settings = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : array();
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}
		$sanitized = $this->sanitize_settings( $settings );

		self::update( $sanitized );

		// Apply settings that need immediate effect.
		$this->apply_settings( $sanitized );

		// Log the change.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'settings_updated',
				'Plugin settings were updated.',
				'info',
				array()
			);
		}

		wp_send_json_success(
			array(
				'message'  => 'Settings saved successfully.',
				'settings' => $sanitized,
			)
		);
	}

	/**
	 * Get settings via AJAX.
	 */
	public function ajax_get_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( self::get_all() );
	}

	/**
	 * Reset settings via AJAX.
	 */
	public function ajax_reset_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		self::reset();

		// Log the reset.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			NexifyMy_Security_Logger::log(
				'settings_reset',
				'Plugin settings were reset to defaults.',
				'info',
				array()
			);
		}

		wp_send_json_success(
			array(
				'message'  => 'Settings reset to defaults.',
				'settings' => self::$defaults,
			)
		);
	}

	/**
	 * Apply settings that need immediate effect.
	 *
	 * @param array $settings The settings.
	 */
	private function apply_settings( $settings ) {
		// Reload plugin textdomain immediately when language setting changes.
		if ( isset( $settings['general']['language'] ) ) {
			if ( function_exists( 'unload_textdomain' ) ) {
				unload_textdomain( 'nexifymy-security' );
			}
			$domain_path = 'languages';
			if ( function_exists( 'plugin_basename' ) && defined( 'NEXIFYMY_SECURITY_FILE' ) ) {
				$domain_path = dirname( plugin_basename( NEXIFYMY_SECURITY_FILE ) ) . '/languages';
			}
			if ( function_exists( 'load_plugin_textdomain' ) ) {
				load_plugin_textdomain(
					'nexifymy-security',
					false,
					$domain_path
				);
			}
		}

		// Update IP whitelist option for WAF.
		if ( isset( $settings['ip']['whitelist'] ) ) {
			update_option( 'nexifymy_security_ip_whitelist', $settings['ip']['whitelist'] );
		}

		// Update trusted proxies for rate limiter.
		if ( isset( $settings['ip']['trusted_proxies'] ) ) {
			update_option( 'nexifymy_security_trusted_proxies', $settings['ip']['trusted_proxies'] );
		}

		// Update scan schedule if changed.
		if ( isset( $settings['background_scan']['schedule'] ) ) {
			update_option( 'nexifymy_scan_schedule', $settings['background_scan']['schedule'] );

			// Reschedule cron if needed.
			if ( class_exists( 'NexifyMy_Security_Background_Scanner' ) ) {
				$bg_scanner = new NexifyMy_Security_Background_Scanner();
				$bg_scanner->schedule_scan( $settings['background_scan']['schedule'] );
			}
		}

		// Flush runtime module settings caches after settings changes.
		if ( class_exists( 'NexifyMy_Security_Deception' ) && method_exists( 'NexifyMy_Security_Deception', 'flush_settings_cache' ) ) {
			NexifyMy_Security_Deception::flush_settings_cache();
		}
		if ( class_exists( 'NexifyMy_Security_P2P' ) && method_exists( 'NexifyMy_Security_P2P', 'flush_settings_cache' ) ) {
			NexifyMy_Security_P2P::flush_settings_cache();
		}
		if ( class_exists( 'NexifyMy_Security_Sandbox' ) && method_exists( 'NexifyMy_Security_Sandbox', 'flush_settings_cache' ) ) {
			NexifyMy_Security_Sandbox::flush_settings_cache();
		}
		if ( class_exists( 'NexifyMy_Security_Predictive_Threat_Hunting' ) && method_exists( 'NexifyMy_Security_Predictive_Threat_Hunting', 'flush_settings_cache' ) ) {
			NexifyMy_Security_Predictive_Threat_Hunting::flush_settings_cache();
		}
	}

	/**
	 * Migrate legacy integration settings to central settings.
	 * This is a one-time migration for existing installations.
	 */
	public static function migrate_legacy_settings() {
		// Migrate integrations from old option key.
		$old_integrations = get_option( 'nexifymy_integrations', null );
		if ( null !== $old_integrations && is_array( $old_integrations ) ) {
			$all_settings                 = self::get_all();
			$all_settings['integrations'] = wp_parse_args( $old_integrations, self::$defaults['integrations'] );
			update_option( self::OPTION_KEY, $all_settings );
			delete_option( 'nexifymy_integrations' );
		}
	}
}
