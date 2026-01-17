<?php
/**
 * Settings Module.
 * Provides centralized configuration for all security features.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Settings {

	/**
	 * Option key for plugin settings.
	 */
	const OPTION_KEY = 'nexifymy_security_settings';

	/**
	 * Default settings.
	 */
	private static $defaults = array(
		// Module Toggles.
		'modules' => array(
			'waf_enabled'         => true,
			'scanner_enabled'     => true,
			'rate_limiter_enabled' => true,
			'background_scan_enabled' => true,
		),

		// WAF Settings.
		'waf' => array(
			'block_sqli'         => true,
			'block_xss'          => true,
			'block_lfi'          => true,
			'block_bad_bots'     => true,
			'log_only_mode'      => false, // If true, log but don't block.
		),

		// Rate Limiter Settings.
		'rate_limiter' => array(
			'max_attempts'       => 5,
			'lockout_duration'   => 900,  // 15 minutes.
			'attempt_window'     => 300,  // 5 minutes.
		),

		// Scanner Settings.
		'scanner' => array(
			'default_mode'       => 'standard',
			'max_file_size_kb'   => 2048,  // 2MB.
			'excluded_paths'     => array(),
			'excluded_extensions' => array( 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip' ),
		),

		// IP Settings.
		'ip' => array(
			'whitelist'          => array(),
			'trusted_proxies'    => array(),
		),

		// Logging Settings.
		'logging' => array(
			'retention_days'     => 30,
			'log_waf_blocks'     => true,
			'log_login_attempts' => true,
			'log_scans'          => true,
		),

		// Background Scan Settings.
		'background_scan' => array(
			'schedule'           => 'daily',
			'scan_mode'          => 'standard',
		),

		// Database Security Settings.
		'database' => array(
			'backup_enabled'     => true,
			'backup_schedule'    => 'weekly',
			'max_backups'        => 5,
			'include_transients' => false,
			'auto_optimize'      => false,
		),

		// Performance Optimizer Settings.
		'performance' => array(
			'enabled'            => true,
			'smart_caching'      => true,
			'cache_ttl'          => 3600,
			'throttle_scans'     => true,
			'max_scan_time'      => 30,
			'max_memory_percent' => 50,
			'defer_heavy_tasks'  => true,
			'off_peak_start'     => 2,
			'off_peak_end'       => 6,
			'lazy_load_modules'  => true,
			'optimize_db_queries'=> true,
		),

		// Core Repair Settings.
		'core_repair' => array(
			'enabled'       => true,
			'backup_before' => true,
			'notify_admin'  => true,
		),

		// Supply Chain Security Settings.
		'supply_chain' => array(
			'enabled'                => true,
			'scan_plugins'           => true,
			'scan_themes'            => true,
			'scan_composer'          => true,
			'scan_npm'               => true,
			'monitor_external_scripts' => true,
			'verify_cdn_integrity'   => true,
			'auto_scan_schedule'     => 'weekly',
			'notify_on_issues'       => true,
		),

		// Proactive Security Settings.
		'proactive' => array(
			'enabled'                => true,
			'auto_recommendations'   => true,
			'auto_patch_plugins'     => false,
			'auto_patch_themes'      => false,
			'auto_patch_core'        => false,
			'patch_schedule'         => 'daily',
			'notify_before_patch'    => true,
			'keep_backups'           => 5,
			'benchmark_schedule'     => 'weekly',
		),
	);


	/**
	 * Initialize the settings module.
	 */
	public function init() {
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
		register_setting( 'nexifymy_security_settings', self::OPTION_KEY, array(
			'type'              => 'array',
			'sanitize_callback' => array( $this, 'sanitize_settings' ),
			'default'           => self::$defaults,
		) );
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
		$settings = self::get_all();
		$settings[ $group ][ $key ] = $value;
		return update_option( self::OPTION_KEY, $settings );
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
		return update_option( self::OPTION_KEY, $settings );
	}

	/**
	 * Reset settings to defaults.
	 *
	 * @return bool
	 */
	public static function reset() {
		return update_option( self::OPTION_KEY, self::$defaults );
	}

	/**
	 * Sanitize settings.
	 *
	 * @param array $input Input settings.
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$sanitized = array();

		// Modules.
		if ( isset( $input['modules'] ) ) {
			$sanitized['modules'] = array(
				'waf_enabled'         => ! empty( $input['modules']['waf_enabled'] ),
				'scanner_enabled'     => ! empty( $input['modules']['scanner_enabled'] ),
				'rate_limiter_enabled' => ! empty( $input['modules']['rate_limiter_enabled'] ),
				'background_scan_enabled' => ! empty( $input['modules']['background_scan_enabled'] ),
			);
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
			$max_attempts_raw = absint( $input['rate_limiter']['max_attempts'] ?? 5 );
			$lockout_duration_raw = absint( $input['rate_limiter']['lockout_duration'] ?? 900 );
			$attempt_window_raw = absint( $input['rate_limiter']['attempt_window'] ?? 300 );

			$sanitized['rate_limiter'] = array(
				'max_attempts'     => max( 1, $max_attempts_raw ?: 5 ),
				'lockout_duration' => max( 60, $lockout_duration_raw ?: 900 ),
				'attempt_window'   => max( 60, $attempt_window_raw ?: 300 ),
			);
		}

		// Scanner.
		if ( isset( $input['scanner'] ) ) {
			$default_mode = sanitize_key( $input['scanner']['default_mode'] ?? 'standard' );
			$max_file_size_kb_raw = absint( $input['scanner']['max_file_size_kb'] ?? 2048 );

			$sanitized['scanner'] = array(
				'default_mode'     => $default_mode ?: 'standard',
				'max_file_size_kb' => max( 100, $max_file_size_kb_raw ?: 2048 ),
				'excluded_paths'   => $this->sanitize_list( $input['scanner']['excluded_paths'] ?? '' ),
				'excluded_extensions' => $this->sanitize_list( $input['scanner']['excluded_extensions'] ?? '' ),
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

		$items = explode( "\n", $input );
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

		return array_filter( $items, function( $ip ) {
			return filter_var( $ip, FILTER_VALIDATE_IP );
		} );
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

		$settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();
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

		wp_send_json_success( array(
			'message'  => 'Settings saved successfully.',
			'settings' => $sanitized,
		) );
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

		wp_send_json_success( array(
			'message'  => 'Settings reset to defaults.',
			'settings' => self::$defaults,
		) );
	}

	/**
	 * Apply settings that need immediate effect.
	 *
	 * @param array $settings The settings.
	 */
	private function apply_settings( $settings ) {
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
	}
}
