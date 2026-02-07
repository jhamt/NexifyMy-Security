<?php
/**
 * Handles the admin interface and settings.
 *
 * DEV NOTES:
 * This is the central admin controller. It registers all menu pages,
 * enqueues dashboard assets, and routes AJAX requests for dashboard data.
 * Last Updated: 2026-02-06
 * Version: 2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Admin {

	/**
	 * Initialize hooks.
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_nexifymy_get_dashboard_data', array( $this, 'ajax_get_dashboard_data' ) );
		add_action( 'wp_ajax_nexifymy_toggle_module', array( $this, 'ajax_toggle_module' ) );
		add_action( 'wp_ajax_nexifymy_save_module_settings', array( $this, 'ajax_save_module_settings' ) );
	}

	/**
	 * Add menu pages.
	 */
	public function add_menu_pages() {
		// Main menu
		add_menu_page(
			__( 'NexifyMy Security', 'nexifymy-security' ),
			__( 'Nexify Security', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			80
		);

		// Dashboard
		add_submenu_page(
			'nexifymy-security',
			__( 'Dashboard', 'nexifymy-security' ),
			__( 'Dashboard', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security',
			array( $this, 'render_dashboard' )
		);

		// Scanner (contains Scanner, Quarantine, Malware Definitions)
		add_submenu_page(
			'nexifymy-security',
			__( 'Scanner', 'nexifymy-security' ),
			__( 'Scanner', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-scanner',
			array( $this, 'render_scanner_page' )
		);

		// Firewall (contains Firewall, Login Protection, Geo Blocking, Rate Limiter)
		add_submenu_page(
			'nexifymy-security',
			__( 'Firewall', 'nexifymy-security' ),
			__( 'Firewall', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-firewall',
			array( $this, 'render_firewall_page' )
		);

		// Modules (contains 2FA, Hardening, Hide Login, Password, Captcha, Self-Protection)
		add_submenu_page(
			'nexifymy-security',
			__( 'Modules', 'nexifymy-security' ),
			__( 'Modules', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-modules',
			array( $this, 'render_modules_page' )
		);

		// Tools (contains Database, Core Repair, Vulnerabilities, Live Traffic, CDN)
		add_submenu_page(
			'nexifymy-security',
			__( 'Tools', 'nexifymy-security' ),
			__( 'Tools', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-tools',
			array( $this, 'render_tools_page' )
		);

		// Settings (contains Logs, Notifications, Settings)
		add_submenu_page(
			'nexifymy-security',
			__( 'Settings', 'nexifymy-security' ),
			__( 'Settings', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-settings',
			array( $this, 'render_settings_page' )
		);

		// Activity Log (User Logbook, Login & Activity Tracking)
		add_submenu_page(
			'nexifymy-security',
			__( 'Activity Log', 'nexifymy-security' ),
			__( 'Activity Log', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-activity-log',
			array( $this, 'render_activity_log_page' )
		);

		// Notifications (quick access)
		add_submenu_page(
			'nexifymy-security',
			__( 'Notifications', 'nexifymy-security' ),
			__( 'Notifications', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-notifications',
			array( $this, 'render_notifications_page' )
		);

		// Analytics
		add_submenu_page(
			'nexifymy-security',
			__( 'Analytics', 'nexifymy-security' ),
			__( 'Analytics', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-analytics',
			array( $this, 'render_analytics_page' )
		);

		// Integrations (SIEM, Ticketing, Communication, CI/CD)
		add_submenu_page(
			'nexifymy-security',
			__( 'Integrations', 'nexifymy-security' ),
			__( 'Integrations', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-integrations',
			array( $this, 'render_integrations_page' )
		);

		// Supply Chain Security
		add_submenu_page(
			'nexifymy-security',
			__( 'Supply Chain', 'nexifymy-security' ),
			__( 'Supply Chain', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-supply-chain',
			array( $this, 'render_supply_chain_page' )
		);

		// Compliance & Reporting
		add_submenu_page(
			'nexifymy-security',
			__( 'Compliance', 'nexifymy-security' ),
			__( 'Compliance', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-compliance',
			array( $this, 'render_compliance_page' )
		);

		// Proactive Security & Recommendations
		add_submenu_page(
			'nexifymy-security',
			__( 'Recommendations', 'nexifymy-security' ),
			__( 'Recommendations', 'nexifymy-security' ),
			'manage_options',
			'nexifymy-security-recommendations',
			array( $this, 'render_recommendations_page' )
		);
	}


	/**
	 * Enqueue admin assets.
	 */
	public function enqueue_assets( $hook ) {
		// Only load on our plugin pages.
		if ( ! $hook || ( strpos( $hook, 'nexifymy' ) === false && strpos( $hook, 'nexify-security' ) === false ) ) {
			return;
		}

		wp_enqueue_style( 'font-awesome', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css', array(), '6.5.1' );
		wp_enqueue_style( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/css/admin.css', array(), NEXIFYMY_SECURITY_VERSION );
		wp_enqueue_script( 'chartjs', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js', array(), '4.4.0', false );
		wp_enqueue_script( 'nexifymy-security-admin', NEXIFYMY_SECURITY_URL . 'assets/js/admin.js', array( 'jquery', 'chartjs' ), NEXIFYMY_SECURITY_VERSION . '.' . time(), true );

		wp_localize_script( 'nexifymy-security-admin', 'nexifymySecurity', array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'nexifymy_security_nonce' ),
			'strings' => array(
				'scanning'    => __( 'Scanning...', 'nexifymy-security' ),
				'scanComplete' => __( 'Scan Complete', 'nexifymy-security' ),
				'error'       => __( 'Error', 'nexifymy-security' ),
			),
		) );
	}

	/**
	 * Calculate security score.
	 */
	private function calculate_security_score() {
		$score = 100;
		$issues = array();

		// Check if all modules are active (simulated - in real use, check options).
		// For now, give points for having the plugin active.

		// Check last scan results.
		$last_scan = get_option( 'nexifymy_last_scheduled_scan' );
		if ( ! $last_scan ) {
			$score -= 20;
			$issues[] = __( 'No scan has been run yet', 'nexifymy-security' );
		} elseif ( isset( $last_scan['results']['threats_found'] ) && $last_scan['results']['threats_found'] > 0 ) {
			$threats = $last_scan['results']['threats_found'];
			$score -= min( 50, $threats * 10 );
			$issues[] = sprintf( __( '%d threats detected in last scan', 'nexifymy-security' ), $threats );
		}

		// Check if WordPress is up to date.
		global $wp_version;
		$latest = get_site_transient( 'update_core' );
		if ( $latest && isset( $latest->updates[0]->version ) && version_compare( $wp_version, $latest->updates[0]->version, '<' ) ) {
			$score -= 15;
			$issues[] = __( 'WordPress is not up to date', 'nexifymy-security' );
		}

		// Check for recent blocked attacks.
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$stats = NexifyMy_Security_Logger::get_stats( 7 );
			if ( isset( $stats['by_severity']['critical'] ) && $stats['by_severity']['critical'] > 5 ) {
				$score -= 10;
				$issues[] = __( 'High number of blocked attacks recently', 'nexifymy-security' );
			}
		}

		return array(
			'score'  => max( 0, min( 100, $score ) ),
			'issues' => $issues,
		);
	}

	/**
	 * Get dashboard data via AJAX.
	 */
	public function ajax_get_dashboard_data() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$security_score = $this->calculate_security_score();
		$last_scan = get_option( 'nexifymy_last_scan' );
		$stats = array();

		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$stats = NexifyMy_Security_Logger::get_stats( 7 );
		}

		wp_send_json_success( array(
			'security_score' => $security_score,
			'last_scan'      => $last_scan,
			'stats'          => $stats,
		) );
	}

	/**
	 * Toggle module enable/disable via AJAX.
	 */
	public function ajax_toggle_module() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$module = isset( $_POST['module'] ) ? sanitize_key( $_POST['module'] ) : '';
		$enabled = isset( $_POST['enabled'] ) ? absint( $_POST['enabled'] ) : 0;

		if ( empty( $module ) ) {
			wp_send_json_error( 'Invalid module' );
		}

		// Backward compatibility: normalize legacy module keys.
		$module_aliases = array(
			'2fa'             => 'two_factor',
			'password_policy' => 'password',
			'vulnerabilities' => 'vulnerability_scanner',
			'audit_log'       => 'activity_log',
		);
		if ( isset( $module_aliases[ $module ] ) ) {
			$module = $module_aliases[ $module ];
		}

		$settings = get_option( 'nexifymy_security_settings', array() );
		
		if ( ! isset( $settings['modules'] ) ) {
			$settings['modules'] = array();
		}

		$settings['modules'][ $module . '_enabled' ] = (bool) $enabled;
		// Use autoload=false for security (like Sucuri/WP Defender)
		update_option( 'nexifymy_security_settings', $settings, false );

		wp_send_json_success( array(
			'module' => $module,
			'enabled' => $enabled,
		) );
	}

	/**
	 * Save module settings via AJAX.
	 */
	public function ajax_save_module_settings() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$module = isset( $_POST['module'] ) ? sanitize_key( $_POST['module'] ) : '';
		$module_settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();

		if ( empty( $module ) ) {
			wp_send_json_error( 'Invalid module' );
		}

		$settings = get_option( 'nexifymy_security_settings', array() );
		if ( ! isset( $settings['modules'] ) || ! is_array( $settings['modules'] ) ) {
			$settings['modules'] = array();
		}

		// Scanner settings require module-aware mapping (scanner + background scan + quarantine mode).
		if ( 'scanner' === $module ) {
			$current_scanner = isset( $settings['scanner'] ) && is_array( $settings['scanner'] ) ? $settings['scanner'] : array();
			$current_bg = isset( $settings['background_scan'] ) && is_array( $settings['background_scan'] ) ? $settings['background_scan'] : array();

			$default_mode = sanitize_key( $module_settings['default_mode'] ?? ( $current_scanner['default_mode'] ?? 'standard' ) );
			if ( ! in_array( $default_mode, array( 'quick', 'standard', 'deep' ), true ) ) {
				$default_mode = 'standard';
			}

			$quarantine_mode = sanitize_key( $module_settings['quarantine_mode'] ?? ( $current_scanner['quarantine_mode'] ?? 'manual' ) );
			if ( ! in_array( $quarantine_mode, array( 'manual', 'auto' ), true ) ) {
				$quarantine_mode = 'manual';
			}

			$excluded_paths_raw = (string) ( $module_settings['excluded_paths'] ?? ( is_array( $current_scanner['excluded_paths'] ?? null ) ? implode( "\n", $current_scanner['excluded_paths'] ) : ( $current_scanner['excluded_paths'] ?? '' ) ) );
			$excluded_extensions_raw = (string) ( $module_settings['excluded_extensions'] ?? ( is_array( $current_scanner['excluded_extensions'] ?? null ) ? implode( ',', $current_scanner['excluded_extensions'] ) : ( $current_scanner['excluded_extensions'] ?? '' ) ) );
			$excluded_paths = preg_split( '/[\r\n,]+/', $excluded_paths_raw );
			$excluded_extensions = preg_split( '/[\r\n,]+/', $excluded_extensions_raw );
			$excluded_paths = array_values( array_filter( array_map( 'sanitize_text_field', array_map( 'trim', (array) $excluded_paths ) ) ) );
			$excluded_extensions = array_values( array_filter( array_map( 'sanitize_text_field', array_map( 'trim', (array) $excluded_extensions ) ) ) );

			$settings['scanner'] = wp_parse_args(
				array(
					'default_mode'            => $default_mode,
					'max_file_size_kb'        => max( 100, absint( $module_settings['max_file_size_kb'] ?? ( $current_scanner['max_file_size_kb'] ?? 2048 ) ) ),
					'excluded_paths'          => $excluded_paths,
					'excluded_extensions'     => $excluded_extensions,
					'quarantine_mode'         => $quarantine_mode,
					'auto_quarantine_enabled' => $quarantine_mode === 'auto',
				),
				$current_scanner
			);

			$settings['modules']['scanner_enabled'] = isset( $module_settings['enabled'] ) ? ! empty( $module_settings['enabled'] ) : ( $settings['modules']['scanner_enabled'] ?? true );

			if ( isset( $module_settings['schedule'] ) ) {
				$schedule = sanitize_key( $module_settings['schedule'] );
				if ( ! in_array( $schedule, array( 'hourly', 'twicedaily', 'daily', 'weekly', 'disabled' ), true ) ) {
					$schedule = $current_bg['schedule'] ?? 'daily';
				}

				$settings['background_scan'] = wp_parse_args(
					array( 'schedule' => $schedule ),
					$current_bg
				);

				update_option( 'nexifymy_scan_schedule', $schedule, false );

				if ( class_exists( 'NexifyMy_Security_Background_Scanner' ) ) {
					$bg_scanner = new NexifyMy_Security_Background_Scanner();
					$bg_scanner->schedule_scan( $schedule );
				}
			}

			if ( isset( $module_settings['background_enabled'] ) ) {
				$settings['modules']['background_scan_enabled'] = ! empty( $module_settings['background_enabled'] );
			}

			update_option( 'nexifymy_security_settings', $settings, false );

			wp_send_json_success( array(
				'module' => $module,
				'message' => __( 'Settings saved successfully', 'nexifymy-security' ),
			) );
		}

		// Normalize rate limiter values to keys used by the runtime module.
		if ( 'rate_limiter' === $module ) {
			$max_attempts = absint( $module_settings['max_attempts'] ?? $module_settings['login_attempts'] ?? 5 );
			$attempt_window_minutes = absint( $module_settings['attempt_window_minutes'] ?? $module_settings['login_window'] ?? 15 );
			$lockout_duration = absint( $module_settings['lockout_duration'] ?? $module_settings['login_lockout'] ?? $module_settings['block_duration'] ?? 900 );

			$settings['rate_limiter'] = wp_parse_args(
				array(
					'max_attempts'     => max( 1, $max_attempts ),
					'attempt_window'   => max( 60, $attempt_window_minutes * 60 ),
					'lockout_duration' => max( 60, $lockout_duration ),
				),
				isset( $settings['rate_limiter'] ) && is_array( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array()
			);

			if ( isset( $module_settings['enabled'] ) ) {
				$settings['modules']['rate_limiter_enabled'] = ! empty( $module_settings['enabled'] );
			}

			update_option( 'nexifymy_security_settings', $settings, false );

			wp_send_json_success( array(
				'module' => $module,
				'message' => __( 'Settings saved successfully', 'nexifymy-security' ),
			) );
		}
		
		// Sanitize based on module type
		$sanitized = array();
		foreach ( $module_settings as $key => $value ) {
			$key = sanitize_key( $key );
			if ( is_array( $value ) ) {
				$sanitized[ $key ] = array_map( 'sanitize_text_field', $value );
			} elseif ( is_numeric( $value ) ) {
				$sanitized[ $key ] = absint( $value );
			} else {
				$sanitized[ $key ] = sanitize_text_field( $value );
			}
		}

		$settings[ $module ] = $sanitized;
		update_option( 'nexifymy_security_settings', $settings, false );

		wp_send_json_success( array(
			'module' => $module,
			'message' => __( 'Settings saved successfully', 'nexifymy-security' ),
		) );
	}

	/**
	 * Render the main dashboard.
	 */
	public function render_dashboard() {
		$security_data = $this->calculate_security_score();
		$score = $security_data['score'];
		$score_class = $score >= 80 ? 'good' : ( $score >= 50 ? 'warning' : 'critical' );
		$settings = get_option( 'nexifymy_security_settings', array() );
		
		// All security modules organized by category
		$module_categories = array(
			'firewall' => array(
				'title' => __( 'Firewall & Protection', 'nexifymy-security' ),
				'icon' => 'shield-alt',
				'modules' => array(
					'waf' => array( 'name' => __( 'Web Application Firewall', 'nexifymy-security' ), 'desc' => __( 'Block malicious requests', 'nexifymy-security' ), 'icon' => 'shield', 'enabled' => true, 'tooltip' => __( 'Protects against SQL injection, XSS, and malicious requests. Safe to enable - only blocks harmful traffic.', 'nexifymy-security' ) ),
					'rate_limiter' => array( 'name' => __( 'Rate Limiting', 'nexifymy-security' ), 'desc' => __( 'Prevent brute force', 'nexifymy-security' ), 'icon' => 'clock', 'enabled' => true, 'tooltip' => __( 'Limits login attempts to prevent brute force attacks. Safe - only affects failed login attempts.', 'nexifymy-security' ) ),
					'ip_blocking' => array( 'name' => __( 'IP Blocking', 'nexifymy-security' ), 'desc' => __( 'Block suspicious IPs', 'nexifymy-security' ), 'icon' => 'dismiss', 'enabled' => ! empty( $settings['modules']['ip_blocking_enabled'] ), 'tooltip' => __( 'Blocks IP addresses that show malicious behavior. Safe - you can whitelist your IP.', 'nexifymy-security' ) ),
					'geo_blocking' => array( 'name' => __( 'Geo Blocking', 'nexifymy-security' ), 'desc' => __( 'Country restrictions', 'nexifymy-security' ), 'icon' => 'location-alt', 'enabled' => ! empty( $settings['modules']['geo_blocking_enabled'] ), 'tooltip' => __( 'Block traffic from specific countries. Configure countries in settings before enabling.', 'nexifymy-security' ) ),
				),
			),
			'scanner' => array(
				'title' => __( 'Malware & Scanning', 'nexifymy-security' ),
				'icon' => 'search',
				'modules' => array(
					'scanner' => array( 'name' => __( 'Malware Scanner', 'nexifymy-security' ), 'desc' => __( 'Detect threats', 'nexifymy-security' ), 'icon' => 'warning', 'enabled' => true, 'tooltip' => __( 'Scans files for malware and suspicious code. Safe - only scans, does not modify files.', 'nexifymy-security' ) ),
					'ai_detection' => array( 'name' => __( 'AI Threat Detection', 'nexifymy-security' ), 'desc' => __( 'Behavioral analysis', 'nexifymy-security' ), 'icon' => 'superhero-alt', 'enabled' => true, 'tooltip' => __( 'Uses AI to detect zero-day threats through behavioral analysis. Learns normal patterns and flags anomalies. Safe - only monitors behavior.', 'nexifymy-security' ) ),
					'core_repair' => array( 'name' => __( 'Core File Repair', 'nexifymy-security' ), 'desc' => __( 'Fix modified files', 'nexifymy-security' ), 'icon' => 'update', 'enabled' => ! empty( $settings['modules']['core_repair_enabled'] ), 'tooltip' => __( 'Repairs modified WordPress core files. Use carefully - backs up before repairing.', 'nexifymy-security' ) ),
					'background_scan' => array( 'name' => __( 'Scheduled Scans', 'nexifymy-security' ), 'desc' => __( 'Automated scanning', 'nexifymy-security' ), 'icon' => 'calendar-alt', 'enabled' => true, 'tooltip' => __( 'Runs automatic malware scans daily. Safe - only scanning, no file changes.', 'nexifymy-security' ) ),
					'vulnerabilities' => array( 'name' => __( 'Vulnerability Check', 'nexifymy-security' ), 'desc' => __( 'Plugin/theme CVEs', 'nexifymy-security' ), 'icon' => 'flag', 'enabled' => true, 'tooltip' => __( 'Checks plugins/themes for known vulnerabilities. Safe - only checks versions.', 'nexifymy-security' ) ),
				),
			),
			'login' => array(
				'title' => __( 'Login & Authentication', 'nexifymy-security' ),
				'icon' => 'lock',
				'modules' => array(
					'two_factor' => array( 'name' => __( 'Two-Factor Auth (2FA)', 'nexifymy-security' ), 'desc' => __( 'Extra login security', 'nexifymy-security' ), 'icon' => 'smartphone', 'enabled' => ! empty( $settings['modules']['two_factor_enabled'] ), 'tooltip' => __( 'Requires second factor for login. Configure your 2FA method before enabling.', 'nexifymy-security' ) ),
					'captcha' => array( 'name' => __( 'CAPTCHA Protection', 'nexifymy-security' ), 'desc' => __( 'Bot prevention', 'nexifymy-security' ), 'icon' => 'forms', 'enabled' => ! empty( $settings['modules']['captcha_enabled'] ), 'tooltip' => __( 'Adds CAPTCHA to login forms. Safe but may affect user experience.', 'nexifymy-security' ) ),
					'password' => array( 'name' => __( 'Password Policies', 'nexifymy-security' ), 'desc' => __( 'Strong passwords', 'nexifymy-security' ), 'icon' => 'admin-network', 'enabled' => true, 'tooltip' => __( 'Enforces strong password requirements for users. Safe - only affects new passwords.', 'nexifymy-security' ) ),
					'login_protection' => array( 'name' => __( 'Login Protection', 'nexifymy-security' ), 'desc' => __( 'Limit login attempts', 'nexifymy-security' ), 'icon' => 'admin-users', 'enabled' => ! empty( $settings['modules']['login_protection_enabled'] ), 'tooltip' => __( 'Additional login security measures. Works with rate limiter.', 'nexifymy-security' ) ),
				),
			),
			'hardening' => array(
				'title' => __( 'WordPress Hardening', 'nexifymy-security' ),
				'icon' => 'admin-tools',
				'modules' => array(
					'file_permissions' => array( 'name' => __( 'File Permissions', 'nexifymy-security' ), 'desc' => __( 'Secure file access', 'nexifymy-security' ), 'icon' => 'media-document', 'enabled' => ! empty( $settings['modules']['file_permissions_enabled'] ), 'tooltip' => __( 'Sets secure file permissions. May require manual adjustment if server has issues.', 'nexifymy-security' ) ),
					'security_headers' => array( 'name' => __( 'Security Headers', 'nexifymy-security' ), 'desc' => __( 'HTTP headers', 'nexifymy-security' ), 'icon' => 'admin-settings', 'enabled' => true, 'tooltip' => __( 'Adds HTTP security headers (X-Frame-Options, CSP). Safe - improves browser security.', 'nexifymy-security' ) ),
					'xmlrpc' => array( 'name' => __( 'XML-RPC Control', 'nexifymy-security' ), 'desc' => __( 'Disable XML-RPC', 'nexifymy-security' ), 'icon' => 'editor-code', 'enabled' => true, 'tooltip' => __( 'Disables XML-RPC to prevent attacks. Safe unless you use Jetpack or mobile apps.', 'nexifymy-security' ) ),
					'rest_api' => array( 'name' => __( 'REST API Security', 'nexifymy-security' ), 'desc' => __( 'API restrictions', 'nexifymy-security' ), 'icon' => 'rest-api', 'enabled' => ! empty( $settings['modules']['rest_api_enabled'] ), 'tooltip' => __( 'Restricts REST API access. May affect plugins that use REST API.', 'nexifymy-security' ) ),
					'file_editor' => array( 'name' => __( 'File Editor', 'nexifymy-security' ), 'desc' => __( 'Disable WP editor', 'nexifymy-security' ), 'icon' => 'edit', 'enabled' => ! empty( $settings['modules']['file_editor_disabled'] ), 'tooltip' => __( 'Disables built-in theme/plugin editor. Safe - prevents code editing in admin.', 'nexifymy-security' ) ),
				),
			),
			'api' => array(
				'title' => __( 'API & Headless Security', 'nexifymy-security' ),
				'icon' => 'cloud',
				'modules' => array(
					'api_security' => array( 'name' => __( 'API Security', 'nexifymy-security' ), 'desc' => __( 'REST API protection', 'nexifymy-security' ), 'icon' => 'admin-network', 'enabled' => true, 'tooltip' => __( 'Protects REST API with JWT auth, rate limiting, and CORS. Essential for headless WordPress.', 'nexifymy-security' ) ),
					'graphql_security' => array( 'name' => __( 'GraphQL Security', 'nexifymy-security' ), 'desc' => __( 'WPGraphQL protection', 'nexifymy-security' ), 'icon' => 'networking', 'enabled' => true, 'tooltip' => __( 'Secures WPGraphQL with query depth limits, complexity checks, and rate limiting. Safe for headless setups.', 'nexifymy-security' ) ),
				),
			),
			'monitoring' => array(
				'title' => __( 'Monitoring & Alerts', 'nexifymy-security' ),
				'icon' => 'chart-line',
				'modules' => array(
					'live_traffic' => array( 'name' => __( 'Live Traffic', 'nexifymy-security' ), 'desc' => __( 'Real-time monitoring', 'nexifymy-security' ), 'icon' => 'visibility', 'enabled' => true, 'tooltip' => __( 'Monitors real-time traffic. Safe - only tracks visits.', 'nexifymy-security' ) ),
					'notifications' => array( 'name' => __( 'Email Notifications', 'nexifymy-security' ), 'desc' => __( 'Security alerts', 'nexifymy-security' ), 'icon' => 'email', 'enabled' => true, 'tooltip' => __( 'Sends email alerts for security events. Safe - configure email settings first.', 'nexifymy-security' ) ),
					'audit_log' => array( 'name' => __( 'Security Logs', 'nexifymy-security' ), 'desc' => __( 'Activity tracking', 'nexifymy-security' ), 'icon' => 'list-view', 'enabled' => true, 'tooltip' => __( 'Logs security events for review. Safe - only records activity.', 'nexifymy-security' ) ),
					'self_protection' => array( 'name' => __( 'Self Protection', 'nexifymy-security' ), 'desc' => __( 'Plugin integrity', 'nexifymy-security' ), 'icon' => 'shield', 'enabled' => true, 'tooltip' => __( 'Protects plugin files from modification. Safe - prevents tampering.', 'nexifymy-security' ) ),
				),
			),
			'tools' => array(
				'title' => __( 'Tools & Utilities', 'nexifymy-security' ),
				'icon' => 'admin-generic',
				'modules' => array(
					'quarantine' => array( 'name' => __( 'Quarantine', 'nexifymy-security' ), 'desc' => __( 'Isolate threats', 'nexifymy-security' ), 'icon' => 'vault', 'enabled' => true, 'tooltip' => __( 'Isolates suspicious files without deleting. Safe - files can be restored.', 'nexifymy-security' ) ),
					'database' => array( 'name' => __( 'Database Security', 'nexifymy-security' ), 'desc' => __( 'Backups & cleanup', 'nexifymy-security' ), 'icon' => 'database', 'enabled' => ! empty( $settings['modules']['database_enabled'] ), 'tooltip' => __( 'Database backup and optimization. Configure backup schedule before enabling.', 'nexifymy-security' ) ),
					'cdn' => array( 'name' => __( 'CDN Integration', 'nexifymy-security' ), 'desc' => __( 'Cloudflare & more', 'nexifymy-security' ), 'icon' => 'cloud', 'enabled' => ! empty( $settings['modules']['cdn_enabled'] ), 'tooltip' => __( 'Integrates with CDN services. Configure CDN credentials before enabling.', 'nexifymy-security' ) ),
				),
			),
		);

		// Get recent activity
		$recent_events = array();
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$recent_events = NexifyMy_Security_Logger::get_recent_events( 5 );
		}

		// Get stats
		$stats = array( 'total' => 0, 'blocked' => 0 );
		if ( class_exists( 'NexifyMy_Security_Logger' ) ) {
			$log_stats = NexifyMy_Security_Logger::get_stats( 7 );
			$stats['total'] = isset( $log_stats['total_events'] ) ? $log_stats['total_events'] : 0;
			$stats['blocked'] = isset( $log_stats['by_severity']['critical'] ) ? $log_stats['by_severity']['critical'] : 0;
		}
		
		$last_scan = get_option( 'nexifymy_last_scan' );
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Dashboard', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			
			<!-- Header -->
			<div class="nms-header">
				<div class="nms-header-left">
					<div class="nms-logo">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-header-title">
						<h2>
							<?php _e( 'NexifyMy Security', 'nexifymy-security' ); ?>
							<span class="nms-version">v<?php echo esc_html( NEXIFYMY_SECURITY_VERSION ); ?></span>
						</h2>
						<p><?php _e( 'Enterprise-Grade WordPress Security', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-header-actions">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-primary">
						<span class="dashicons dashicons-search"></span>
						<?php _e( 'Run Scan', 'nexifymy-security' ); ?>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-settings' ) ); ?>" class="nms-btn nms-btn-secondary">
						<span class="dashicons dashicons-admin-generic"></span>
						<?php _e( 'Settings', 'nexifymy-security' ); ?>
					</a>
				</div>
			</div>

			<!-- Horizontal Navigation Tabs (Hidden as per user request to use sidebar) -->
			<!--
			<div class="nms-tabs">
				<a href="javascript:void(0);" class="nms-tab active" data-tab="overview">
					<span class="dashicons dashicons-dashboard"></span>
					<?php _e( 'Dashboard', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="firewall">
					<span class="dashicons dashicons-shield"></span>
					<?php _e( 'Firewall', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="scanner">
					<span class="dashicons dashicons-search"></span>
					<?php _e( 'Scan', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="login-security">
					<span class="dashicons dashicons-lock"></span>
					<?php _e( 'Login Security', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="hardening">
					<span class="dashicons dashicons-admin-tools"></span>
					<?php _e( 'Hardening', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="modules">
					<span class="dashicons dashicons-admin-plugins"></span>
					<?php _e( 'Modules', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="live-traffic">
					<span class="dashicons dashicons-visibility"></span>
					<?php _e( 'Live Traffic', 'nexifymy-security' ); ?>
				</a>
				<a href="javascript:void(0);" class="nms-tab" data-tab="logs">
					<span class="dashicons dashicons-list-view"></span>
					<?php _e( 'Logs', 'nexifymy-security' ); ?>
					<?php if ( $stats['blocked'] > 0 ) : ?>
						<span class="nms-tab-badge"><?php echo intval( $stats['blocked'] ); ?></span>
					<?php endif; ?>
				</a>
			</div>
			-->
			
			<div class="nms-main-content">

			<!-- Main Content Area (Full Width) -->
				<!-- Tab Content Container -->
				<div class="nms-tab-content-wrapper">
				
				<!-- Overview Tab Content -->
				<div class="nms-tab-content active" id="nms-tab-overview">
					
					<!-- Stats Row -->
					<div class="nms-stats-row">
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo esc_html( $score ); ?>%</h4>
						<p><?php _e( 'Security Score', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-dismiss"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo intval( $stats['blocked'] ); ?></h4>
						<p><?php _e( 'Threats Blocked', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-yes-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo ( $last_scan && isset( $last_scan['time'] ) ) ? esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : '--'; ?></h4>
						<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon purple">
						<span class="dashicons dashicons-chart-line"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo intval( $stats['total'] ); ?></h4>
						<p><?php _e( 'Events (7 days)', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Main Grid -->
			<div class="nms-dashboard-grid">
				
				<!-- Main Column -->
				<div class="nms-main-col">
					
					<!-- Security Score Hero -->
					<div class="nms-card">
						<div class="nms-score-hero">
							<div class="nms-score-circle-container">
								<svg class="nms-score-svg" viewBox="0 0 100 100">
									<circle class="nms-score-bg" cx="50" cy="50" r="42" />
									<circle class="nms-score-progress <?php echo esc_attr( $score_class ); ?>" cx="50" cy="50" r="42" 
										stroke-dasharray="<?php echo esc_attr( ( $score / 100 ) * 264 ); ?> 264" />
								</svg>
								<div class="nms-score-value">
									<strong><?php echo esc_html( $score ); ?></strong>
									<span>/100</span>
								</div>
							</div>
							<div class="nms-score-details">
								<h3><?php _e( 'Security Status', 'nexifymy-security' ); ?></h3>
								<div class="nms-score-status <?php echo esc_attr( $score_class ); ?>">
									<span class="dashicons dashicons-<?php echo $score >= 80 ? 'yes-alt' : ( $score >= 50 ? 'warning' : 'dismiss' ); ?>"></span>
									<?php
									if ( $score >= 80 ) {
										_e( 'Your site is well protected', 'nexifymy-security' );
									} elseif ( $score >= 50 ) {
										_e( 'Some improvements recommended', 'nexifymy-security' );
									} else {
										_e( 'Immediate action required', 'nexifymy-security' );
									}
									?>
								</div>
								<?php if ( ! empty( $security_data['issues'] ) ) : ?>
									<ul class="nms-issues-list">
										<?php foreach ( array_slice( $security_data['issues'], 0, 4 ) as $issue ) : ?>
											<li>
												<span class="dashicons dashicons-warning"></span>
												<?php echo esc_html( $issue ); ?>
											</li>
										<?php endforeach; ?>
									</ul>
								<?php endif; ?>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-primary">
									<?php _e( 'Run Full Security Scan', 'nexifymy-security' ); ?>
								</a>
							</div>
						</div>
					</div>

					<!-- Module Categories -->
					<?php foreach ( $module_categories as $cat_key => $category ) : ?>
						<div class="nms-modules-section">
							<div class="nms-section-title">
								<h3>
									<span class="dashicons dashicons-<?php echo esc_attr( $category['icon'] ); ?>"></span>
									<?php echo esc_html( $category['title'] ); ?>
								</h3>
								<span class="nms-count"><?php echo count( $category['modules'] ); ?> <?php _e( 'modules', 'nexifymy-security' ); ?></span>
							</div>
							<div class="nms-modules-grid">
								<?php
								// Map categories to admin pages since tabs are hidden
								$page_map = array(
									'firewall' => 'nexifymy-security-firewall',
									'scanner' => 'nexifymy-security-scanner',
									'login' => 'nexifymy-security-firewall', 
									'hardening' => 'nexifymy-security-modules',
									'monitoring' => 'nexifymy-security-tools', // Live Traffic is here
									'tools' => 'nexifymy-security-tools',
									'api_security' => 'nexifymy-security-modules',
								);
								
								foreach ( $category['modules'] as $mod_key => $module ) : 
									$target_page = isset( $page_map[ $cat_key ] ) ? $page_map[ $cat_key ] : 'nexifymy-security-modules';
									$url = admin_url( 'admin.php?page=' . $target_page );
									
									// Add specific tabs/pages for known module mappings
									if ($mod_key === 'rate_limiter') {
										$url = admin_url( 'admin.php?page=nexifymy-security-firewall&tab=rate' );
									} elseif ($mod_key === 'quarantine') {
										$url = admin_url( 'admin.php?page=nexifymy-security-scanner&tab=quarantine' );
									} elseif ($mod_key === 'database') {
										$url = admin_url( 'admin.php?page=nexifymy-security-tools&tab=database' );
									} elseif ($mod_key === 'live_traffic') {
										$url = admin_url( 'admin.php?page=nexifymy-security-tools&tab=traffic' );
									}
								?>
									<div class="nms-module-card <?php echo $module['enabled'] ? 'active' : ''; ?>" title="<?php echo esc_attr( $module['tooltip'] ); ?>">
										<a href="<?php echo esc_url( $url ); ?>" class="nms-module-clickable">
											<div class="nms-module-icon">
												<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
											</div>
											<div class="nms-module-info">
												<span class="nms-module-name"><?php echo esc_html( $module['name'] ); ?></span>
												<span class="nms-module-desc"><?php echo esc_html( $module['desc'] ); ?></span>
											</div>
										</a>
										<label class="nms-toggle" onclick="event.stopPropagation();">
											<input type="checkbox" <?php checked( $module['enabled'] ); ?> data-module="<?php echo esc_attr( $mod_key ); ?>">
											<span class="nms-toggle-slider"></span>
										</label>
									</div>
								<?php endforeach; ?>
							</div>
						</div>
					<?php endforeach; ?>
				</div>

				<!-- Side Column -->
				<div class="nms-side-col">
					
					<!-- Quick Actions -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-performance"></span>
								<?php _e( 'Quick Actions', 'nexifymy-security' ); ?>
							</h2>
						</div>
						<div class="nms-card-body">
							<div class="nms-quick-actions">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner&mode=quick' ) ); ?>" class="nms-action-btn primary">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-search"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Fast security check', 'nexifymy-security' ); ?></span>
									</div>
								</a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner&mode=deep' ) ); ?>" class="nms-action-btn">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-shield"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Full malware analysis', 'nexifymy-security' ); ?></span>
									</div>
								</a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-action-btn">
									<div class="nms-action-icon">
										<span class="dashicons dashicons-admin-tools"></span>
									</div>
									<div class="nms-action-text">
										<strong><?php _e( 'Harden Site', 'nexifymy-security' ); ?></strong>
										<span><?php _e( 'Apply security fixes', 'nexifymy-security' ); ?></span>
									</div>
								</a>
							</div>
						</div>
					</div>

					<!-- Recent Activity -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-backup"></span>
								<?php _e( 'Recent Activity', 'nexifymy-security' ); ?>
							</h2>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-logs' ) ); ?>" class="nms-card-header-action">
								<?php _e( 'View All', 'nexifymy-security' ); ?>
							</a>
						</div>
						<div class="nms-card-body no-padding">
							<?php if ( ! empty( $recent_events ) ) : ?>
								<ul class="nms-activity-list">
									<?php foreach ( $recent_events as $event ) : ?>
										<li class="nms-activity-item">
											<div class="nms-activity-icon <?php echo esc_attr( $event['severity'] ?? 'info' ); ?>">
												<span class="dashicons dashicons-<?php echo esc_attr( $event['icon'] ?? 'info' ); ?>"></span>
											</div>
											<div class="nms-activity-content">
												<div class="nms-activity-title"><?php echo esc_html( $event['message'] ?? '' ); ?></div>
												<div class="nms-activity-meta"><?php echo esc_html( $event['ip'] ?? '' ); ?></div>
											</div>
											<div class="nms-activity-time"><?php echo esc_html( human_time_diff( $event['time'] ?? time() ) ); ?></div>
										</li>
									<?php endforeach; ?>
								</ul>
							<?php else : ?>
								<div class="nms-empty-state">
									<span class="dashicons dashicons-info"></span>
									<h4><?php _e( 'No Recent Activity', 'nexifymy-security' ); ?></h4>
									<p><?php _e( 'Security events will appear here.', 'nexifymy-security' ); ?></p>
								</div>
							<?php endif; ?>
						</div>
					</div>

					<!-- System Info -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h2>
								<span class="dashicons dashicons-info"></span>
								<?php _e( 'System Status', 'nexifymy-security' ); ?>
							</h2>
						</div>
						<div class="nms-card-body">
							<ul class="nms-system-list">
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'WordPress', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value good"><?php echo esc_html( get_bloginfo( 'version' ) ); ?></span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'PHP Version', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value <?php echo version_compare( PHP_VERSION, '7.4', '>=' ) ? 'good' : 'warning'; ?>">
										<?php echo esc_html( PHP_VERSION ); ?>
									</span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'SSL Status', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value <?php echo is_ssl() ? 'good' : 'bad'; ?>">
										<?php echo is_ssl() ? __( 'Active', 'nexifymy-security' ) : __( 'Not Active', 'nexifymy-security' ); ?>
									</span>
								</li>
								<li class="nms-system-item">
									<span class="nms-system-label"><?php _e( 'Plugin Version', 'nexifymy-security' ); ?></span>
									<span class="nms-system-value"><?php echo esc_html( NEXIFYMY_SECURITY_VERSION ); ?></span>
								</li>
							</ul>
						</div>
					</div>

					</div>
			</div>
			</div><!-- End #nms-tab-overview -->

				<!-- Firewall Tab Content -->
			<div class="nms-tab-content" id="nms-tab-firewall">
				<?php
				$fw_settings = isset( $settings['firewall'] ) ? $settings['firewall'] : array();
				$fw_enabled = ! empty( $settings['modules']['waf_enabled'] );
				?>
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Web Application Firewall (WAF)', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div class="nms-settings-row">
							<div class="nms-setting-item">
								<div class="nms-setting-info">
									<span class="dashicons dashicons-shield-alt"></span>
									<div>
										<strong><?php _e( 'Enable Firewall', 'nexifymy-security' ); ?></strong>
										<p><?php _e( 'Block malicious requests and attacks', 'nexifymy-security' ); ?></p>
									</div>
								</div>
								<label class="nms-toggle">
									<input type="checkbox" data-module="waf" <?php checked( $fw_enabled ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<h4 style="margin: 20px 0 15px; font-size: 14px;"><?php _e( 'Protection Rules', 'nexifymy-security' ); ?></h4>
						<div class="nms-quick-settings-grid">
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-database"></span>
								<span><?php _e( 'SQL Injection', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="sql_injection" <?php checked( ! empty( $fw_settings['sql_injection'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-editor-code"></span>
								<span><?php _e( 'XSS Protection', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="xss_protection" <?php checked( ! empty( $fw_settings['xss_protection'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-media-document"></span>
								<span><?php _e( 'File Inclusion', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="file_inclusion" <?php checked( ! empty( $fw_settings['file_inclusion'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
							<div class="nms-quick-setting">
								<span class="dashicons dashicons-admin-users"></span>
								<span><?php _e( 'Bad Bots', 'nexifymy-security' ); ?></span>
								<label class="nms-toggle nms-toggle-sm">
									<input type="checkbox" name="bad_bots" <?php checked( ! empty( $fw_settings['bad_bots'] ) || empty( $fw_settings ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-firewall' ) ); ?>" class="nms-btn nms-btn-secondary">
								<span class="dashicons dashicons-admin-generic"></span>
								<?php _e( 'Advanced Firewall Settings', 'nexifymy-security' ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>


				<!-- Scanner Tab Content -->
			<div class="nms-tab-content" id="nms-tab-scanner">
				<?php
				$scanner_enabled = ! empty( $settings['modules']['scanner_enabled'] ) || ! isset( $settings['modules']['scanner_enabled'] );
				?>
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div class="nms-settings-row">
							<div class="nms-setting-item">
								<div class="nms-setting-info">
									<span class="dashicons dashicons-search"></span>
									<div>
										<strong><?php _e( 'Enable Scanner Module', 'nexifymy-security' ); ?></strong>
										<p><?php _e( 'Detect malware, backdoors, and suspicious code', 'nexifymy-security' ); ?></p>
									</div>
								</div>
								<label class="nms-toggle">
									<input type="checkbox" data-module="scanner" <?php checked( $scanner_enabled ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</div>
						</div>
						
						<h4 style="margin: 20px 0 15px; font-size: 14px;"><?php _e( 'Quick Scan Actions', 'nexifymy-security' ); ?></h4>
						<div class="nms-scan-buttons">
							<button type="button" class="nms-btn nms-btn-primary scan-btn" data-mode="quick">
								<span class="dashicons dashicons-search"></span>
								<?php _e( 'Quick Scan', 'nexifymy-security' ); ?>
							</button>
							<button type="button" class="nms-btn nms-btn-secondary scan-btn" data-mode="standard">
								<span class="dashicons dashicons-shield"></span>
								<?php _e( 'Standard Scan', 'nexifymy-security' ); ?>
							</button>
							<button type="button" class="nms-btn nms-btn-secondary scan-btn" data-mode="deep">
								<span class="dashicons dashicons-shield-alt"></span>
								<?php _e( 'Deep Scan', 'nexifymy-security' ); ?>
							</button>
						</div>
						
						<!-- Scan Progress (hidden until scan starts) -->
						<div id="scanner-progress" class="nms-scan-progress" style="display: none; margin-top: 20px;">
							<div class="nms-progress-container">
								<div class="nms-progress-bar">
									<div class="nms-progress-fill" style="width: 0%"></div>
								</div>
								<div class="nms-progress-info">
									<span class="nms-progress-percent">0%</span>
									<span class="nms-progress-status"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
								</div>
							</div>
						</div>
						
						<!-- Scan Results (hidden until scan completes) -->
						<div id="scanner-results" style="display: none; margin-top: 20px;"></div>
						
						<?php if ( $last_scan && isset( $last_scan['time'] ) ) : ?>
						<div style="margin-top: 20px; padding: 15px; background: var(--nms-gray-50); border-radius: var(--nms-radius-md);">
							<strong><?php _e( 'Last Scan:', 'nexifymy-security' ); ?></strong>
							<?php echo esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ); ?> <?php _e( 'ago', 'nexifymy-security' ); ?>
							<?php if ( isset( $last_scan['results']['threats_found'] ) ) : ?>
								&mdash; <span style="color: <?php echo $last_scan['results']['threats_found'] > 0 ? 'var(--nms-danger)' : 'var(--nms-success)'; ?>;">
									<?php echo intval( $last_scan['results']['threats_found'] ); ?> <?php _e( 'threats found', 'nexifymy-security' ); ?>
								</span>
							<?php endif; ?>
						</div>
						<?php endif; ?>
						
						<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-scanner' ) ); ?>" class="nms-btn nms-btn-secondary">
								<span class="dashicons dashicons-admin-generic"></span>
								<?php _e( 'Advanced Scanner Options', 'nexifymy-security' ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>


				<!-- Modules Tab Content -->
				<div class="nms-tab-content" id="nms-tab-modules">
					<div class="nms-card">
						<div class="nms-card-header">
							<h3><?php _e( 'Security Modules', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'Enable or disable security modules.', 'nexifymy-security' ); ?></p>
						</div>
						<div class="nms-card-body">
							<div class="nms-modules-list">
								<?php
								$modules = array(
									'waf'          => array( 'name' => __( 'WAF Firewall', 'nexifymy-security' ), 'icon' => 'shield' ),
									'scanner'      => array( 'name' => __( 'Malware Scanner', 'nexifymy-security' ), 'icon' => 'search' ),
									'rate_limiter' => array( 'name' => __( 'Rate Limiter', 'nexifymy-security' ), 'icon' => 'lock' ),
									'two_factor'   => array( 'name' => __( '2FA', 'nexifymy-security' ), 'icon' => 'smartphone' ),
								);

								$settings = class_exists( 'NexifyMy_Security_Settings' )
									? NexifyMy_Security_Settings::get_all()
									: get_option( 'nexifymy_security_settings', array() );

								foreach ( $modules as $key => $module ) :
									$enabled = ! empty( $settings['modules'][ $key . '_enabled' ] );
								?>
								<div class="nms-module-row">
									<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
									<span class="nms-module-name"><?php echo esc_html( $module['name'] ); ?></span>
									<label class="nms-toggle">
										<input type="checkbox" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $enabled ); ?>>
										<span class="nms-toggle-slider"></span>
									</label>
								</div>
								<?php endforeach; ?>
							</div>
						</div>
					</div>
				</div>

				<!-- Tools Tab Content -->
				<div class="nms-tab-content" id="nms-tab-tools">
					<div class="nms-card">
						<div class="nms-card-header"><h3><?php _e( 'Security Tools', 'nexifymy-security' ); ?></h3></div>
						<div class="nms-card-body">
							<div class="nms-tools-grid">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-quarantine' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?></a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-database' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-database"></span> <?php _e( 'Database', 'nexifymy-security' ); ?></a>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-tool-link"><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Hardening', 'nexifymy-security' ); ?></a>
							</div>
						</div>
					</div>
				</div>

				<!-- Logs Tab Content -->
				<div class="nms-tab-content" id="nms-tab-logs">
					<?php $this->render_logs_tab(); ?>
				</div>

				<!-- Settings Tab Content -->
				<div class="nms-tab-content" id="nms-tab-settings">
					<div class="nms-card">
						<div class="nms-card-header"><h3><?php _e( 'Settings', 'nexifymy-security' ); ?></h3></div>
						<div class="nms-card-body">
							<p><?php _e( 'Configure plugin settings.', 'nexifymy-security' ); ?></p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-settings' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'Open Settings', 'nexifymy-security' ); ?></a>
						</div>
					</div>
				</div>

			<!-- Login Security Tab Content -->
		<div class="nms-tab-content" id="nms-tab-login-security">
			<?php
			$login_settings = isset( $settings['login'] ) ? $settings['login'] : array();
			$two_factor_enabled = ! empty( $settings['modules']['two_factor_enabled'] );
			$rate_limiter_enabled = ! empty( $settings['modules']['rate_limiter_enabled'] );
			?>
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Login Security', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div class="nms-quick-settings-grid nms-quick-settings-grid-2">
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-smartphone"></span>
								<strong><?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Require a second factor for login verification', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" data-module="two_factor" <?php checked( $two_factor_enabled ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-lock"></span>
								<strong><?php _e( 'Login Rate Limiting', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Limit login attempts to prevent brute force attacks', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" data-module="rate_limiter" <?php checked( $rate_limiter_enabled ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-shield"></span>
								<strong><?php _e( 'Login CAPTCHA', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Add CAPTCHA verification to login forms', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" name="login_captcha" <?php checked( ! empty( $login_settings['captcha_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-quick-setting-card">
							<div class="nms-quick-setting-header">
								<span class="dashicons dashicons-admin-network"></span>
								<strong><?php _e( 'Strong Passwords', 'nexifymy-security' ); ?></strong>
							</div>
							<p><?php _e( 'Enforce strong password requirements', 'nexifymy-security' ); ?></p>
							<label class="nms-toggle">
								<input type="checkbox" name="strong_passwords" <?php checked( ! empty( $login_settings['strong_passwords'] ) || empty( $login_settings ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
					</div>
					
					<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-modules' ) ); ?>" class="nms-btn nms-btn-secondary">
							<span class="dashicons dashicons-admin-generic"></span>
							<?php _e( 'Advanced Login Settings', 'nexifymy-security' ); ?>
						</a>
					</div>
				</div>
			</div>
		</div>

			<!-- Hardening Tab Content -->
		<div class="nms-tab-content" id="nms-tab-hardening">
			<?php
			$hardening_settings = isset( $settings['hardening'] ) ? $settings['hardening'] : array();
			?>
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'WordPress Hardening', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<p style="color: var(--nms-gray-600); margin-bottom: 20px;"><?php _e( 'Apply security hardening measures to protect your WordPress installation.', 'nexifymy-security' ); ?></p>
					
					<div class="nms-hardening-checklist">
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-dismiss" style="color: var(--nms-danger);"></span>
								<div>
									<strong><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent XML-RPC attacks and brute force attempts', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_xmlrpc" <?php checked( ! empty( $hardening_settings['disable_xmlrpc'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-edit" style="color: var(--nms-warning);"></span>
								<div>
									<strong><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent code editing in WordPress admin', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_file_editor" <?php checked( ! empty( $hardening_settings['disable_file_editor'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-rest-api" style="color: var(--nms-info);"></span>
								<div>
									<strong><?php _e( 'Restrict REST API', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Limit REST API access to authenticated users', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="restrict_rest_api" <?php checked( ! empty( $hardening_settings['restrict_rest_api'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-visibility" style="color: var(--nms-gray-500);"></span>
								<div>
									<strong><?php _e( 'Disable Directory Browsing', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Prevent directory listing via .htaccess', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_directory_browsing" <?php checked( ! empty( $hardening_settings['disable_directory_browsing'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
						
						<div class="nms-hardening-item">
							<div class="nms-hardening-info">
								<span class="dashicons dashicons-shield" style="color: var(--nms-success);"></span>
								<div>
									<strong><?php _e( 'Security Headers', 'nexifymy-security' ); ?></strong>
									<p><?php _e( 'Add HTTP security headers (X-Frame-Options, CSP, etc.)', 'nexifymy-security' ); ?></p>
								</div>
							</div>
							<label class="nms-toggle">
								<input type="checkbox" name="security_headers" <?php checked( ! empty( $hardening_settings['security_headers'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</div>
					</div>
					
					<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--nms-border);">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-hardening' ) ); ?>" class="nms-btn nms-btn-secondary">
							<span class="dashicons dashicons-admin-generic"></span>
							<?php _e( 'Advanced Hardening Options', 'nexifymy-security' ); ?>
						</a>
					</div>
				</div>
			</div>
		</div>


			<!-- Live Traffic Tab Content -->
			<div class="nms-tab-content" id="nms-tab-live-traffic">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Live Traffic', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<p><?php _e( 'Monitor real-time traffic and visitor activity.', 'nexifymy-security' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-tools' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'View Live Traffic', 'nexifymy-security' ); ?></a>
					</div>
				</div>
			</div>

			<!-- Notifications Tab Content -->
			<div class="nms-tab-content" id="nms-tab-notifications">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Notification Settings', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<p><?php _e( 'Configure email alerts and notifications.', 'nexifymy-security' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-notifications' ) ); ?>" class="nms-btn nms-btn-primary"><?php _e( 'Manage Notifications', 'nexifymy-security' ); ?></a>
					</div>
				</div>
			</div>

			<!-- Help Tab Content -->
			<div class="nms-tab-content" id="nms-tab-help">
				<div class="nms-card">
					<div class="nms-card-header"><h3><?php _e( 'Help & Documentation', 'nexifymy-security' ); ?></h3></div>
					<div class="nms-card-body">
						<h4><?php _e( 'Getting Started', 'nexifymy-security' ); ?></h4>
						<ul style="list-style: disc; margin-left: 20px; margin-bottom: 20px;">
							<li><?php _e( 'Run a security scan to identify vulnerabilities', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Enable firewall protection to block attacks', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Configure 2FA for enhanced login security', 'nexifymy-security' ); ?></li>
							<li><?php _e( 'Review security logs regularly', 'nexifymy-security' ); ?></li>
						</ul>
						<h4><?php _e( 'Need Support?', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Contact our support team for assistance with NexifyMy Security.', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			</div><!-- End .nms-tab-content-wrapper -->

			</div><!-- End .nms-main-content -->

	</div><!-- End .wrap -->
		<?php
	}

	/**
	 * Render the scanner page.
	 */
	public function render_scanner() {
		$last_scan = get_option( 'nexifymy_last_scan' );
		$signature_version = get_option( 'nexifymy_signature_version', '1.0.0' );
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-search"></span> <?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></h2>
				<p><?php _e( 'Scan your website for malware and security vulnerabilities.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Scanner Stats -->
			<div class="nms-stats-row">
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-clock"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo ( $last_scan && isset( $last_scan['time'] ) ) ? esc_html( human_time_diff( strtotime( $last_scan['time'] ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : '--'; ?></h4>
						<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-warning"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['threats_found'] ) ? intval( $last_scan['results']['threats_found'] ) : '0'; ?></h4>
						<p><?php _e( 'Threats Found', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-media-default"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['files_scanned'] ) ? number_format( intval( $last_scan['results']['files_scanned'] ) ) : '0'; ?></h4>
						<p><?php _e( 'Files Scanned', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon purple">
						<span class="dashicons dashicons-database"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo esc_html( $signature_version ); ?></h4>
						<p><?php _e( 'Definitions', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon success">
						<span class="dashicons dashicons-yes-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['files_clean'] ) ? number_format( intval( $last_scan['results']['files_clean'] ) ) : '0'; ?></h4>
						<p><?php _e( 'Clean Files', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon warning">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $last_scan['results']['quarantined'] ) ? intval( $last_scan['results']['quarantined'] ) : '0'; ?></h4>
						<p><?php _e( 'Quarantined', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Scan Modes -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Start a New Scan', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
				<div class="nms-scan-modes-grid">
					<!-- Quick Scan -->
					<div class="nms-scan-mode-card" data-mode="quick">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-search"></span>
						</div>
						<h4><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Scan critical areas only', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'High-risk areas only', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Fast execution', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Checks for web shells', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>

					<!-- Standard Scan -->
					<div class="nms-scan-mode-card" data-mode="standard">
						<div class="nms-recommended-badge"><?php _e( 'Recommended', 'nexifymy-security' ); ?></div>
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield"></span>
						</div>
						<h4><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Full malware scan', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full malware signatures', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Plugin & Theme analysis', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Database security check', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>

					<!-- Deep Scan -->
					<div class="nms-scan-mode-card" data-mode="deep">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield-alt"></span>
						</div>
						<h4><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Comprehensive analysis', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Exhaustive file scan', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Heuristic pattern detection', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Core WordPress integrity', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
				</div>
					</div>
				</div>
			</div>

			<!-- Scan Progress -->
			<div id="scanner-progress" class="nms-card" style="display: none; margin-top: 20px;">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-update spin"></span> <?php _e( 'Scanning...', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div class="nms-progress-container">
						<div class="nms-progress-bar">
							<div class="nms-progress-fill" style="width: 0%"></div>
						</div>
						<div class="nms-progress-info">
							<span class="nms-progress-percent">0%</span>
							<span class="nms-progress-status"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
						</div>
					</div>
					<p class="nms-scan-file-current" style="margin-top: 10px; color: var(--nms-gray-500); font-size: 12px;"></p>
				</div>
			</div>

			<!-- Scan Results -->
			<div id="scanner-results" class="nms-card" style="display: none; margin-top: 20px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Scan Results', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div id="results-summary" style="margin-bottom: 20px;"></div>
					<table class="widefat" id="results-table">
						<thead>
							<tr>
								<th><?php _e( 'File', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Threat', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="results-content">
						</tbody>
					</table>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the firewall page.
	 */
	public function render_firewall() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$fw_settings = isset( $settings['firewall'] ) ? $settings['firewall'] : array();
		$blocked_count = get_option( 'nexifymy_blocked_requests_count', 0 );
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Firewall Settings', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-shield"></span> <?php _e( 'Firewall Settings', 'nexifymy-security' ); ?></h2>
				<p><?php _e( 'Configure Web Application Firewall (WAF) to protect your site.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Firewall Stats -->
			<div class="nms-stats-row" style="margin-bottom: 20px;">
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-shield-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo empty( $fw_settings['enabled'] ) ? __( 'Disabled', 'nexifymy-security' ) : __( 'Active', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'WAF Status', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon red">
						<span class="dashicons dashicons-dismiss"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo number_format( intval( $blocked_count ) ); ?></h4>
						<p><?php _e( 'Blocked Attacks', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-admin-site-alt3"></span>
					</div>
					<div class="nms-stat-content">
						<h4><?php echo isset( $fw_settings['mode'] ) ? ucfirst( esc_html( $fw_settings['mode'] ) ) : 'Standard'; ?></h4>
						<p><?php _e( 'Protection Mode', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- WAF Settings -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Firewall Configuration', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table" id="firewall-settings">
						<tr>
							<th><?php _e( 'Enable Firewall', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="fw-enabled" <?php checked( ! empty( $fw_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
								<p class="description"><?php _e( 'Enable Web Application Firewall protection.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Protection Mode', 'nexifymy-security' ); ?></th>
							<td>
								<select id="fw-mode">
									<option value="standard" <?php selected( $fw_settings['mode'] ?? 'standard', 'standard' ); ?>><?php _e( 'Standard - Balanced protection', 'nexifymy-security' ); ?></option>
									<option value="strict" <?php selected( $fw_settings['mode'] ?? '', 'strict' ); ?>><?php _e( 'Strict - Maximum security', 'nexifymy-security' ); ?></option>
									<option value="learning" <?php selected( $fw_settings['mode'] ?? '', 'learning' ); ?>><?php _e( 'Learning - Log only, no blocking', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<!-- Protection Rules -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Protection Rules', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table" id="firewall-rules">
						<tr>
							<th><?php _e( 'SQL Injection Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="sql_injection" <?php checked( $fw_settings['sql_injection'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'XSS Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="xss_protection" <?php checked( $fw_settings['xss_protection'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'File Inclusion Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="file_inclusion" <?php checked( $fw_settings['file_inclusion'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php _e( 'Bot & Crawler Protection', 'nexifymy-security' ); ?></th>
						<td>
							<fieldset>
								<label for="bad_bots" style="display: block; margin-bottom: 8px;">
									<input type="checkbox" name="bad_bots" id="bad_bots" <?php checked( $fw_settings['bad_bots'] ?? true ); ?>>
									<?php _e( 'Block known bad bots and scrapers', 'nexifymy-security' ); ?>
								</label>
								<label for="suspicious_agents" style="display: block; margin-bottom: 8px;">
									<input type="checkbox" name="suspicious_agents" id="suspicious_agents" <?php checked( $fw_settings['suspicious_agents'] ?? false ); ?>>
									<?php _e( 'Block suspicious User-Agents', 'nexifymy-security' ); ?>
								</label>
								<label for="aggressive_crawlers">
									<input type="checkbox" name="aggressive_crawlers" id="aggressive_crawlers" <?php checked( $fw_settings['aggressive_crawlers'] ?? false ); ?>>
									<?php _e( 'Block aggressive crawlers (high request rate)', 'nexifymy-security' ); ?>
								</label>
							</fieldset>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php _e( 'Advanced Hardening', 'nexifymy-security' ); ?></th>
						<td>
							<fieldset>
								<label for="disable_xmlrpc" style="display: block; margin-bottom: 8px;">
									<input type="checkbox" name="disable_xmlrpc" id="disable_xmlrpc" <?php checked( $fw_settings['disable_xmlrpc'] ?? false ); ?>>
									<?php _e( 'Disable XML-RPC (prevents common brute force vector)', 'nexifymy-security' ); ?>
								</label>
								<label for="block_app_passwords">
									<input type="checkbox" name="block_app_passwords" id="block_app_passwords" <?php checked( $fw_settings['block_app_passwords'] ?? false ); ?>>
									<?php _e( 'Disable Application Passwords', 'nexifymy-security' ); ?>
								</label>
							</fieldset>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Directory Traversal Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" name="directory_traversal" <?php checked( $fw_settings['directory_traversal'] ?? true ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
					</table>
					
					<table class="form-table" style="border-top: 1px solid #e2e8f0; margin-top: 20px; padding-top: 20px;">
						<tr>
							<th scope="row"><?php _e( 'Rate Limiting', 'nexifymy-security' ); ?></th>
							<td>
								<fieldset>
									<label for="ratelimit_enabled" style="display: block; margin-bottom: 10px;">
										<input type="checkbox" name="ratelimit_enabled" id="ratelimit_enabled" <?php checked( $fw_settings['ratelimit_enabled'] ?? false ); ?>>
										<?php _e( 'Enable Rate Limiting', 'nexifymy-security' ); ?>
									</label>
									<div class="nms-inline-settings" style="display: flex; gap: 20px; align-items: center; margin-bottom: 5px;">
										<div>
											<label for="ratelimit_requests" class="small-text"><?php _e( 'Max Requests', 'nexifymy-security' ); ?></label>
											<input type="number" name="ratelimit_requests" id="ratelimit_requests" value="<?php echo esc_attr( $fw_settings['ratelimit_requests'] ?? 60 ); ?>" class="small-text" style="width: 70px;">
										</div>
										<div>
											<label for="ratelimit_window" class="small-text"><?php _e( 'Time Window (sec)', 'nexifymy-security' ); ?></label>
											<input type="number" name="ratelimit_window" id="ratelimit_window" value="<?php echo esc_attr( $fw_settings['ratelimit_window'] ?? 60 ); ?>" class="small-text" style="width: 70px;">
										</div>
									</div>
									<p class="description"><?php _e( 'Limit excessive requests from a single IP address.', 'nexifymy-security' ); ?></p>
								</fieldset>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php _e( 'HTTP Security Headers', 'nexifymy-security' ); ?></th>
							<td>
								<fieldset>
									<label for="header_xframe" style="display: block; margin-bottom: 5px;">
										<input type="checkbox" name="header_xframe" id="header_xframe" <?php checked( $fw_settings['header_xframe'] ?? true ); ?>>
										<?php _e( 'X-Frame-Options (Prevent Clickjacking)', 'nexifymy-security' ); ?>
									</label>
									<label for="header_xss" style="display: block; margin-bottom: 5px;">
										<input type="checkbox" name="header_xss" id="header_xss" <?php checked( $fw_settings['header_xss'] ?? true ); ?>>
										<?php _e( 'X-XSS-Protection', 'nexifymy-security' ); ?>
									</label>
									<label for="header_hsts" style="display: block; margin-bottom: 5px;">
										<input type="checkbox" name="header_hsts" id="header_hsts" <?php checked( $fw_settings['header_hsts'] ?? false ); ?>>
										<?php _e( 'HTTP Strict Transport Security (HSTS)', 'nexifymy-security' ); ?>
									</label>
									<label for="header_nosniff" style="display: block;">
										<input type="checkbox" name="header_nosniff" id="header_nosniff" <?php checked( $fw_settings['header_nosniff'] ?? true ); ?>>
										<?php _e( 'X-Content-Type-Options (No Sniff)', 'nexifymy-security' ); ?>
									</label>
								</fieldset>
							</td>
						</tr>
					</table>
					<p style="margin-top: 20px;">
						<button type="button" class="nms-btn nms-btn-primary" id="save-firewall-settings">
							<?php _e( 'Save Settings', 'nexifymy-security' ); ?>
						</button>
						<span id="firewall-status" style="margin-left: 15px;"></span>
					</p>
				</div>
			</div>

			<!-- IP Management -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'IP Management', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
						<div>
							<h4><?php _e( 'Whitelist IPs', 'nexifymy-security' ); ?></h4>
							<textarea id="ip-whitelist" rows="6" class="large-text" placeholder="<?php _e( 'Enter IPs, one per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $fw_settings['whitelist'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'IPs that will never be blocked.', 'nexifymy-security' ); ?></p>
						</div>
						<div>
							<h4><?php _e( 'Blacklist IPs', 'nexifymy-security' ); ?></h4>
							<textarea id="ip-blacklist" rows="6" class="large-text" placeholder="<?php _e( 'Enter IPs, one per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $fw_settings['blacklist'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'IPs that will always be blocked.', 'nexifymy-security' ); ?></p>
						</div>
					</div>
				</div>
			</div>

			<!-- Blocked IPs -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Recently Blocked IPs', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div id="blocked-ips-list">
						<p><?php _e( 'Loading blocked IPs...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the logs page.
	 */
	public function render_logs() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Security Logs', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-list-view"></span> <?php _e( 'Security Logs', 'nexifymy-security' ); ?></h2>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Event Logs', 'nexifymy-security' ); ?></h2>
					<div class="log-filters">
						<select id="log-severity-filter">
							<option value=""><?php _e( 'All Severities', 'nexifymy-security' ); ?></option>
							<option value="critical"><?php _e( 'Critical', 'nexifymy-security' ); ?></option>
							<option value="warning"><?php _e( 'Warning', 'nexifymy-security' ); ?></option>
							<option value="info"><?php _e( 'Info', 'nexifymy-security' ); ?></option>
						</select>
						<button class="button" id="refresh-logs"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
					</div>
				</div>
				<div class="card-body">
					<table class="widefat striped" id="logs-table">
						<thead>
							<tr>
								<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="logs-tbody">
							<tr><td colspan="5"><?php _e( 'Loading logs...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
					<div class="log-pagination" id="log-pagination"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the notifications page.
	 */
	public function render_notifications() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Notifications', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-bell"></span> <?php _e( 'Notifications', 'nexifymy-security' ); ?></h2>
				<p class="description"><?php _e( 'Unread security alerts from your logs.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Unread Alerts', 'nexifymy-security' ); ?> <span id="notifications-unread-count"></span></h2>
					<button type="button" class="button" id="mark-all-notifications-read"><?php _e( 'Mark All as Read', 'nexifymy-security' ); ?></button>
				</div>
				<div class="card-body">
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'Date', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Event', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="notifications-tbody">
							<tr><td colspan="5"><?php _e( 'Loading alerts...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
					<p class="description"><?php _e( 'Shows unread Critical/Warning events. Use Logs for full history.', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the settings page.
	 */
	public function render_settings() {
		// Load settings.
		require_once NEXIFYMY_SECURITY_PATH . 'includes/class-nexifymy-security-settings.php';
		$settings = NexifyMy_Security_Settings::get_all();
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Settings', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'Settings', 'nexifymy-security' ); ?></h2>
				<p class="description"><?php _e( 'Configure your security settings.', 'nexifymy-security' ); ?></p>
			</div>

			<form id="nexifymy-settings-form">
				<!-- Module Toggles -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Module Controls', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Web Application Firewall', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[waf_enabled]" value="1" <?php checked( $settings['modules']['waf_enabled'] ); ?>> <?php _e( 'Enable WAF protection', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Malware Scanner', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[scanner_enabled]" value="1" <?php checked( $settings['modules']['scanner_enabled'] ); ?>> <?php _e( 'Enable malware scanner', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[rate_limiter_enabled]" value="1" <?php checked( $settings['modules']['rate_limiter_enabled'] ); ?>> <?php _e( 'Enable login rate limiting', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Background Scans', 'nexifymy-security' ); ?></th>
								<td>
									<label><input type="checkbox" name="modules[background_scan_enabled]" value="1" <?php checked( $settings['modules']['background_scan_enabled'] ); ?>> <?php _e( 'Enable scheduled scans', 'nexifymy-security' ); ?></label>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Rate Limiter Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Max Failed Attempts', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[max_attempts]" value="<?php echo esc_attr( $settings['rate_limiter']['max_attempts'] ); ?>" min="1" max="20" class="small-text">
									<p class="description"><?php _e( 'Number of failed login attempts before lockout.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[lockout_duration]" value="<?php echo esc_attr( $settings['rate_limiter']['lockout_duration'] ); ?>" min="60" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
									<p class="description"><?php _e( 'How long to block an IP after exceeding attempts.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Attempt Window', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="rate_limiter[attempt_window]" value="<?php echo esc_attr( $settings['rate_limiter']['attempt_window'] ); ?>" min="60" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
									<p class="description"><?php _e( 'Time window used to count failed login attempts.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- IP Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'IP Configuration', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'IP Whitelist', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="ip[whitelist]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['ip']['whitelist'] ) ); ?></textarea>
									<p class="description"><?php _e( 'One IP per line. These IPs will bypass WAF checks.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Trusted Proxies', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="ip[trusted_proxies]" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['ip']['trusted_proxies'] ) ); ?></textarea>
									<p class="description"><?php _e( 'One IP per line. Proxy IPs allowed to send X-Forwarded-For headers (e.g., Cloudflare, load balancers).', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Scanner Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Default Scan Mode', 'nexifymy-security' ); ?></th>
								<td>
									<select name="scanner[default_mode]">
										<option value="quick" <?php selected( $settings['scanner']['default_mode'], 'quick' ); ?>><?php _e( 'Quick', 'nexifymy-security' ); ?></option>
										<option value="standard" <?php selected( $settings['scanner']['default_mode'], 'standard' ); ?>><?php _e( 'Standard', 'nexifymy-security' ); ?></option>
										<option value="deep" <?php selected( $settings['scanner']['default_mode'], 'deep' ); ?>><?php _e( 'Deep', 'nexifymy-security' ); ?></option>
									</select>
									<p class="description"><?php _e( 'Default scan mode used when none is specified.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Max File Size', 'nexifymy-security' ); ?></th>
								<td>
									<input type="number" name="scanner[max_file_size_kb]" value="<?php echo esc_attr( $settings['scanner']['max_file_size_kb'] ); ?>" min="100" class="small-text"> KB
									<p class="description"><?php _e( 'Skip files larger than this size.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Excluded Paths', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="scanner[excluded_paths]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['scanner']['excluded_paths'] ) ); ?></textarea>
									<p class="description"><?php _e( 'Paths to exclude from scanning (relative to WordPress root). One per line.', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Excluded Extensions', 'nexifymy-security' ); ?></th>
								<td>
									<textarea name="scanner[excluded_extensions]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['scanner']['excluded_extensions'] ) ); ?></textarea>
									<p class="description"><?php _e( 'File extensions to exclude from scanning (one per line, without dots).', 'nexifymy-security' ); ?></p>
								</td>
							</tr>
						</table>
					</div>
				</div>

				<!-- Background Scan Settings -->
				<div class="nexifymy-card">
					<div class="card-header">
						<h2><?php _e( 'Scheduled Scans', 'nexifymy-security' ); ?></h2>
					</div>
					<div class="card-body">
						<table class="form-table">
							<tr>
								<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
								<td>
									<select name="background_scan[schedule]">
										<option value="hourly" <?php selected( $settings['background_scan']['schedule'], 'hourly' ); ?>><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
										<option value="twicedaily" <?php selected( $settings['background_scan']['schedule'], 'twicedaily' ); ?>><?php _e( 'Twice Daily', 'nexifymy-security' ); ?></option>
										<option value="daily" <?php selected( $settings['background_scan']['schedule'], 'daily' ); ?>><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
										<option value="weekly" <?php selected( $settings['background_scan']['schedule'], 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
										<option value="disabled" <?php selected( $settings['background_scan']['schedule'], 'disabled' ); ?>><?php _e( 'Disabled', 'nexifymy-security' ); ?></option>
									</select>
								</td>
							</tr>
							<tr>
								<th><?php _e( 'Scheduled Scan Mode', 'nexifymy-security' ); ?></th>
								<td>
									<select name="background_scan[scan_mode]">
										<option value="quick" <?php selected( $settings['background_scan']['scan_mode'], 'quick' ); ?>><?php _e( 'Quick', 'nexifymy-security' ); ?></option>
								<option value="standard" <?php selected( $settings['background_scan']['scan_mode'], 'standard' ); ?>><?php _e( 'Standard', 'nexifymy-security' ); ?></option>
								<option value="deep" <?php selected( $settings['background_scan']['scan_mode'], 'deep' ); ?>><?php _e( 'Deep', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Logging Settings -->
		<div class="nexifymy-card">
			<div class="card-header">
				<h2><?php _e( 'Logging', 'nexifymy-security' ); ?></h2>
			</div>
			<div class="card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Log Retention', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" name="logging[retention_days]" value="<?php echo esc_attr( $settings['logging']['retention_days'] ); ?>" min="1" max="365" class="small-text"> <?php _e( 'days', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Logs older than this are automatically purged daily.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Email Alerts Settings -->
		<?php
		$alert_settings = array(
			'enabled'           => false,
			'recipient_email'   => get_option( 'admin_email' ),
			'alert_types'       => array( 'threat_detected', 'ip_lockout' ),
			'throttle_minutes'  => 60,
			'daily_summary'     => false,
		);
		if ( class_exists( 'NexifyMy_Security_Alerts' ) ) {
			$alert_settings = NexifyMy_Security_Alerts::get_settings();
		}
		?>
		<div class="nexifymy-card">
			<div class="card-header">
				<h2><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></h2>
			</div>
			<div class="card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Alerts', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[enabled]" value="1" <?php checked( $alert_settings['enabled'] ); ?>> <?php _e( 'Send email notifications for security events', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Recipient Email', 'nexifymy-security' ); ?></th>
						<td>
							<input type="email" name="alerts[recipient_email]" value="<?php echo esc_attr( $alert_settings['recipient_email'] ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Leave blank to use admin email.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Alert Types', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[alert_types][]" value="threat_detected" <?php checked( in_array( 'threat_detected', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="ip_lockout" <?php checked( in_array( 'ip_lockout', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'IP Lockout', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="waf_block" <?php checked( in_array( 'waf_block', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'WAF Attack Blocked', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="alerts[alert_types][]" value="file_quarantined" <?php checked( in_array( 'file_quarantined', $alert_settings['alert_types'] ) ); ?>> <?php _e( 'File Quarantined', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Throttle Period', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" name="alerts[throttle_minutes]" value="<?php echo esc_attr( $alert_settings['throttle_minutes'] ); ?>" min="0" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Prevent duplicate alerts within this period.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Daily Summary', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="alerts[daily_summary]" value="1" <?php checked( $alert_settings['daily_summary'] ); ?>> <?php _e( 'Send daily email digest', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th></th>
						<td>
							<button type="button" class="button" id="test-alert"><?php _e( 'Send Test Alert', 'nexifymy-security' ); ?></button>
							<span id="test-alert-result"></span>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Action Buttons -->
		<div class="nexifymy-settings-actions">
			<button type="submit" class="button button-primary button-hero" id="save-settings">
				<?php _e( 'Save Settings', 'nexifymy-security' ); ?>
			</button>
			<button type="button" class="button" id="reset-settings">
				<?php _e( 'Reset to Defaults', 'nexifymy-security' ); ?>
			</button>
		</div>
		</form>
	</div>
	<?php
}

	/**
	 * Render the quarantine page.
	 */
	public function render_quarantine() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Quarantine', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?></h2>
				<p class="description"><?php _e( 'Manage quarantined threats and recoverable deleted files.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Quarantined Files', 'nexifymy-security' ); ?></h2>
					<button class="button" id="refresh-quarantine"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
				</div>
				<div class="card-body">
					<p class="description"><?php _e( 'Files in quarantine are safely stored and cannot execute.', 'nexifymy-security' ); ?></p>
					
					<table class="widefat striped" id="quarantine-table">
						<thead>
							<tr>
								<th><?php _e( 'Original Path', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Reason', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Quarantined', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="quarantine-tbody">
							<tr><td colspan="5"><?php _e( 'Loading quarantined files...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<div class="nexifymy-card nexifymy-card-full">
				<div class="card-header">
					<h2><?php _e( 'Deleted Files (Recoverable)', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p class="description"><?php _e( 'Files moved here can be restored back to quarantine or deleted permanently.', 'nexifymy-security' ); ?></p>
					
					<table class="widefat striped" id="deleted-quarantine-table">
						<thead>
							<tr>
								<th><?php _e( 'Original Path', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Deleted', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="deleted-quarantine-tbody">
							<tr><td colspan="4"><?php _e( 'Loading deleted files...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'About Quarantine', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ul>
						<li><strong><?php _e( 'Quarantine:', 'nexifymy-security' ); ?></strong> <?php _e( 'Moves suspicious files to a protected directory.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Restore:', 'nexifymy-security' ); ?></strong> <?php _e( 'Returns the file to its original location.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Delete:', 'nexifymy-security' ); ?></strong> <?php _e( 'Moves quarantined files to recoverable deleted storage.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Delete Permanently:', 'nexifymy-security' ); ?></strong> <?php _e( 'Permanently removes a file from deleted storage.', 'nexifymy-security' ); ?></li>
					</ul>
				</div>
			</div>
		</div>

		<!-- Confirmation Modal -->
		<div id="nms-confirm-modal" class="nms-modal-overlay">
			<div class="nms-modal">
				<div class="nms-modal-header danger" id="modal-header">
					<span class="dashicons dashicons-warning"></span>
					<h3 id="modal-title"><?php _e( 'Confirm Action', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-modal-body">
					<p id="modal-message"><?php _e( 'Are you sure you want to proceed?', 'nexifymy-security' ); ?></p>
					<div class="file-path" id="modal-file-path"></div>
				</div>
				<div class="nms-modal-footer">
					<button type="button" class="nms-modal-btn nms-modal-btn-cancel" id="modal-cancel">
						<?php _e( 'Cancel', 'nexifymy-security' ); ?>
					</button>
					<button type="button" class="nms-modal-btn nms-modal-btn-danger" id="modal-confirm">
						<?php _e( 'Confirm', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the database page.
	 */
	public function render_database() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Database Security', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-database"></span> <?php _e( 'Database Security', 'nexifymy-security' ); ?></h2>
				<p class="description"><?php _e( 'Backup, optimize, and secure your database.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Database Info Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Information', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="database-info">
						<p><?php _e( 'Loading database information...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Backup Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Backup', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'Create a backup of your WordPress database. Backups are stored securely and can be downloaded.', 'nexifymy-security' ); ?></p>
					<button class="button button-primary" id="create-backup">
						<span class="dashicons dashicons-download"></span> <?php _e( 'Create Backup Now', 'nexifymy-security' ); ?>
					</button>
					<span id="backup-status"></span>

					<h3><?php _e( 'Existing Backups', 'nexifymy-security' ); ?></h3>
					<table class="widefat striped" id="backups-table">
						<thead>
							<tr>
								<th><?php _e( 'Filename', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Created', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody id="backups-tbody">
							<tr><td colspan="4"><?php _e( 'Loading backups...', 'nexifymy-security' ); ?></td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<!-- Optimization Card -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Database Optimization', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'Clean up unnecessary data to improve database performance.', 'nexifymy-security' ); ?></p>
					
					<div id="optimization-stats">
						<p><?php _e( 'Loading optimization stats...', 'nexifymy-security' ); ?></p>
					</div>

					<button class="button button-secondary" id="optimize-database">
						<span class="dashicons dashicons-performance"></span> <?php _e( 'Optimize Database', 'nexifymy-security' ); ?>
					</button>
					<span id="optimize-status"></span>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Live Traffic page.
	 */
	public function render_live_traffic() {
		$traffic_analytics = array();
		if ( isset( $GLOBALS['nexifymy_live_traffic'] ) ) {
			$traffic_analytics = $GLOBALS['nexifymy_live_traffic']->get_analytics();
		}
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-chart-area"></span> <?php _e( 'Traffic Analytics', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Monitor visitor trends, page views, and traffic patterns over time.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Traffic Overview Stats -->
			<div class="nms-stats-row" style="margin-bottom: 24px;">
				<div class="nms-stat-card">
					<div class="nms-stat-icon blue">
						<span class="dashicons dashicons-visibility"></span>
					</div>
					<div class="nms-stat-content">
						<h4 id="stat-today"><?php echo isset( $traffic_analytics['today'] ) ? number_format( $traffic_analytics['today'] ) : '0'; ?></h4>
						<p><?php _e( 'Visits Today', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon green">
						<span class="dashicons dashicons-chart-line"></span>
					</div>
					<div class="nms-stat-content">
						<h4 id="stat-week"><?php echo isset( $traffic_analytics['week'] ) ? number_format( $traffic_analytics['week'] ) : '0'; ?></h4>
						<p><?php _e( 'This Week', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon purple">
						<span class="dashicons dashicons-calendar-alt"></span>
					</div>
					<div class="nms-stat-content">
						<h4 id="stat-month"><?php echo isset( $traffic_analytics['month'] ) ? number_format( $traffic_analytics['month'] ) : '0'; ?></h4>
						<p><?php _e( 'This Month', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-stat-card">
					<div class="nms-stat-icon orange">
						<span class="dashicons dashicons-groups"></span>
					</div>
					<div class="nms-stat-content">
						<h4 id="stat-unique"><?php echo isset( $traffic_analytics['unique_ips'] ) ? number_format( $traffic_analytics['unique_ips'] ) : '0'; ?></h4>
						<p><?php _e( 'Unique Visitors', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Visitor Trends Chart -->
			<div class="nms-card" style="margin-bottom: 24px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Visitor Trends - Last 30 Days', 'nexifymy-security' ); ?></h3>
					<div class="nms-card-actions">
						<select id="traffic-chart-period" style="padding: 4px 8px; border-radius: 4px; border: 1px solid var(--nms-border);">
							<option value="7"><?php _e( 'Last 7 Days', 'nexifymy-security' ); ?></option>
							<option value="30" selected><?php _e( 'Last 30 Days', 'nexifymy-security' ); ?></option>
							<option value="90"><?php _e( 'Last 90 Days', 'nexifymy-security' ); ?></option>
						</select>
					</div>
				</div>
				<div class="nms-card-body">
					<canvas id="traffic-trends-chart" width="400" height="120"></canvas>
				</div>
			</div>

			<div class="nms-grid-2">
				<!-- Top Pages -->
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Top Pages', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div id="top-pages-list">
							<p style="color: var(--nms-gray-500); text-align: center; padding: 20px;">
								<?php _e( 'Loading top pages...', 'nexifymy-security' ); ?>
							</p>
						</div>
					</div>
				</div>

				<!-- Traffic Sources -->
				<div class="nms-card">
					<div class="nms-card-header">
						<h3><?php _e( 'Top Referrers', 'nexifymy-security' ); ?></h3>
					</div>
					<div class="nms-card-body">
						<div id="top-referrers-list">
							<p style="color: var(--nms-gray-500); text-align: center; padding: 20px;">
								<?php _e( 'Loading referrers...', 'nexifymy-security' ); ?>
							</p>
						</div>
					</div>
				</div>
			</div>

			<!-- Geographic Distribution -->
			<div class="nms-card" style="margin-top: 24px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Geographic Distribution', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<div id="geo-distribution">
						<p style="color: var(--nms-gray-500); text-align: center; padding: 20px;">
							<?php _e( 'Loading geographic data...', 'nexifymy-security' ); ?>
						</p>
					</div>
				</div>
			</div>

			<script>
			document.addEventListener('DOMContentLoaded', function() {
				if (typeof Chart === 'undefined') return;

				// Load traffic analytics data
				function loadTrafficAnalytics(days) {
					jQuery.ajax({
						url: nexifymySecurity.ajaxUrl,
						type: 'POST',
						data: {
							action: 'nexifymy_get_traffic_analytics',
							nonce: nexifymySecurity.nonce,
							days: days || 30
						},
						success: function(response) {
							if (response && response.success && response.data) {
								updateTrafficChart(response.data.chart_data);
								updateTopPages(response.data.top_pages);
								updateTopReferrers(response.data.top_referrers);
								updateGeoDistribution(response.data.geo_distribution);
							}
						}
					});
				}

				// Update traffic trends chart
				var trafficChart = null;
				function updateTrafficChart(chartData) {
					var ctx = document.getElementById('traffic-trends-chart');
					if (!ctx) return;

					if (trafficChart) {
						trafficChart.destroy();
					}

					trafficChart = new Chart(ctx.getContext('2d'), {
						type: 'line',
						data: {
							labels: chartData.labels,
							datasets: [{
								label: '<?php _e( 'Page Views', 'nexifymy-security' ); ?>',
								data: chartData.page_views,
								borderColor: '#6366f1',
								backgroundColor: 'rgba(99, 102, 241, 0.1)',
								borderWidth: 2,
								tension: 0.4,
								fill: true,
								pointBackgroundColor: '#ffffff',
								pointBorderColor: '#6366f1',
								pointRadius: 4
							}, {
								label: '<?php _e( 'Unique Visitors', 'nexifymy-security' ); ?>',
								data: chartData.unique_visitors,
								borderColor: '#10b981',
								backgroundColor: 'rgba(16, 185, 129, 0.05)',
								borderWidth: 2,
								tension: 0.4,
								fill: false,
								borderDash: [5, 5]
							}]
						},
						options: {
							responsive: true,
							maintainAspectRatio: true,
							plugins: {
								legend: { position: 'top' },
								tooltip: {
									mode: 'index',
									intersect: false
								}
							},
							scales: {
								y: { beginAtZero: true }
							}
						}
					});
				}

				function updateTopPages(pages) {
					var html = '<ul class="nms-list-stats">';
					if (pages && pages.length > 0) {
						pages.forEach(function(page) {
							html += '<li>';
							html += '<span class="nms-stat-label" title="' + page.url + '">';
							html += '<span class="dashicons dashicons-admin-page"></span> ';
							html += page.url.substring(0, 50) + (page.url.length > 50 ? '...' : '');
							html += '</span>';
							html += '<span class="nms-badge info">' + page.count + ' <?php _e( 'views', 'nexifymy-security' ); ?></span>';
							html += '</li>';
						});
					} else {
						html += '<li style="text-align: center; color: var(--nms-gray-500);"><?php _e( 'No data available', 'nexifymy-security' ); ?></li>';
					}
					html += '</ul>';
					jQuery('#top-pages-list').html(html);
				}

				function updateTopReferrers(referrers) {
					var html = '<ul class="nms-list-stats">';
					if (referrers && referrers.length > 0) {
						referrers.forEach(function(ref) {
							var source = ref.referrer || '<?php _e( 'Direct', 'nexifymy-security' ); ?>';
							html += '<li>';
							html += '<span class="nms-stat-label" title="' + source + '">';
							html += '<span class="dashicons dashicons-admin-links"></span> ';
							html += source.substring(0, 40) + (source.length > 40 ? '...' : '');
							html += '</span>';
							html += '<span class="nms-badge success">' + ref.count + '</span>';
							html += '</li>';
						});
					} else {
						html += '<li style="text-align: center; color: var(--nms-gray-500);"><?php _e( 'No data available', 'nexifymy-security' ); ?></li>';
					}
					html += '</ul>';
					jQuery('#top-referrers-list').html(html);
				}

				function updateGeoDistribution(geo) {
					var html = '<ul class="nms-list-stats">';
					if (geo && geo.length > 0) {
						geo.forEach(function(country) {
							html += '<li>';
							html += '<span class="nms-stat-label">';
							html += '<span class="dashicons dashicons-location"></span> ';
							html += country.country_name || country.country_code || '<?php _e( 'Unknown', 'nexifymy-security' ); ?>';
							html += '</span>';
							html += '<span class="nms-badge warning">' + country.count + ' <?php _e( 'visits', 'nexifymy-security' ); ?></span>';
							html += '</li>';
						});
					} else {
						html += '<li style="text-align: center; color: var(--nms-gray-500);"><?php _e( 'No geographic data available', 'nexifymy-security' ); ?></li>';
					}
					html += '</ul>';
					jQuery('#geo-distribution').html(html);
				}

				// Period selector
				jQuery('#traffic-chart-period').on('change', function() {
					loadTrafficAnalytics(jQuery(this).val());
				});

				// Initial load
				loadTrafficAnalytics(30);
			});
			</script>
		</div>
		<?php
	}

	/**
	 * Render the Geo Blocking page.
	 */
	public function render_geo_blocking() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-admin-site-alt3"></span> <?php _e( 'Geo Blocking', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Block or allow traffic based on country.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Country Blocking Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Geo Blocking', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="geo-enabled" /> <?php _e( 'Enable country-based blocking', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Mode', 'nexifymy-security' ); ?></th>
							<td>
								<select id="geo-mode">
									<option value="blacklist"><?php _e( 'Blacklist (block selected)', 'nexifymy-security' ); ?></option>
									<option value="whitelist"><?php _e( 'Whitelist (allow only selected)', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Countries', 'nexifymy-security' ); ?></th>
							<td>
								<select id="geo-countries" multiple style="width: 100%; height: 200px;">
									<?php _e( 'Loading countries...', 'nexifymy-security' ); ?>
								</select>
								<p class="description"><?php _e( 'Hold Ctrl/Cmd to select multiple countries.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Message', 'nexifymy-security' ); ?></th>
							<td>
								<input type="text" id="geo-message" class="regular-text" value="Access denied from your region." />
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-geo-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="geo-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Hardening page.
	 */
	public function render_hardening() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-lock"></span> <?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Apply security hardening measures to WordPress.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Hardening Options', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="hardening-options">
						<tr>
							<th><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_xmlrpc" checked /> <?php _e( 'Block XML-RPC access (prevents brute force)', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Hide WP Version', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="hide_wp_version" checked /> <?php _e( 'Remove WordPress version from source code', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_file_editor" checked /> <?php _e( 'Disable theme/plugin editor in admin', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Security Headers', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="security_headers" checked /> <?php _e( 'Add X-Frame-Options, X-XSS-Protection headers', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Restrict REST API', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_rest_api" /> <?php _e( 'Require login for REST API access', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Disable Pingback', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="disable_pingback" checked /> <?php _e( 'Disable pingback/trackback functionality', 'nexifymy-security' ); ?></label></td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="apply-hardening"><?php _e( 'Apply Settings', 'nexifymy-security' ); ?></button>
						<span id="hardening-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Password Policy page.
	 */
	public function render_password() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-privacy"></span> <?php _e( 'Password Policy', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Enforce strong password requirements for all users.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Password Requirements', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="password-options">
						<tr>
							<th><?php _e( 'Minimum Length', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="pass-min-length" value="12" min="8" max="32" />
								<p class="description"><?php _e( 'Minimum password length (8-32 characters)', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Character Requirements', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="require_upper" checked /> <?php _e( 'Uppercase letter (A-Z)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_lower" checked /> <?php _e( 'Lowercase letter (a-z)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_number" checked /> <?php _e( 'Number (0-9)', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="require_special" checked /> <?php _e( 'Special character (!@#$...)', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Common Passwords', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" name="block_common" checked /> <?php _e( 'Prevent use of commonly breached passwords', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Password Expiry', 'nexifymy-security' ); ?></th>
							<td>
								<select id="pass-expiry">
									<option value="0"><?php _e( 'Never expires', 'nexifymy-security' ); ?></option>
									<option value="30"><?php _e( '30 days', 'nexifymy-security' ); ?></option>
									<option value="60"><?php _e( '60 days', 'nexifymy-security' ); ?></option>
									<option value="90"><?php _e( '90 days', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-password-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="password-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the CDN page.
	 */
	public function render_cdn() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-cloud"></span> <?php _e( 'CDN Integration', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Configure CDN integration and cache management.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- CDN Status -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'CDN Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="cdn-status">
						<p><?php _e( 'Loading CDN status...', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Cloudflare Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Cloudflare API Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable CDN Integration', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" id="cdn-enabled" /> <?php _e( 'Enable CDN features', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'Provider', 'nexifymy-security' ); ?></th>
							<td>
								<select id="cdn-provider">
									<option value="auto"><?php _e( 'Auto-detect', 'nexifymy-security' ); ?></option>
									<option value="cloudflare"><?php _e( 'Cloudflare', 'nexifymy-security' ); ?></option>
									<option value="sucuri"><?php _e( 'Sucuri', 'nexifymy-security' ); ?></option>
									<option value="generic"><?php _e( 'Generic Proxy', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Trust Proxy Headers', 'nexifymy-security' ); ?></th>
							<td><label><input type="checkbox" id="cdn-trust-proxy" checked /> <?php _e( 'Use CDN/proxy headers to determine real client IP', 'nexifymy-security' ); ?></label></td>
						</tr>
						<tr>
							<th><?php _e( 'API Token', 'nexifymy-security' ); ?></th>
							<td>
								<input type="password" id="cf-api-key" class="regular-text" />
								<p class="description"><?php _e( 'Cloudflare API Token (with Zone permissions)', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Zone ID', 'nexifymy-security' ); ?></th>
							<td>
								<input type="text" id="cf-zone-id" class="regular-text" />
								<p class="description"><?php _e( 'Found in Cloudflare dashboard under Overview', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-cdn-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<button class="button" id="test-cdn-connection" style="margin-left: 8px;"><?php _e( 'Test Connection', 'nexifymy-security' ); ?></button>
						<button class="button" id="purge-cdn-cache" style="margin-left: 8px;"><?php _e( 'Purge Cache', 'nexifymy-security' ); ?></button>
						<span id="cdn-settings-status" style="margin-left: 12px;"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Vulnerabilities page.
	 */
	public function render_vulnerabilities() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-warning"></span> <?php _e( 'Vulnerability Scanner', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Scan plugins, themes, and WordPress core for known vulnerabilities.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Scan Controls -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scan Controls', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p>
						<button class="button button-primary button-hero" id="run-vuln-scan">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Run Vulnerability Scan', 'nexifymy-security' ); ?>
						</button>
					</p>
					<div id="vuln-scan-status"></div>
				</div>
			</div>

			<!-- Scan Results -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scan Results', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="vuln-results">
						<p><?php _e( 'No scan results available. Run a scan to check for vulnerabilities.', 'nexifymy-security' ); ?></p>
					</div>
				</div>
			</div>

			<!-- Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Scanner', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-enabled" checked /> <?php _e( 'Enable vulnerability scanner features', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'WPScan API Token', 'nexifymy-security' ); ?></th>
							<td>
								<input type="password" id="wpscan-api-token" class="regular-text" />
								<p class="description"><?php _e( 'Get a free API token from wpscan.com for detailed vulnerability data.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Automatic Scans', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-auto-scan" /> <?php _e( 'Enable scheduled scans', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
							<td>
								<select id="vuln-scan-schedule">
									<option value="weekly"><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
									<option value="daily"><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="vuln-email-alerts" checked /> <?php _e( 'Send email when vulnerabilities are found', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-vuln-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="vuln-settings-status"></span>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Captcha page.
	 */
	public function render_captcha() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield"></span> <?php _e( 'Login Captcha', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Protect login and registration forms with math-based captcha.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Captcha Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table" id="captcha-settings">
						<tr>
							<th><?php _e( 'Enable Captcha', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="captcha_enabled" checked /> <?php _e( 'Enable captcha protection', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Protected Forms', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" name="enable_login" checked /> <?php _e( 'Login form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_registration" checked /> <?php _e( 'Registration form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_reset" checked /> <?php _e( 'Password reset form', 'nexifymy-security' ); ?></label><br>
								<label><input type="checkbox" name="enable_comment" /> <?php _e( 'Comment form', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Difficulty', 'nexifymy-security' ); ?></th>
							<td>
								<select id="captcha-difficulty">
									<option value="easy"><?php _e( 'Easy (addition only)', 'nexifymy-security' ); ?></option>
									<option value="medium"><?php _e( 'Medium (addition/subtraction)', 'nexifymy-security' ); ?></option>
									<option value="hard"><?php _e( 'Hard (includes multiplication)', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-captcha-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="captcha-status"></span>
					</p>
				</div>
			</div>

			<!-- Preview -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Captcha Preview', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p><?php _e( 'This is how the captcha will appear on login forms:', 'nexifymy-security' ); ?></p>
					<div style="max-width: 300px; padding: 20px; background: #f1f1f1; border-radius: 5px;">
						<label style="font-weight: 600;">5 + 3 = ?</label><br>
						<input type="number" style="width: 100%; padding: 8px; margin-top: 5px;" placeholder="<?php _e( 'Enter answer', 'nexifymy-security' ); ?>" />
					</div>
					</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the 2FA page.
	 */
	public function render_2fa() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-lock"></span> <?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Add an extra layer of security with TOTP-based 2FA.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( '2FA Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable 2FA', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-enabled" checked /> <?php _e( 'Allow users to enable 2FA', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Force for Admins', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-force-admin" /> <?php _e( 'Require 2FA for all administrators', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Backup', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="2fa-email-backup" checked /> <?php _e( 'Allow email code as backup method', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Remember Device', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="2fa-remember-days" value="30" min="1" max="365" style="width: 80px;" />
								<span><?php _e( 'days', 'nexifymy-security' ); ?></span>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-2fa-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="2fa-status"></span>
					</p>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How 2FA Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ol>
						<li><?php _e( 'Users enable 2FA in their profile settings', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Scan QR code with authenticator app (Google/Microsoft Authenticator)', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Enter 6-digit code to verify setup', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'On next login, enter password + 6-digit code', 'nexifymy-security' ); ?></li>
					</ol>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Hide Login page.
	 */
	public function render_hide_login() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-hidden"></span> <?php _e( 'Hide Login URL', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Hide wp-admin and wp-login.php from attackers.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Login URL Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="hide-login-enabled" /> <?php _e( 'Hide default login URLs', 'nexifymy-security' ); ?></label>
								<p class="description" style="color: orange;">
									<strong><?php _e( 'Warning:', 'nexifymy-security' ); ?></strong>
									<?php _e( 'Make sure to remember your custom login URL!', 'nexifymy-security' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Login Slug', 'nexifymy-security' ); ?></th>
							<td>
								<code><?php echo esc_html( home_url( '/' ) ); ?></code>
								<input type="text" id="login-slug" value="secure-login" style="width: 200px;" />
								<p class="description"><?php _e( 'Choose a unique, hard-to-guess slug.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Redirect Blocked Access', 'nexifymy-security' ); ?></th>
							<td>
								<select id="hide-login-redirect">
									<option value="404"><?php _e( 'Show 404 page', 'nexifymy-security' ); ?></option>
									<option value="home"><?php _e( 'Redirect to homepage', 'nexifymy-security' ); ?></option>
									<option value="custom"><?php _e( 'Custom URL', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
					<p>
						<button class="button button-primary" id="save-hide-login-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
						<span id="hide-login-status"></span>
					</p>
				</div>
			</div>

			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Current Login URL', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p id="current-login-url">
						<code><?php echo esc_html( wp_login_url() ); ?></code>
					</p>
					<p class="description"><?php _e( 'Bookmark this URL so you can always access your login page.', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Self-Protection page.
	 */
	public function render_self_protection() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Plugin Self-Protection', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Protect the security plugin from tampering and unauthorized modifications.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- Protection Status -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Integrity Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="protection-status">
						<p><?php _e( 'Loading protection status...', 'nexifymy-security' ); ?></p>
					</div>
					<p>
						<button class="button button-primary" id="run-integrity-check">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Run Integrity Check', 'nexifymy-security' ); ?>
						</button>
						<button class="button" id="regenerate-hashes">
							<span class="dashicons dashicons-update"></span> <?php _e( 'Regenerate Baseline', 'nexifymy-security' ); ?>
						</button>
						<span id="integrity-status"></span>
					</p>
				</div>
			</div>

			<!-- Settings -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Protection Settings', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'File Integrity Monitoring', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="monitor-files" checked /> <?php _e( 'Monitor plugin files for changes', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block File Editor', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="block-editor" checked /> <?php _e( 'Prevent editing plugin files via WordPress editor', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Email Alerts', 'nexifymy-security' ); ?></th>
							<td>
								<label><input type="checkbox" id="tampering-alerts" checked /> <?php _e( 'Send email when tampering is detected', 'nexifymy-security' ); ?></label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Check Interval', 'nexifymy-security' ); ?></th>
							<td>
								<select id="check-interval">
									<option value="hourly"><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
									<option value="daily"><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								</select>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<!-- How It Works -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How Self-Protection Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ul>
						<li><strong><?php _e( 'File Hashing:', 'nexifymy-security' ); ?></strong> <?php _e( 'SHA-256 hashes of all plugin files are stored as a baseline.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Integrity Checks:', 'nexifymy-security' ); ?></strong> <?php _e( 'Files are periodically compared against the baseline.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Tamper Detection:', 'nexifymy-security' ); ?></strong> <?php _e( 'Any modifications trigger immediate email alerts.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Editor Blocking:', 'nexifymy-security' ); ?></strong> <?php _e( 'Plugin files cannot be edited via WordPress.', 'nexifymy-security' ); ?></li>
						<li><strong><?php _e( 'Deactivation Monitoring:', 'nexifymy-security' ); ?></strong> <?php _e( 'Alerts sent if plugin is deactivated.', 'nexifymy-security' ); ?></li>
					</ul>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Core Repair page.
	 */
	public function render_core_repair() {
		global $wp_version;
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><span class="dashicons dashicons-hammer"></span> <?php _e( 'Core File Repair', 'nexifymy-security' ); ?></h1>
				<p class="description"><?php _e( 'Check and repair corrupted WordPress core files using official sources.', 'nexifymy-security' ); ?></p>
			</div>

			<!-- WordPress Version Info -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'WordPress Core Status', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'WordPress Version', 'nexifymy-security' ); ?></th>
							<td><strong><?php echo esc_html( $wp_version ); ?></strong></td>
						</tr>
						<tr>
							<th><?php _e( 'Integrity Status', 'nexifymy-security' ); ?></th>
							<td id="core-status"><?php _e( 'Not checked yet', 'nexifymy-security' ); ?></td>
						</tr>
					</table>
				</div>
			</div>

			<!-- Action Buttons -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'Actions', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<p>
						<button class="button button-primary" id="check-core-integrity">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Check Core Integrity', 'nexifymy-security' ); ?>
						</button>
						<button class="button button-secondary" id="repair-all-core" style="display: none;">
							<span class="dashicons dashicons-hammer"></span> <?php _e( 'Repair All Modified Files', 'nexifymy-security' ); ?>
						</button>
						<span id="repair-status"></span>
					</p>
				</div>
			</div>

			<!-- Results -->
			<div class="nexifymy-card" id="integrity-results" style="display: none;">
				<div class="card-header">
					<h2><?php _e( 'Integrity Check Results', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<div id="results-content"></div>
				</div>
			</div>

			<!-- How It Works -->
			<div class="nexifymy-card">
				<div class="card-header">
					<h2><?php _e( 'How Core Repair Works', 'nexifymy-security' ); ?></h2>
				</div>
				<div class="card-body">
					<ol>
						<li><?php _e( 'Fetches official file checksums from WordPress.org API', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Compares each core file against the expected hash', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Identifies modified or missing files', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Downloads fresh WordPress package from official source', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Backs up corrupted files before replacement', 'nexifymy-security' ); ?></li>
						<li><?php _e( 'Replaces corrupted files with clean versions', 'nexifymy-security' ); ?></li>
					</ol>
					<p class="description">
						<strong><?php _e( 'Note:', 'nexifymy-security' ); ?></strong>
						<?php _e( 'Backups are stored in wp-content/nexifymy-backups/core/', 'nexifymy-security' ); ?>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Modules Hub page.
	 */
	public function render_modules_hub() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$module_settings = isset( $settings['modules'] ) && is_array( $settings['modules'] ) ? $settings['modules'] : array();
		$modules = array(
			'firewall' => array(
				'name' => __( 'Web Application Firewall', 'nexifymy-security' ),
				'desc' => __( 'Protect against SQL injection, XSS, RFI, and other attacks.', 'nexifymy-security' ),
				'icon' => 'shield',
				'page' => 'firewall',
			),
			'scanner' => array(
				'name' => __( 'Malware Scanner', 'nexifymy-security' ),
				'desc' => __( 'Scan files for malware and suspicious code.', 'nexifymy-security' ),
				'icon' => 'search',
				'page' => 'scanner',
			),
			'login_protection' => array(
				'name' => __( 'Login Protection', 'nexifymy-security' ),
				'desc' => __( 'Brute force protection and login attempt limits.', 'nexifymy-security' ),
				'icon' => 'lock',
				'page' => 'login-protection',
			),
			'two_factor' => array(
				'name' => __( 'Two-Factor Authentication', 'nexifymy-security' ),
				'desc' => __( 'Add 2FA to user accounts for extra security.', 'nexifymy-security' ),
				'icon' => 'smartphone',
				'page' => '2fa',
			),
			'hide_login' => array(
				'name' => __( 'Hide Login', 'nexifymy-security' ),
				'desc' => __( 'Change the default login URL to prevent attacks.', 'nexifymy-security' ),
				'icon' => 'hidden',
				'page' => 'hide-login',
			),
			'geo_blocking' => array(
				'name' => __( 'Geo Blocking', 'nexifymy-security' ),
				'desc' => __( 'Block access from specific countries.', 'nexifymy-security' ),
				'icon' => 'admin-site',
				'page' => 'geo-blocking',
			),
			'rate_limiter' => array(
				'name' => __( 'Rate Limiter', 'nexifymy-security' ),
				'desc' => __( 'Limit request rates to prevent abuse.', 'nexifymy-security' ),
				'icon' => 'clock',
				'page' => 'rate-limiter',
			),
			'hardening' => array(
				'name' => __( 'Security Hardening', 'nexifymy-security' ),
				'desc' => __( 'Apply WordPress security best practices.', 'nexifymy-security' ),
				'icon' => 'shield-alt',
				'page' => 'hardening',
			),
			'captcha' => array(
				'name' => __( 'CAPTCHA', 'nexifymy-security' ),
				'desc' => __( 'Add CAPTCHA to login and forms.', 'nexifymy-security' ),
				'icon' => 'visibility',
				'page' => 'captcha',
			),
			'self_protection' => array(
				'name' => __( 'Self-Protection', 'nexifymy-security' ),
				'desc' => __( 'Protect plugin files from tampering.', 'nexifymy-security' ),
				'icon' => 'admin-plugins',
				'page' => 'self-protection',
			),
			'password' => array(
				'name' => __( 'Password Policy', 'nexifymy-security' ),
				'desc' => __( 'Enforce strong password requirements.', 'nexifymy-security' ),
				'icon' => 'privacy',
				'page' => 'password',
			),
		);
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><?php _e( 'Security Modules', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Enable and configure security modules for your site.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-modules-grid">
				<?php foreach ( $modules as $key => $module ) :
					$option_key = $key . '_enabled';
					$enabled = array_key_exists( $option_key, $module_settings )
						? ! empty( $module_settings[ $option_key ] )
						: true;
				?>
				<div class="nms-module-card <?php echo $enabled ? 'active' : ''; ?>">
					<div class="nms-module-card-header">
						<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
						<h3><?php echo esc_html( $module['name'] ); ?></h3>
						<label class="nms-toggle">
							<input type="checkbox" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $enabled ); ?>>
							<span class="nms-toggle-slider"></span>
						</label>
					</div>
					<div class="nms-module-card-body">
						<p><?php echo esc_html( $module['desc'] ); ?></p>
					</div>
					<div class="nms-module-card-footer">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-' . $module['page'] ) ); ?>" class="nms-btn nms-btn-secondary">
							<?php _e( 'Settings', 'nexifymy-security' ); ?> →
						</a>
					</div>
				</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Tools Hub page.
	 */
	public function render_tools_hub() {
		$tools = array(
			array(
				'name' => __( 'Database Security', 'nexifymy-security' ),
				'desc' => __( 'Optimize and secure your database.', 'nexifymy-security' ),
				'icon' => 'database',
				'page' => 'database',
			),
			array(
				'name' => __( 'Core File Repair', 'nexifymy-security' ),
				'desc' => __( 'Verify and repair WordPress core files.', 'nexifymy-security' ),
				'icon' => 'admin-tools',
				'page' => 'core-repair',
			),
			array(
				'name' => __( 'Vulnerability Scanner', 'nexifymy-security' ),
				'desc' => __( 'Check for known vulnerabilities.', 'nexifymy-security' ),
				'icon' => 'warning',
				'page' => 'vulnerabilities',
			),
			array(
				'name' => __( 'Live Traffic', 'nexifymy-security' ),
				'desc' => __( 'Monitor real-time site traffic.', 'nexifymy-security' ),
				'icon' => 'chart-line',
				'page' => 'live-traffic',
			),
			array(
				'name' => __( 'Quarantine', 'nexifymy-security' ),
				'desc' => __( 'View and manage quarantined threats.', 'nexifymy-security' ),
				'icon' => 'archive',
				'page' => 'quarantine',
			),
			array(
				'name' => __( 'Malware Definitions', 'nexifymy-security' ),
				'desc' => __( 'Update malware detection signatures.', 'nexifymy-security' ),
				'icon' => 'update',
				'page' => 'definitions',
			),
			array(
				'name' => __( 'Security Logs', 'nexifymy-security' ),
				'desc' => __( 'View all security events.', 'nexifymy-security' ),
				'icon' => 'list-view',
				'page' => 'logs',
			),
			array(
				'name' => __( 'CDN Integration', 'nexifymy-security' ),
				'desc' => __( 'Configure CDN for security and performance.', 'nexifymy-security' ),
				'icon' => 'networking',
				'page' => 'cdn',
			),
		);
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><?php _e( 'Security Tools', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Quick access to security maintenance tools.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-tools-grid-hub">
				<?php foreach ( $tools as $tool ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-' . $tool['page'] ) ); ?>" class="nms-tool-card">
					<span class="dashicons dashicons-<?php echo esc_attr( $tool['icon'] ); ?>"></span>
					<h3><?php echo esc_html( $tool['name'] ); ?></h3>
					<p><?php echo esc_html( $tool['desc'] ); ?></p>
				</a>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Malware Definitions page.
	 */
	public function render_malware_definitions() {
		$status = array();
		if ( isset( $GLOBALS['nexifymy_signatures'] ) && method_exists( $GLOBALS['nexifymy_signatures'], 'get_status' ) ) {
			$status = $GLOBALS['nexifymy_signatures']->get_status();
		}

		$signature_source = $status['last_update']['source'] ?? ( $status['source'] ?? 'unknown' );
		$signature_version = is_string( $signature_source ) && $signature_source !== '' ? $signature_source : 'unknown';
		$last_update = $status['last_update']['updated_at'] ?? null;
		$signature_count = isset( $status['total_signatures'] ) ? (int) $status['total_signatures'] : 0;

		$settings = get_option( 'nexifymy_security_settings', array() );
		$auto_update = isset( $settings['signatures']['auto_update'] ) ? (bool) $settings['signatures']['auto_update'] : true;
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><?php _e( 'Malware Definitions', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Keep your malware signatures up to date for best protection.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Signature Status', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="widefat">
						<tbody>
							<tr>
								<th><?php _e( 'Current Version', 'nexifymy-security' ); ?></th>
								<td><code><?php echo esc_html( $signature_version ); ?></code></td>
							</tr>
							<tr>
								<th><?php _e( 'Total Signatures', 'nexifymy-security' ); ?></th>
								<td><?php echo intval( $signature_count ); ?></td>
							</tr>
							<tr>
								<th><?php _e( 'Last Updated', 'nexifymy-security' ); ?></th>
								<td><?php echo $last_update ? esc_html( human_time_diff( strtotime( $last_update ), current_time( 'timestamp' ) ) ) . ' ' . __( 'ago', 'nexifymy-security' ) : __( 'Never', 'nexifymy-security' ); ?></td>
							</tr>
						</tbody>
					</table>
					<div style="margin-top: 20px;">
						<button type="button" id="update-definitions" class="nms-btn nms-btn-primary">
							<span class="dashicons dashicons-update"></span>
							<?php _e( 'Update Definitions Now', 'nexifymy-security' ); ?>
						</button>
						<span id="update-status" style="margin-left: 15px;"></span>
					</div>
				</div>
			</div>
			
			<div class="nms-card" style="margin-top: 20px;">
				<div class="nms-card-header">
					<h3><?php _e( 'Auto-Update Settings', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Auto-Update', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="auto-update-signatures" value="1" <?php checked( $auto_update ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
								<p class="description"><?php _e( 'Automatically update malware signatures daily.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Login Protection page.
	 */
	public function render_login_protection() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$login_settings = isset( $settings['login_protection'] ) ? $settings['login_protection'] : array();
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><?php _e( 'Login Protection', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Protect your login page from brute force attacks.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Brute Force Protection', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Protection', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="login-prot-enabled" value="1" <?php checked( ! empty( $login_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Max Login Attempts', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-attempts" value="<?php echo intval( $login_settings['max_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text">
								<p class="description"><?php _e( 'Lock out after this many failed attempts.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-duration" value="<?php echo intval( $login_settings['lockout_duration'] ?? 30 ); ?>" min="5" max="1440" class="small-text">
								<?php _e( 'minutes', 'nexifymy-security' ); ?>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Permanent Ban Threshold', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="login-prot-ban" value="<?php echo intval( $login_settings['ban_threshold'] ?? 3 ); ?>" min="1" max="10" class="small-text">
								<p class="description"><?php _e( 'Number of lockouts before permanent ban.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
			
			<p class="submit">
				<button type="button" id="save-login-prot-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				<span id="login-prot-status" style="margin-left: 15px;"></span>
			</p>
		</div>
		<?php
	}

	/**
	 * Render the Rate Limiter page.
	 */
	public function render_rate_limiter() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$rate_settings = isset( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array();
		?>
		<div class="wrap nexifymy-security-wrap">
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h1><?php _e( 'Rate Limiter', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Limit request rates to prevent abuse and DDoS attacks.', 'nexifymy-security' ); ?></p>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Rate Limiting Settings', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<table class="form-table">
						<tr>
							<th><?php _e( 'Enable Rate Limiting', 'nexifymy-security' ); ?></th>
							<td>
								<label class="nms-toggle">
									<input type="checkbox" id="rate-enabled" value="1" <?php checked( ! empty( $rate_settings['enabled'] ) ); ?>>
									<span class="nms-toggle-slider"></span>
								</label>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Requests Per Minute', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="rate-requests" value="<?php echo intval( $rate_settings['requests_per_minute'] ?? 60 ); ?>" min="10" max="500" class="small-text">
								<p class="description"><?php _e( 'Maximum requests allowed per minute per IP.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Block Duration', 'nexifymy-security' ); ?></th>
							<td>
								<input type="number" id="rate-duration" value="<?php echo intval( $rate_settings['block_duration'] ?? 60 ); ?>" min="1" max="1440" class="small-text">
								<?php _e( 'minutes', 'nexifymy-security' ); ?>
							</td>
						</tr>
						<tr>
							<th><?php _e( 'Whitelist IPs', 'nexifymy-security' ); ?></th>
							<td>
								<textarea id="rate-whitelist" class="large-text" rows="3" placeholder="<?php _e( 'One IP per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( $rate_settings['whitelist'] ?? '' ); ?></textarea>
								<p class="description"><?php _e( 'IPs that bypass rate limiting.', 'nexifymy-security' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
			
			<p class="submit">
				<button type="button" id="save-rate-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				<span id="rate-status" style="margin-left: 15px;"></span>
			</p>
		</div>
		<?php
	}

	/**
	 * Render the Scanner page with tabs.
	 */
	public function render_scanner_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'scanner';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Scan your site for malware, vulnerabilities, and security issues.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" data-tab="scanner">
					<span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'ai-detection' ? 'active' : ''; ?>" data-tab="ai-detection">
					<span class="dashicons dashicons-superhero-alt"></span> <?php _e( 'AI Threat Detection', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'quarantine' ? 'active' : ''; ?>" data-tab="quarantine">
					<span class="dashicons dashicons-archive"></span> <?php _e( 'Quarantine', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'definitions' ? 'active' : ''; ?>" data-tab="definitions">
					<span class="dashicons dashicons-database"></span> <?php _e( 'Malware Definitions', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-scanner" class="nms-tab-panel <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'scanner' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_scanner_content(); ?>
				</div>
				<div id="tab-ai-detection" class="nms-tab-panel <?php echo $active_tab === 'ai-detection' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'ai-detection' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_ai_detection_content(); ?>
				</div>
				<div id="tab-quarantine" class="nms-tab-panel <?php echo $active_tab === 'quarantine' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'quarantine' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_quarantine_content(); ?>
				</div>
				<div id="tab-definitions" class="nms-tab-panel <?php echo $active_tab === 'definitions' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'definitions' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_definitions_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Firewall page with tabs.
	 */
	public function render_firewall_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'firewall';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Firewall', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Configure firewall rules and protection settings.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" data-tab="firewall">
					<span class="dashicons dashicons-shield"></span> <?php _e( 'Firewall Rules', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'login' ? 'active' : ''; ?>" data-tab="login">
					<span class="dashicons dashicons-lock"></span> <?php _e( 'Login Protection', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" data-tab="geo">
					<span class="dashicons dashicons-admin-site-alt3"></span> <?php _e( 'Geo Blocking', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'rate' ? 'active' : ''; ?>" data-tab="rate">
					<span class="dashicons dashicons-dashboard"></span> <?php _e( 'Rate Limiter', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-firewall" class="nms-tab-panel <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>">
					<?php $this->render_firewall_content(); ?>
				</div>
				<div id="tab-login" class="nms-tab-panel <?php echo $active_tab === 'login' ? 'active' : ''; ?>">
					<?php $this->render_login_content(); ?>
				</div>
				<div id="tab-geo" class="nms-tab-panel <?php echo $active_tab === 'geo' ? 'active' : ''; ?>">
					<?php $this->render_geo_content(); ?>
				</div>
				<div id="tab-rate" class="nms-tab-panel <?php echo $active_tab === 'rate' ? 'active' : ''; ?>">
					<?php $this->render_rate_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Modules page with tabs.
	 */
	public function render_modules_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-plugins"></span> <?php _e( 'Modules', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Enable and configure security modules.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-screenoptions"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'waf' ? 'active' : ''; ?>" data-tab="waf">
					<span class="dashicons dashicons-shield-alt"></span> <?php _e( 'WAF', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" data-tab="firewall">
					<span class="dashicons dashicons-lock"></span> <?php _e( 'Firewall', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" data-tab="scanner">
					<span class="dashicons dashicons-search"></span> <?php _e( 'Scanner', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'ratelimit' ? 'active' : ''; ?>" data-tab="ratelimit">
					<span class="dashicons dashicons-clock"></span> <?php _e( 'Rate Limit', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'login' ? 'active' : ''; ?>" data-tab="login">
					<span class="dashicons dashicons-admin-users"></span> <?php _e( 'Login', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" data-tab="geo">
					<span class="dashicons dashicons-location-alt"></span> <?php _e( 'Geo Block', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === '2fa' ? 'active' : ''; ?>" data-tab="2fa">
					<span class="dashicons dashicons-smartphone"></span> <?php _e( '2FA', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'hardening' ? 'active' : ''; ?>" data-tab="hardening">
					<span class="dashicons dashicons-hammer"></span> <?php _e( 'Hardening', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'hidelogin' ? 'active' : ''; ?>" data-tab="hidelogin">
					<span class="dashicons dashicons-hidden"></span> <?php _e( 'Hide Login', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'password' ? 'active' : ''; ?>" data-tab="password">
					<span class="dashicons dashicons-admin-network"></span> <?php _e( 'Password', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'captcha' ? 'active' : ''; ?>" data-tab="captcha">
					<span class="dashicons dashicons-forms"></span> <?php _e( 'Captcha', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'notifications' ? 'active' : ''; ?>" data-tab="notifications">
					<span class="dashicons dashicons-email"></span> <?php _e( 'Alerts', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_modules_hub_content(); ?>
				</div>
				<div id="tab-waf" class="nms-tab-panel <?php echo $active_tab === 'waf' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'waf' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_waf_settings_content(); ?>
				</div>
				<div id="tab-firewall" class="nms-tab-panel <?php echo $active_tab === 'firewall' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'firewall' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_firewall_content(); ?>
				</div>
				<div id="tab-scanner" class="nms-tab-panel <?php echo $active_tab === 'scanner' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'scanner' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_scanner_settings_content(); ?>
				</div>
				<div id="tab-ratelimit" class="nms-tab-panel <?php echo $active_tab === 'ratelimit' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'ratelimit' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_rate_content(); ?>
				</div>
				<div id="tab-login" class="nms-tab-panel <?php echo $active_tab === 'login' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'login' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_login_content(); ?>
				</div>
				<div id="tab-geo" class="nms-tab-panel <?php echo $active_tab === 'geo' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'geo' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_geo_content(); ?>
				</div>
				<div id="tab-2fa" class="nms-tab-panel <?php echo $active_tab === '2fa' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === '2fa' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_2fa_content(); ?>
				</div>
				<div id="tab-hardening" class="nms-tab-panel <?php echo $active_tab === 'hardening' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'hardening' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_hardening_content(); ?>
				</div>
				<div id="tab-hidelogin" class="nms-tab-panel <?php echo $active_tab === 'hidelogin' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'hidelogin' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_hide_login_content(); ?>
				</div>
				<div id="tab-password" class="nms-tab-panel <?php echo $active_tab === 'password' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'password' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_password_content(); ?>
				</div>
				<div id="tab-captcha" class="nms-tab-panel <?php echo $active_tab === 'captcha' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'captcha' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_captcha_content(); ?>
				</div>
				<div id="tab-traffic" class="nms-tab-panel <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'traffic' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_live_traffic_content(); ?>
				</div>
				<div id="tab-notifications" class="nms-tab-panel <?php echo $active_tab === 'notifications' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'notifications' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_notifications_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Tools page with tabs.
	 */
	public function render_tools_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-tools"></span> <?php _e( 'Tools', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Maintenance and diagnostic tools for your site.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-screenoptions"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'database' ? 'active' : ''; ?>" data-tab="database">
					<span class="dashicons dashicons-database"></span> <?php _e( 'Database', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'core' ? 'active' : ''; ?>" data-tab="core">
					<span class="dashicons dashicons-hammer"></span> <?php _e( 'Core Repair', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" data-tab="traffic">
					<span class="dashicons dashicons-visibility"></span> <?php _e( 'Live Traffic', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'supply-chain' ? 'active' : ''; ?>" data-tab="supply-chain">
					<span class="dashicons dashicons-networking"></span> <?php _e( 'Supply Chain', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_tools_hub_content(); ?>
				</div>
				<div id="tab-database" class="nms-tab-panel <?php echo $active_tab === 'database' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'database' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_database_content(); ?>
				</div>
				<div id="tab-core" class="nms-tab-panel <?php echo $active_tab === 'core' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'core' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_core_repair_content(); ?>
				</div>
				<div id="tab-traffic" class="nms-tab-panel <?php echo $active_tab === 'traffic' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'traffic' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_live_traffic_content(); ?>
				</div>
				<div id="tab-supply-chain" class="nms-tab-panel <?php echo $active_tab === 'supply-chain' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'supply-chain' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_supply_chain_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Settings page with tabs.
	 */
	public function render_settings_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'general';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'Settings', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Configure plugin settings and preferences.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'general' ? 'active' : ''; ?>" data-tab="general">
					<span class="dashicons dashicons-admin-settings"></span> <?php _e( 'General', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'email' ? 'active' : ''; ?>" data-tab="email">
					<span class="dashicons dashicons-email-alt"></span> <?php _e( 'Email Alerts', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'import-export' ? 'active' : ''; ?>" data-tab="import-export">
					<span class="dashicons dashicons-download"></span> <?php _e( 'Import/Export', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'advanced' ? 'active' : ''; ?>" data-tab="advanced">
					<span class="dashicons dashicons-admin-tools"></span> <?php _e( 'Advanced', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'logs' ? 'active' : ''; ?>" data-tab="logs">
					<span class="dashicons dashicons-editor-alignleft"></span> <?php _e( 'Logs', 'nexifymy-security' ); ?>
				</button>

			</div>

			<div class="nms-tab-content">
				<div id="tab-general" class="nms-tab-panel <?php echo $active_tab === 'general' ? 'active' : ''; ?>">
					<?php $this->render_settings_content(); ?>
				</div>
				<div id="tab-email" class="nms-tab-panel <?php echo $active_tab === 'email' ? 'active' : ''; ?>">
					<?php $this->render_email_settings_content(); ?>
				</div>
				<div id="tab-import-export" class="nms-tab-panel <?php echo $active_tab === 'import-export' ? 'active' : ''; ?>">
					<?php $this->render_import_export_content(); ?>
				</div>
				<div id="tab-advanced" class="nms-tab-panel <?php echo $active_tab === 'advanced' ? 'active' : ''; ?>">
					<?php $this->render_advanced_settings_content(); ?>
				</div>
				<div id="tab-logs" class="nms-tab-panel <?php echo $active_tab === 'logs' ? 'active' : ''; ?>">
					<?php $this->render_logs_content(); ?>
				</div>

			</div>
		</div>
		<?php
	}

	/**
	 * Render modules hub content for tab panel.
	 */
	private function render_modules_hub_content() {
		$modules = array(
			'two_factor'      => array(
				'name'            => __( '2FA', 'nexifymy-security' ),
				'icon'            => 'smartphone',
				'desc'            => __( 'Two-factor authentication', 'nexifymy-security' ),
				'info'            => __( 'Adds extra security layer with TOTP, Email, or SMS codes', 'nexifymy-security' ),
				'default_enabled' => true,
				'legacy_keys'     => array( '2fa_enabled' ),
			),
			'hardening'       => array(
				'name'            => __( 'Hardening', 'nexifymy-security' ),
				'icon'            => 'hammer',
				'desc'            => __( 'Security hardening', 'nexifymy-security' ),
				'info'            => __( 'Disables file editing, XML-RPC, and applies WordPress best practices', 'nexifymy-security' ),
				'default_enabled' => true,
			),
			'hide_login'      => array(
				'name'            => __( 'Hide Login', 'nexifymy-security' ),
				'icon'            => 'hidden',
				'desc'            => __( 'Hide wp-admin', 'nexifymy-security' ),
				'info'            => __( 'Changes login URL from /wp-admin to custom slug to prevent bot attacks', 'nexifymy-security' ),
				'default_enabled' => false,
			),
			'password'        => array(
				'name'            => __( 'Password', 'nexifymy-security' ),
				'icon'            => 'admin-network',
				'desc'            => __( 'Password policy', 'nexifymy-security' ),
				'info'            => __( 'Enforces strong passwords with minimum length, complexity rules', 'nexifymy-security' ),
				'default_enabled' => true,
				'legacy_keys'     => array( 'password_policy_enabled' ),
			),
			'captcha'         => array(
				'name'            => __( 'Captcha', 'nexifymy-security' ),
				'icon'            => 'shield',
				'desc'            => __( 'Bot protection', 'nexifymy-security' ),
				'info'            => __( 'Adds Google reCAPTCHA, Cloudflare Turnstile, or math challenges', 'nexifymy-security' ),
				'default_enabled' => true,
			),
			'self_protection' => array(
				'name'            => __( 'Self-Protection', 'nexifymy-security' ),
				'icon'            => 'lock',
				'desc'            => __( 'Plugin protection', 'nexifymy-security' ),
				'info'            => __( 'Prevents unauthorized modification of security plugin files', 'nexifymy-security' ),
				'default_enabled' => true,
			),
		);
		$settings = get_option( 'nexifymy_security_settings', array() );
		$enabled_modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		?>
		<div class="nms-modules-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; margin-bottom: 30px;">
			<?php foreach ( $modules as $key => $module ) :
				$option_key = $key . '_enabled';
				$is_enabled = null;

				if ( array_key_exists( $option_key, $enabled_modules ) ) {
					$is_enabled = ! empty( $enabled_modules[ $option_key ] );
				} elseif ( ! empty( $module['legacy_keys'] ) && is_array( $module['legacy_keys'] ) ) {
					foreach ( $module['legacy_keys'] as $legacy_key ) {
						if ( array_key_exists( $legacy_key, $enabled_modules ) ) {
							$is_enabled = ! empty( $enabled_modules[ $legacy_key ] );
							break;
						}
					}
				}

				if ( null === $is_enabled ) {
					$is_enabled = isset( $module['default_enabled'] ) ? (bool) $module['default_enabled'] : true;
				}
			?>
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body">
					<div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;">
						<div class="nms-stat-icon <?php echo $is_enabled ? 'green' : 'blue'; ?>" style="width: 40px; height: 40px; flex-shrink: 0;">
							<span class="dashicons dashicons-<?php echo esc_attr( $module['icon'] ); ?>"></span>
						</div>
						<div style="flex: 1;">
							<h4 style="margin: 0 0 4px 0; font-size: 15px;"><?php echo esc_html( $module['name'] ); ?></h4>
							<p style="margin: 0 0 8px 0; font-size: 12px; color: var(--nms-gray-500);"><?php echo esc_html( $module['desc'] ); ?></p>
							<p style="margin: 0; font-size: 11px; color: var(--nms-gray-400); line-height: 1.4;"><?php echo esc_html( $module['info'] ); ?></p>
						</div>
					</div>
					<div style="display: flex; justify-content: space-between; align-items: center; padding-top: 12px; border-top: 1px solid var(--nms-border);">
						<label class="nms-toggle">
							<input type="checkbox" class="module-toggle" data-module="<?php echo esc_attr( $key ); ?>" <?php checked( $is_enabled ); ?>>
							<span class="nms-toggle-slider"></span>
						</label>
						<span class="nms-badge <?php echo $is_enabled ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
							<?php echo $is_enabled ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
						</span>
					</div>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render 2FA content for tab panel.
	 */
	private function render_2fa_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$tfa_settings = isset( $settings['two_factor'] ) ? $settings['two_factor'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-smartphone"></span> <?php _e( 'Two-Factor Authentication', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Add an extra layer of security by requiring two forms of authentication for user logins.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable 2FA Module', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-enabled" data-module="two_factor" <?php checked( ! empty( $tfa_settings['enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Enable or disable two-factor authentication.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-shield"></span> <?php _e( '2FA Methods', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'TOTP Authenticator Apps', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-totp" <?php checked( ! empty( $tfa_settings['totp_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Support Google Authenticator, Authy, etc.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email Verification', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-email" <?php checked( ! empty( $tfa_settings['email_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Send verification codes via email.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Backup Codes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-backup" <?php checked( ! empty( $tfa_settings['backup_codes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Allow users to generate emergency backup codes.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Number of Backup Codes', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="2fa-backup-count" value="<?php echo intval( $tfa_settings['backup_code_count'] ?? 10 ); ?>" min="5" max="20" class="small-text">
							<p class="description"><?php _e( 'Number of backup codes to generate per user.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-groups"></span> <?php _e( 'User Requirements', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Mandatory for Roles', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="2fa-roles[]" value="administrator" <?php checked( in_array( 'administrator', $tfa_settings['mandatory_roles'] ?? array() ) ); ?>> Administrator</label><br>
							<label><input type="checkbox" name="2fa-roles[]" value="editor" <?php checked( in_array( 'editor', $tfa_settings['mandatory_roles'] ?? array() ) ); ?>> Editor</label><br>
							<label><input type="checkbox" name="2fa-roles[]" value="author" <?php checked( in_array( 'author', $tfa_settings['mandatory_roles'] ?? array() ) ); ?>> Author</label><br>
							<label><input type="checkbox" name="2fa-roles[]" value="contributor" <?php checked( in_array( 'contributor', $tfa_settings['mandatory_roles'] ?? array() ) ); ?>> Contributor</label>
							<p class="description"><?php _e( 'Require 2FA for selected user roles.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Optional for All Users', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-optional" <?php checked( ! empty( $tfa_settings['optional_all'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Allow all users to enable 2FA voluntarily.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Grace Period', 'nexifymy-security' ); ?></th>
						<td>
							<select id="2fa-grace-period" class="regular-text">
								<option value="0" <?php selected( $tfa_settings['grace_period'] ?? 7, 0 ); ?>><?php _e( 'No Grace Period', 'nexifymy-security' ); ?></option>
								<option value="1" <?php selected( $tfa_settings['grace_period'] ?? 7, 1 ); ?>><?php _e( '1 Day', 'nexifymy-security' ); ?></option>
								<option value="3" <?php selected( $tfa_settings['grace_period'] ?? 7, 3 ); ?>><?php _e( '3 Days', 'nexifymy-security' ); ?></option>
								<option value="7" <?php selected( $tfa_settings['grace_period'] ?? 7, 7 ); ?>><?php _e( '7 Days', 'nexifymy-security' ); ?></option>
								<option value="14" <?php selected( $tfa_settings['grace_period'] ?? 7, 14 ); ?>><?php _e( '14 Days', 'nexifymy-security' ); ?></option>
								<option value="30" <?php selected( $tfa_settings['grace_period'] ?? 7, 30 ); ?>><?php _e( '30 Days', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Allow users time to set up 2FA before enforcement.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-lock"></span> <?php _e( 'Security Options', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Remember Device', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-remember" <?php checked( ! empty( $tfa_settings['remember_device'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Allow users to skip 2FA on trusted devices.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Remember Duration', 'nexifymy-security' ); ?></th>
						<td>
							<select id="2fa-remember-duration" class="regular-text">
								<option value="86400" <?php selected( $tfa_settings['remember_duration'] ?? 2592000, 86400 ); ?>><?php _e( '1 Day', 'nexifymy-security' ); ?></option>
								<option value="604800" <?php selected( $tfa_settings['remember_duration'] ?? 2592000, 604800 ); ?>><?php _e( '7 Days', 'nexifymy-security' ); ?></option>
								<option value="2592000" <?php selected( $tfa_settings['remember_duration'] ?? 2592000, 2592000 ); ?>><?php _e( '30 Days', 'nexifymy-security' ); ?></option>
								<option value="7776000" <?php selected( $tfa_settings['remember_duration'] ?? 2592000, 7776000 ); ?>><?php _e( '90 Days', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Code Expiration', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="2fa-code-expiry" value="<?php echo intval( $tfa_settings['code_expiry'] ?? 300 ); ?>" min="60" max="600" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Time before email verification codes expire.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Max Attempts', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="2fa-max-attempts" value="<?php echo intval( $tfa_settings['max_attempts'] ?? 3 ); ?>" min="1" max="10" class="small-text">
							<p class="description"><?php _e( 'Failed 2FA attempts before temporary lockout.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="2fa-lockout" value="<?php echo intval( $tfa_settings['lockout_duration'] ?? 900 ); ?>" min="300" max="3600" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Lockout period after max failed 2FA attempts.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email Notifications', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="2fa-notify" <?php checked( ! empty( $tfa_settings['email_notify'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Notify users when 2FA is enabled/disabled on their account.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-2fa-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="2fa-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render hardening content for tab panel.
	 */
	private function render_hardening_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$hardening = isset( $settings['hardening'] ) ? $settings['hardening'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-hammer"></span> <?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Reduce attack surface by disabling unnecessary features and hardening WordPress configuration.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-edit"></span> <?php _e( 'Editor & File Access', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Disable File Editor', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_file_editor" <?php checked( ! empty( $hardening['disable_file_editor'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable plugin/theme file editor in WordPress admin.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Plugin/Theme Installation', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_install" <?php checked( ! empty( $hardening['disable_install'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent plugin/theme installation from admin panel.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable File Modifications', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_file_mods" <?php checked( ! empty( $hardening['disable_file_mods'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Completely disable all file modifications (DISALLOW_FILE_MODS).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-visibility"></span> <?php _e( 'Information Disclosure', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Hide WordPress Version', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="hide_wp_version" <?php checked( ! empty( $hardening['hide_wp_version'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Remove version information from HTML and feeds.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable REST API User Enumeration', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_rest_user_enum" <?php checked( ! empty( $hardening['disable_rest_user_enum'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent user discovery via /wp-json/wp/v2/users endpoint.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Author Archives', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_author_archives" <?php checked( ! empty( $hardening['disable_author_archives'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable author archive pages to prevent username enumeration.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Remove Generator Tags', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="remove_generator" <?php checked( ! empty( $hardening['remove_generator'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Remove generator meta tags from all pages.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Directory Browsing', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_directory_browse" <?php checked( ! empty( $hardening['disable_directory_browse'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent listing directory contents via .htaccess.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-rest-api"></span> <?php _e( 'API & Services', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Disable XML-RPC', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_xmlrpc" <?php checked( ! empty( $hardening['disable_xmlrpc'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable XML-RPC (used in DDoS and brute force attacks).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Pingbacks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_pingbacks" <?php checked( ! empty( $hardening['disable_pingbacks'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable pingback functionality to prevent DDoS.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Trackbacks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_trackbacks" <?php checked( ! empty( $hardening['disable_trackbacks'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable trackback functionality.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Embeds', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_embeds" <?php checked( ! empty( $hardening['disable_embeds'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable oEmbed functionality and REST API endpoints.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable RSS/Atom Feeds', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_feeds" <?php checked( ! empty( $hardening['disable_feeds'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Completely disable all RSS and Atom feeds.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-network"></span> <?php _e( 'Login Security', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Disable Login Error Messages', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_login_errors" <?php checked( ! empty( $hardening['disable_login_errors'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Show generic error message on login failure.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Remove Login Hints', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="remove_login_hints" <?php checked( ! empty( $hardening['remove_login_hints'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Remove password reset hints and suggestions.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Force SSL for Admin', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="force_ssl_admin" <?php checked( ! empty( $hardening['force_ssl_admin'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Force SSL/HTTPS for admin area (FORCE_SSL_ADMIN).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-database"></span> <?php _e( 'Database Security', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Change Database Prefix', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" name="db_prefix" value="<?php echo esc_attr( $hardening['db_prefix'] ?? '' ); ?>" placeholder="wp_" class="regular-text">
							<p class="description"><?php _e( 'Change database table prefix (requires manual database update).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-appearance"></span> <?php _e( 'Content Security', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Disable Right-Click', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_right_click" <?php checked( ! empty( $hardening['disable_right_click'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Disable right-click context menu on frontend.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Disable Text Selection', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="disable_text_selection" <?php checked( ! empty( $hardening['disable_text_selection'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent text selection and copying on frontend.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Add Security Headers', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="security_headers" <?php checked( ! empty( $hardening['security_headers'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Add X-Frame-Options, X-Content-Type-Options, and other security headers.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-hardening-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="hardening-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render hide login content for tab panel.
	 */
	private function render_hide_login_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$hide_login = isset( $settings['hide_login'] ) ? $settings['hide_login'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Hide Login Page', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Hide Login', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="hide-login-enabled" <?php checked( ! empty( $hide_login['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Custom Login URL', 'nexifymy-security' ); ?></th>
						<td><input type="text" id="hide-login-url" value="<?php echo esc_attr( $hide_login['login_url'] ?? '' ); ?>" class="regular-text" placeholder="my-secret-login"></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-hide-login-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="hide-login-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render password content for tab panel.
	 */
	private function render_password_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$pass_settings = isset( $settings['password'] ) ? $settings['password'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Password Policy', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enforce Strong Passwords', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="pass-enforce" <?php checked( ! empty( $pass_settings['enforce'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Minimum Length', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="pass-min-length" value="<?php echo intval( $pass_settings['min_length'] ?? 12 ); ?>" min="8" max="32" class="small-text"></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-pass-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="pass-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render captcha content for tab panel.
	 */
	private function render_captcha_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$captcha = isset( $settings['captcha'] ) ? $settings['captcha'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Captcha Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Captcha', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="captcha-enabled" <?php checked( ! empty( $captcha['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Captcha Provider', 'nexifymy-security' ); ?></th>
						<td>
							<select id="captcha-provider" class="regular-text">
								<option value="nexifymy" <?php selected( $captcha['provider'] ?? 'nexifymy', 'nexifymy' ); ?>><?php _e( 'NexifyMy Captcha (Built-in)', 'nexifymy-security' ); ?></option>
								<option value="recaptcha" <?php selected( $captcha['provider'] ?? 'nexifymy', 'recaptcha' ); ?>><?php _e( 'Google reCAPTCHA v2', 'nexifymy-security' ); ?></option>
								<option value="recaptcha_v3" <?php selected( $captcha['provider'] ?? 'nexifymy', 'recaptcha_v3' ); ?>><?php _e( 'Google reCAPTCHA v3', 'nexifymy-security' ); ?></option>
								<option value="turnstile" <?php selected( $captcha['provider'] ?? 'nexifymy', 'turnstile' ); ?>><?php _e( 'Cloudflare Turnstile', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Select which captcha service to use.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>

					<!-- NexifyMy Captcha Settings -->
					<tr class="nexifymy-captcha-row" style="display: <?php echo ( $captcha['provider'] ?? 'nexifymy' ) === 'nexifymy' ? 'table-row' : 'none'; ?>;">
						<th><?php _e( 'NexifyMy Captcha Type', 'nexifymy-security' ); ?></th>
						<td>
							<select id="captcha-nexifymy-type" class="regular-text">
								<option value="math" <?php selected( $captcha['nexifymy_type'] ?? 'math', 'math' ); ?>><?php _e( 'Math Question', 'nexifymy-security' ); ?></option>
								<option value="text_match" <?php selected( $captcha['nexifymy_type'] ?? 'math', 'text_match' ); ?>><?php _e( 'Text Matching', 'nexifymy-security' ); ?></option>
								<option value="image" <?php selected( $captcha['nexifymy_type'] ?? 'math', 'image' ); ?>><?php _e( 'Image Selection', 'nexifymy-security' ); ?></option>
								<option value="audio" <?php selected( $captcha['nexifymy_type'] ?? 'math', 'audio' ); ?>><?php _e( 'Audio (Speaking)', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Choose the type of challenge for NexifyMy captcha.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nexifymy-captcha-row" style="display: <?php echo ( $captcha['provider'] ?? 'nexifymy' ) === 'nexifymy' ? 'table-row' : 'none'; ?>;">
						<th><?php _e( 'Difficulty Level', 'nexifymy-security' ); ?></th>
						<td>
							<select id="captcha-difficulty" class="regular-text">
								<option value="easy" <?php selected( $captcha['difficulty'] ?? 'easy', 'easy' ); ?>><?php _e( 'Easy', 'nexifymy-security' ); ?></option>
								<option value="medium" <?php selected( $captcha['difficulty'] ?? 'easy', 'medium' ); ?>><?php _e( 'Medium', 'nexifymy-security' ); ?></option>
								<option value="hard" <?php selected( $captcha['difficulty'] ?? 'easy', 'hard' ); ?>><?php _e( 'Hard', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Difficulty level for NexifyMy captcha challenges.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>

					<!-- Google reCAPTCHA / Cloudflare Settings -->
					<tr class="external-captcha-row" style="display: <?php echo ( $captcha['provider'] ?? 'nexifymy' ) !== 'nexifymy' ? 'table-row' : 'none'; ?>;">
						<th><?php _e( 'Site Key', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="captcha-site-key" value="<?php echo esc_attr( $captcha['site_key'] ?? '' ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Get your keys from Google reCAPTCHA or Cloudflare Turnstile dashboard.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="external-captcha-row" style="display: <?php echo ( $captcha['provider'] ?? 'nexifymy' ) !== 'nexifymy' ? 'table-row' : 'none'; ?>;">
						<th><?php _e( 'Secret Key', 'nexifymy-security' ); ?></th>
						<td><input type="password" id="captcha-secret-key" value="<?php echo esc_attr( $captcha['secret_key'] ?? '' ); ?>" class="regular-text"></td>
					</tr>

					<!-- Common Settings -->
					<tr>
						<th><?php _e( 'Show on Forms', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" id="captcha-enable-login" <?php checked( ! empty( $captcha['enable_login'] ) ); ?>> <?php _e( 'Login Form', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="captcha-enable-registration" <?php checked( ! empty( $captcha['enable_registration'] ) ); ?>> <?php _e( 'Registration Form', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="captcha-enable-reset" <?php checked( ! empty( $captcha['enable_reset'] ) ); ?>> <?php _e( 'Password Reset Form', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="captcha-enable-comment" <?php checked( ! empty( $captcha['enable_comment'] ) ); ?>> <?php _e( 'Comment Form', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-captcha-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="captcha-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<script>
		jQuery(document).ready(function($) {
			$('#captcha-provider').on('change', function() {
				var provider = $(this).val();
				if (provider === 'nexifymy') {
					$('.nexifymy-captcha-row').show();
					$('.external-captcha-row').hide();
				} else {
					$('.nexifymy-captcha-row').hide();
					$('.external-captcha-row').show();
				}
			});
		});
		</script>
		<?php
	}

	/**
	 * Render tools hub content for tab panel.
	 */
	private function render_tools_hub_content() {
		$tools = array(
			array( 'name' => __( 'Database Optimizer', 'nexifymy-security' ), 'icon' => 'database', 'desc' => __( 'Clean and optimize database', 'nexifymy-security' ), 'tab' => 'database' ),
			array( 'name' => __( 'Core File Repair', 'nexifymy-security' ), 'icon' => 'hammer', 'desc' => __( 'Verify and repair core files', 'nexifymy-security' ), 'tab' => 'core' ),
			array( 'name' => __( 'Live Traffic', 'nexifymy-security' ), 'icon' => 'visibility', 'desc' => __( 'Monitor real-time traffic', 'nexifymy-security' ), 'tab' => 'traffic' ),
		);
		?>
		<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px;">
			<?php foreach ( $tools as $tool ) : ?>
			<div class="nms-card" style="margin: 0; cursor: pointer;" onclick="jQuery('.nms-page-tab[data-tab=\'<?php echo esc_attr( $tool['tab'] ); ?>\']').click();">
				<div class="nms-card-body" style="display: flex; align-items: center; gap: 16px;">
					<div class="nms-stat-icon blue" style="width: 48px; height: 48px;">
						<span class="dashicons dashicons-<?php echo esc_attr( $tool['icon'] ); ?>"></span>
					</div>
					<div>
						<h4 style="margin: 0 0 4px; font-size: 15px; font-weight: 600;"><?php echo esc_html( $tool['name'] ); ?></h4>
						<p style="margin: 0; font-size: 13px; color: var(--nms-gray-500);"><?php echo esc_html( $tool['desc'] ); ?></p>
					</div>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render database content for tab panel.
	 */
	private function render_database_content() {
		global $wpdb;
		$tables = $wpdb->get_results( "SHOW TABLE STATUS" );
		$total_size = 0;
		$overhead = 0;
		foreach ( $tables as $table ) {
			$total_size += $table->Data_length + $table->Index_length;
			$overhead += $table->Data_free;
		}
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-database"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo count( $tables ); ?></h4>
					<p><?php _e( 'Tables', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-chart-area"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo size_format( $total_size ); ?></h4>
					<p><?php _e( 'Total Size', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon <?php echo $overhead > 0 ? 'orange' : 'green'; ?>"><span class="dashicons dashicons-warning"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo size_format( $overhead ); ?></h4>
					<p><?php _e( 'Overhead', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Database Actions', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<button class="nms-btn nms-btn-primary" id="optimize-db"><?php _e( 'Optimize Database', 'nexifymy-security' ); ?></button>
				<span id="db-status" style="margin-left: 15px;"></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Render core repair content for tab panel.
	 */
	private function render_core_repair_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'WordPress Core File Verification', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p class="description"><?php _e( 'Compare your WordPress core files against the official checksums to detect modifications.', 'nexifymy-security' ); ?></p>
				<div style="margin-top: 20px;">
					<button class="nms-btn nms-btn-primary" id="verify-core"><?php _e( 'Verify Core Files', 'nexifymy-security' ); ?></button>
					<span id="core-status" style="margin-left: 15px;"></span>
				</div>
				<div id="core-results" style="margin-top: 20px; display: none;"></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render live traffic content for tab panel.
	 */
	private function render_live_traffic_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Live Traffic Monitor', 'nexifymy-security' ); ?></h3>
				<button class="nms-btn nms-btn-secondary" id="refresh-traffic"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="traffic-table">
					<thead>
						<tr>
							<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Method', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'URL', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="traffic-tbody">
						<tr><td colspan="5"><?php _e( 'Loading traffic data...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render supply chain security content.
	 */
	private function render_supply_chain_content() {
		global $nexifymy_supply_chain;
		$results = $nexifymy_supply_chain ? $nexifymy_supply_chain->get_last_results() : array();
		$settings = $nexifymy_supply_chain ? $nexifymy_supply_chain->get_settings() : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Supply Chain Security', 'nexifymy-security' ); ?></h3>
				<div>
					<button class="nms-btn nms-btn-primary" id="run-supply-chain-scan">
						<span class="dashicons dashicons-update"></span> <?php _e( 'Run Scan', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>
			<div class="nms-card-body">
				<?php if ( empty( $results ) ) : ?>
					<p><?php _e( 'No scan results available. Click "Run Scan" to analyze your dependencies.', 'nexifymy-security' ); ?></p>
				<?php else : ?>
					<!-- Summary Stats -->
					<div class="nms-stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
						<div class="nms-stat-card">
							<div class="nms-stat-label"><?php _e( 'Last Scan', 'nexifymy-security' ); ?></div>
							<div class="nms-stat-value"><?php echo esc_html( $results['scanned_at'] ?? '-' ); ?></div>
						</div>
						<div class="nms-stat-card <?php echo isset( $results['total_issues'] ) && $results['total_issues'] > 0 ? 'danger' : 'success'; ?>">
							<div class="nms-stat-label"><?php _e( 'Issues Found', 'nexifymy-security' ); ?></div>
							<div class="nms-stat-value"><?php echo intval( $results['total_issues'] ?? 0 ); ?></div>
						</div>
					</div>

					<!-- Plugins Section -->
					<?php if ( ! empty( $results['plugins'] ) ) : ?>
					<div class="nms-section" style="margin-bottom: 25px;">
						<h4><?php _e( 'Plugins', 'nexifymy-security' ); ?></h4>
						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-bottom: 15px;">
							<div class="nms-info-box">
								<strong><?php echo intval( $results['plugins']['total'] ?? 0 ); ?></strong> Total Plugins
							</div>
							<div class="nms-info-box danger">
								<strong><?php echo count( $results['plugins']['vulnerable'] ?? array() ); ?></strong> Vulnerable
							</div>
							<div class="nms-info-box warning">
								<strong><?php echo count( $results['plugins']['outdated'] ?? array() ); ?></strong> Outdated
							</div>
							<div class="nms-info-box">
								<strong><?php echo count( $results['plugins']['abandoned'] ?? array() ); ?></strong> Abandoned
							</div>
						</div>

						<?php if ( ! empty( $results['plugins']['vulnerable'] ) || ! empty( $results['plugins']['outdated'] ) ) : ?>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php _e( 'Plugin', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Current Version', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Latest Version', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( array_merge( $results['plugins']['vulnerable'] ?? array(), $results['plugins']['outdated'] ?? array() ) as $plugin ) : ?>
								<tr>
									<td><strong><?php echo esc_html( $plugin['name'] ); ?></strong></td>
									<td><?php echo esc_html( $plugin['version'] ); ?></td>
									<td><?php echo esc_html( $plugin['latest_version'] ?? '-' ); ?></td>
									<td>
										<?php if ( isset( $plugin['vulnerable'] ) && $plugin['vulnerable'] ) : ?>
											<span class="nms-badge nms-badge-danger"><?php _e( 'Vulnerable', 'nexifymy-security' ); ?></span>
										<?php elseif ( $plugin['status'] === 'outdated' ) : ?>
											<span class="nms-badge nms-badge-warning"><?php _e( 'Outdated', 'nexifymy-security' ); ?></span>
										<?php elseif ( $plugin['status'] === 'abandoned' ) : ?>
											<span class="nms-badge nms-badge-secondary"><?php _e( 'Abandoned', 'nexifymy-security' ); ?></span>
										<?php endif; ?>
									</td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<?php endif; ?>
					</div>
					<?php endif; ?>

					<!-- Composer Dependencies -->
					<?php if ( ! empty( $results['composer']['found'] ) ) : ?>
					<div class="nms-section" style="margin-bottom: 25px;">
						<h4><?php _e( 'Composer Dependencies', 'nexifymy-security' ); ?></h4>
						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-bottom: 15px;">
							<div class="nms-info-box">
								<strong><?php echo count( $results['composer']['packages'] ?? array() ); ?></strong> Packages
							</div>
							<div class="nms-info-box <?php echo count( $results['composer']['vulnerable'] ?? array() ) > 0 ? 'danger' : 'success'; ?>">
								<strong><?php echo count( $results['composer']['vulnerable'] ?? array() ); ?></strong> Vulnerable
							</div>
						</div>

						<?php if ( ! empty( $results['composer']['vulnerable'] ) ) : ?>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php _e( 'Package', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Version', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $results['composer']['vulnerable'] as $pkg ) : ?>
								<tr>
									<td><code><?php echo esc_html( $pkg['name'] ); ?></code></td>
									<td><?php echo esc_html( $pkg['version'] ); ?></td>
									<td><span class="nms-badge nms-badge-danger"><?php _e( 'Vulnerable', 'nexifymy-security' ); ?></span></td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<?php endif; ?>
					</div>
					<?php endif; ?>

					<!-- NPM Dependencies -->
					<?php if ( ! empty( $results['npm']['found'] ) ) : ?>
					<div class="nms-section" style="margin-bottom: 25px;">
						<h4><?php _e( 'NPM Dependencies', 'nexifymy-security' ); ?></h4>
						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-bottom: 15px;">
							<div class="nms-info-box">
								<strong><?php echo count( $results['npm']['packages'] ?? array() ); ?></strong> Packages
							</div>
							<div class="nms-info-box <?php echo count( $results['npm']['vulnerable'] ?? array() ) > 0 ? 'danger' : 'success'; ?>">
								<strong><?php echo count( $results['npm']['vulnerable'] ?? array() ); ?></strong> Vulnerable
							</div>
						</div>

						<?php if ( ! empty( $results['npm']['vulnerable'] ) ) : ?>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php _e( 'Package', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Version', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $results['npm']['vulnerable'] as $pkg ) : ?>
								<tr>
									<td><code><?php echo esc_html( $pkg['name'] ); ?></code></td>
									<td><?php echo esc_html( $pkg['version'] ); ?></td>
									<td><span class="nms-badge nms-badge-danger"><?php _e( 'Vulnerable', 'nexifymy-security' ); ?></span></td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<?php endif; ?>
					</div>
					<?php endif; ?>

					<!-- External Scripts -->
					<?php if ( ! empty( $results['external_scripts']['total'] ) ) : ?>
					<div class="nms-section">
						<h4><?php _e( 'External Scripts & CDN Resources', 'nexifymy-security' ); ?></h4>
						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-bottom: 15px;">
							<div class="nms-info-box">
								<strong><?php echo intval( $results['external_scripts']['total'] ?? 0 ); ?></strong> External Scripts
							</div>
							<div class="nms-info-box success">
								<strong><?php echo count( $results['external_scripts']['verified'] ?? array() ); ?></strong> Verified
							</div>
							<div class="nms-info-box warning">
								<strong><?php echo count( $results['external_scripts']['unverified'] ?? array() ); ?></strong> Unverified
							</div>
						</div>

						<?php if ( ! empty( $results['external_scripts']['unverified'] ) ) : ?>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php _e( 'Handle', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Host', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Action', 'nexifymy-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $results['external_scripts']['unverified'] as $script ) : ?>
								<tr>
									<td><code><?php echo esc_html( $script['handle'] ); ?></code></td>
									<td><?php echo esc_html( $script['host'] ); ?></td>
									<td><span class="nms-badge nms-badge-warning"><?php _e( 'No SRI', 'nexifymy-security' ); ?></span></td>
									<td>
										<button class="button button-small verify-cdn-script" data-url="<?php echo esc_attr( $script['src'] ); ?>">
											<?php _e( 'Generate SRI', 'nexifymy-security' ); ?>
										</button>
									</td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<?php endif; ?>
					</div>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		</div>

		<!-- Settings Card -->
		<div class="nms-card" style="margin-top: 20px;">
			<div class="nms-card-header">
				<h3><?php _e( 'Supply Chain Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Scan Plugins', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-scan-plugins" <?php checked( ! empty( $settings['scan_plugins'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Themes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-scan-themes" <?php checked( ! empty( $settings['scan_themes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Composer Dependencies', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-scan-composer" <?php checked( ! empty( $settings['scan_composer'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan NPM Dependencies', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-scan-npm" <?php checked( ! empty( $settings['scan_npm'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Monitor External Scripts', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-monitor-scripts" <?php checked( ! empty( $settings['monitor_external_scripts'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Scan Schedule', 'nexifymy-security' ); ?></th>
						<td>
							<select id="supply-chain-auto-scan">
								<option value="daily" <?php selected( $settings['auto_scan_schedule'] ?? '', 'daily' ); ?>><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								<option value="weekly" <?php selected( $settings['auto_scan_schedule'] ?? '', 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email Notifications', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="supply-chain-notify" <?php checked( ! empty( $settings['notify_on_issues'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Receive email alerts when vulnerabilities are detected', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" class="button button-primary" id="save-supply-chain-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>

		<script>
		jQuery(document).ready(function($) {
			// Run scan
			$('#run-supply-chain-scan').on('click', function() {
				var btn = $(this);
				btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Scanning...');

				$.post(ajaxurl, {
					action: 'nexifymy_supply_chain_scan',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>'
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert('Scan failed: ' + (response.data || 'Unknown error'));
						btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Run Scan');
					}
				});
			});

			// Verify CDN script
			$(document).on('click', '.verify-cdn-script', function() {
				var btn = $(this);
				var url = btn.data('url');
				btn.prop('disabled', true).text('Generating...');

				$.post(ajaxurl, {
					action: 'nexifymy_verify_cdn_script',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>',
					url: url
				}, function(response) {
					if (response.success && response.data.integrity) {
						var integrity = response.data.integrity;
						prompt('Copy this SRI hash:', integrity);
					} else {
						alert('Failed to generate SRI hash');
					}
					btn.prop('disabled', false).text('Generate SRI');
				});
			});

			// Save settings
			$('#save-supply-chain-settings').on('click', function() {
				var settings = {
					enabled: true,
					scan_plugins: $('#supply-chain-scan-plugins').is(':checked'),
					scan_themes: $('#supply-chain-scan-themes').is(':checked'),
					scan_composer: $('#supply-chain-scan-composer').is(':checked'),
					scan_npm: $('#supply-chain-scan-npm').is(':checked'),
					monitor_external_scripts: $('#supply-chain-monitor-scripts').is(':checked'),
					verify_cdn_integrity: true,
					auto_scan_schedule: $('#supply-chain-auto-scan').val(),
					notify_on_issues: $('#supply-chain-notify').is(':checked')
				};

				$.post(ajaxurl, {
					action: 'nexifymy_save_module_settings',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>',
					module: 'supply_chain',
					settings: settings
				}, function(response) {
					if (response.success) {
						alert('Settings saved successfully');
					}
				});
			});
		});
		</script>
		<?php
	}

	/**
	 * Render compliance & reporting content.
	 */
	private function render_compliance_content() {
		global $nexifymy_compliance;
		$reports = $nexifymy_compliance ? $nexifymy_compliance->get_reports() : array();
		$settings = $nexifymy_compliance ? $nexifymy_compliance->get_settings() : array();

		// Get latest report for quick stats
		$latest_report = null;
		if ( ! empty( $reports ) ) {
			$latest_report = end( $reports );
		}
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Compliance & Security Reporting', 'nexifymy-security' ); ?></h3>
				<div>
					<button class="nms-btn nms-btn-secondary" id="run-compliance-check">
						<span class="dashicons dashicons-yes-alt"></span> <?php _e( 'Run Quick Check', 'nexifymy-security' ); ?>
					</button>
					<button class="nms-btn nms-btn-primary" id="generate-compliance-report">
						<span class="dashicons dashicons-media-document"></span> <?php _e( 'Generate Report', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>
			<div class="nms-card-body">
				<?php if ( $latest_report ) : ?>
					<div class="nms-compliance-summary" style="display: grid; grid-template-columns: 180px 1fr; gap: 30px; padding: 30px; background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%); border-radius: 12px; margin-bottom: 30px;">
						<div style="text-align: center;">
							<div class="nms-grade-circle" style="width: 140px; height: 140px; border-radius: 50%; background: <?php echo $latest_report['grade'] === 'A' ? '#22c55e' : ($latest_report['grade'] === 'B' ? '#84cc16' : ($latest_report['grade'] === 'C' ? '#eab308' : ($latest_report['grade'] === 'D' ? '#f97316' : '#ef4444'))); ?>; display: flex; align-items: center; justify-content: center; font-size: 64px; font-weight: bold; color: white; box-shadow: 0 8px 20px rgba(0,0,0,0.3); margin: 0 auto;">
								<?php echo esc_html( $latest_report['grade'] ); ?>
							</div>
							<div style="color: rgba(255,255,255,0.9); margin-top: 10px; font-size: 13px;">Security Grade</div>
						</div>
						<div style="color: white;">
							<h3 style="margin: 0 0 15px 0; font-size: 24px; color: white;">Security Score: <?php echo esc_html( $latest_report['score'] ); ?>%</h3>
							<p style="opacity: 0.9; margin-bottom: 20px;">Last generated: <?php echo esc_html( $latest_report['generated_at'] ); ?></p>
							<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
								<div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; text-align: center;">
									<div style="font-size: 28px; font-weight: bold; color: #22c55e;"><i class="fas fa-check-circle"></i></div>
									<div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">Compliant</div>
								</div>
								<div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; text-align: center;">
									<div style="font-size: 28px; font-weight: bold; color: #ef4444;"><i class="fas fa-times-circle"></i></div>
									<div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">Critical</div>
								</div>
								<div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; text-align: center;">
									<div style="font-size: 28px; font-weight: bold; color: #eab308;"><i class="fas fa-exclamation-triangle"></i></div>
									<div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">Warnings</div>
								</div>
							</div>
						</div>
					</div>
				<?php else : ?>
					<div class="nms-empty-state" style="text-align: center; padding: 60px 20px; background: #f8fafc; border-radius: 12px; margin-bottom: 30px;">
						<span class="dashicons dashicons-media-document" style="font-size: 64px; color: #cbd5e1; margin-bottom: 15px;"></span>
						<h3 style="margin: 0 0 10px 0; color: #64748b;">No Reports Generated Yet</h3>
						<p style="color: #94a3b8; margin-bottom: 20px;">Generate your first compliance report to assess your security posture.</p>
						<button class="nms-btn nms-btn-primary" id="generate-first-report">
							<span class="dashicons dashicons-media-document"></span> Generate First Report
						</button>
					</div>
				<?php endif; ?>

				<!-- Quick Compliance Check Results -->
				<div id="quick-compliance-results" style="display: none; margin-bottom: 30px;">
					<h4 style="margin: 0 0 15px 0;">Compliance Check Results</h4>
					<div id="compliance-check-grid"></div>
				</div>

				<!-- Reports History -->
				<div class="nms-section">
					<h4><?php _e( 'Report History', 'nexifymy-security' ); ?></h4>
					<?php if ( ! empty( $reports ) ) : ?>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php _e( 'Generated', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Score', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Grade', 'nexifymy-security' ); ?></th>
									<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( array_reverse( $reports, true ) as $report ) : ?>
								<tr>
									<td><?php echo esc_html( $report['generated_at'] ); ?></td>
									<td><?php echo esc_html( $report['score'] ); ?>%</td>
									<td>
										<span class="nms-grade-badge nms-grade-<?php echo esc_attr( strtolower( $report['grade'] ) ); ?>" style="display: inline-block; width: 32px; height: 32px; border-radius: 50%; text-align: center; line-height: 32px; font-weight: bold; color: white;">
											<?php echo esc_html( $report['grade'] ); ?>
										</span>
									</td>
									<td>
										<button class="button button-small download-report" data-report-id="<?php echo esc_attr( $report['id'] ); ?>">
											<span class="dashicons dashicons-download"></span> <?php _e( 'Download', 'nexifymy-security' ); ?>
										</button>
									</td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php else : ?>
						<p><?php _e( 'No reports available.', 'nexifymy-security' ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		</div>

		<!-- Settings Card -->
		<div class="nms-card" style="margin-top: 20px;">
			<div class="nms-card-header">
				<h3><?php _e( 'Compliance Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th style="vertical-align: middle;"><?php _e( 'Auto-Generate Reports', 'nexifymy-security' ); ?></th>
						<td style="vertical-align: middle;">
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-auto-generate" <?php checked( ! empty( $settings['auto_generate'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Automatically generate reports on schedule', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th style="vertical-align: middle;"><?php _e( 'Report Schedule', 'nexifymy-security' ); ?></th>
						<td style="vertical-align: middle;">
							<select id="compliance-schedule">
								<option value="daily" <?php selected( $settings['schedule'] ?? '', 'daily' ); ?>><?php _e( 'Daily', 'nexifymy-security' ); ?></option>
								<option value="weekly" <?php selected( $settings['schedule'] ?? '', 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
								<option value="monthly" <?php selected( $settings['schedule'] ?? '', 'monthly' ); ?>><?php _e( 'Monthly', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th style="vertical-align: middle;"><?php _e( 'Email Reports', 'nexifymy-security' ); ?></th>
						<td style="vertical-align: middle;">
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-email-reports" <?php checked( ! empty( $settings['email_reports'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Send reports to admin email', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Include GDPR Checks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-include-gdpr" <?php checked( ! empty( $settings['include_gdpr'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Include Security Checks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-include-security" <?php checked( ! empty( $settings['include_security'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Include Threat Summary', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-include-threats" <?php checked( ! empty( $settings['include_threats'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Include Performance Metrics', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="compliance-include-performance" <?php checked( ! empty( $settings['include_performance'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Report Retention (days)', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="compliance-retention-days" value="<?php echo esc_attr( $settings['retention_days'] ?? 90 ); ?>" min="30" max="365" class="small-text">
							<p class="description"><?php _e( 'How long to keep old reports (30-365 days)', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" class="button button-primary" id="save-compliance-settings"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>

		<script>
		jQuery(document).ready(function($) {
			// Generate report
			$('#generate-compliance-report, #generate-first-report').on('click', function() {
				var btn = $(this);
				btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Generating...');

				$.post(ajaxurl, {
					action: 'nexifymy_generate_report',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>'
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert('Report generation failed: ' + (response.data || 'Unknown error'));
						btn.prop('disabled', false).html('<span class="dashicons dashicons-media-document"></span> Generate Report');
					}
				});
			});

			// Run quick compliance check
			$('#run-compliance-check').on('click', function() {
				var btn = $(this);
				btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Checking...');

				$.post(ajaxurl, {
					action: 'nexifymy_run_compliance_check',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>'
				}, function(response) {
					if (response.success) {
						displayComplianceResults(response.data);
						btn.prop('disabled', false).html('<span class="dashicons dashicons-yes-alt"></span> Run Quick Check');
					} else {
						alert('Check failed: ' + (response.data || 'Unknown error'));
						btn.prop('disabled', false).html('<span class="dashicons dashicons-yes-alt"></span> Run Quick Check');
					}
				});
			});

			function displayComplianceResults(results) {
				var html = '<div style="display: grid; gap: 20px;">';

				$.each(results, function(category, data) {
					var passed = 0;
					var failed = 0;
					var checks = data.checks;

					$.each(checks, function(key, check) {
						if (check.passed) passed++;
						else failed++;
					});

					var total = passed + failed;
					var percentage = total > 0 ? Math.round((passed / total) * 100) : 0;

					html += '<div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">';
					html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">';
					html += '<h4 style="margin: 0;">' + data.name + '</h4>';
					html += '<span style="font-size: 24px; font-weight: bold; color: ' + (percentage >= 80 ? '#22c55e' : (percentage >= 60 ? '#eab308' : '#ef4444')) + ';">' + percentage + '%</span>';
					html += '</div>';

					html += '<div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">';
					$.each(checks, function(key, check) {
						html += '<div style="display: flex; align-items: center; padding: 8px; background: ' + (check.passed ? '#f0fdf4' : '#fef2f2') + '; border-radius: 6px;">';
						html += '<span style="margin-right: 10px;">' + (check.passed ? '✓' : '✗') + '</span>';
						html += '<span style="font-size: 13px;">' + check.name + '</span>';
						html += '</div>';
					});
					html += '</div></div>';
				});

				html += '</div>';

				$('#compliance-check-grid').html(html);
				$('#quick-compliance-results').slideDown();
			}

			// Download report
			$(document).on('click', '.download-report', function() {
				var reportId = $(this).data('report-id');

				$.post(ajaxurl, {
					action: 'nexifymy_download_report',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>',
					report_id: reportId
				}, function(response) {
					if (response.success && response.data.url) {
						window.open(response.data.url, '_blank');
					} else {
						alert('Failed to download report');
					}
				});
			});

			// Save settings
			$('#save-compliance-settings').on('click', function() {
				var settings = {
					enabled: true,
					auto_generate: $('#compliance-auto-generate').is(':checked'),
					schedule: $('#compliance-schedule').val(),
					email_reports: $('#compliance-email-reports').is(':checked'),
					include_gdpr: $('#compliance-include-gdpr').is(':checked'),
					include_security: $('#compliance-include-security').is(':checked'),
					include_performance: $('#compliance-include-performance').is(':checked'),
					include_threats: $('#compliance-include-threats').is(':checked'),
					retention_days: parseInt($('#compliance-retention-days').val())
				};

				$.post(ajaxurl, {
					action: 'nexifymy_save_module_settings',
					nonce: '<?php echo wp_create_nonce( 'nexifymy_security_nonce' ); ?>',
					module: 'compliance',
					settings: settings
				}, function(response) {
					if (response.success) {
						alert('Settings saved successfully');
					}
				});
			});
		});
		</script>
		<?php
	}

	/**
	 * Render settings content for tab panel.
	 */
	private function render_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'General Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Plugin Language', 'nexifymy-security' ); ?></th>
						<td>
							<select name="general[language]" id="settings-language">
								<?php
								$current_lang = $settings['general']['language'] ?? 'site_default';
								$languages    = NexifyMy_Security_Settings::get_available_languages();
								foreach ( $languages as $code => $label ) {
									echo '<option value="' . esc_attr( $code ) . '" ' . selected( $current_lang, $code, false ) . '>' . esc_html( $label ) . '</option>';
								}
								?>
							</select>
							<p class="description">
								<?php
								printf(
									/* translators: %d: number of languages */
									esc_html__( 'Override the language for the plugin interface. Supported languages: %d', 'nexifymy-security' ),
									count( $languages )
								);
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Plugin Last Updated', 'nexifymy-security' ); ?></th>
						<td>
							<?php
							$plugin_file = NEXIFYMY_SECURITY_PATH . 'nexifymy-security.php';
							if ( file_exists( $plugin_file ) ) {
								echo esc_html( date_i18n( get_option( 'date_format' ), filemtime( $plugin_file ) ) );
							} else {
								esc_html_e( 'Unknown', 'nexifymy-security' );
							}
							?>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email Notifications', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="general[email_notifications]" id="settings-email" <?php checked( ! empty( $settings['general']['email_notifications'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Notification Email', 'nexifymy-security' ); ?></th>
						<td><input type="email" name="general[email_address]" id="settings-email-address" value="<?php echo esc_attr( $settings['general']['email_address'] ?? get_option( 'admin_email' ) ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Updates', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" name="general[auto_updates]" id="settings-auto-update" <?php checked( ! empty( $settings['general']['auto_updates'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-general-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="general-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render logs content for tab panel.
	 */
	private function render_logs_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Security Logs', 'nexifymy-security' ); ?></h3>
				<div>
					<button class="nms-btn nms-btn-secondary" id="refresh-logs"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
					<button class="nms-btn nms-btn-danger" id="clear-logs"><?php _e( 'Clear Logs', 'nexifymy-security' ); ?></button>
				</div>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="logs-table">
					<thead>
						<tr>
							<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="logs-tbody">
						<tr><td colspan="5"><?php _e( 'Loading logs...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render notifications content for tab panel.
	 */
	private function render_notifications_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Security Notifications', 'nexifymy-security' ); ?></h3>
				<button class="nms-btn nms-btn-secondary" id="mark-all-read"><?php _e( 'Mark All Read', 'nexifymy-security' ); ?></button>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="notifications-table">
					<thead>
						<tr>
							<th><?php _e( 'Date', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Type', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Message', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'IP', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="notifications-tbody">
						<tr><td colspan="4"><?php _e( 'Loading notifications...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
		</div>
		</div>
		<?php
	}

	/**
	 * Render scanner content for tab panel.
	 */
	private function render_scanner_content() {
		$last_scan = get_option( 'nexifymy_last_scan', array() );
		$scan_results = get_option( 'nexifymy_scan_results', array() );
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-media-document"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo number_format( $last_scan['files_scanned'] ?? 0 ); ?></h4>
					<p><?php _e( 'Files Scanned', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon <?php echo ( $scan_results['threats'] ?? 0 ) > 0 ? 'red' : 'green'; ?>"><span class="dashicons dashicons-shield"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo intval( $scan_results['threats'] ?? 0 ); ?></h4>
					<p><?php _e( 'Threats Found', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-clock"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo $last_scan['time'] ? human_time_diff( strtotime( $last_scan['time'] ) ) . ' ago' : __( 'Never', 'nexifymy-security' ); ?></h4>
					<p><?php _e( 'Last Scan', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>

		<?php
		// Display Site Health Dashboard if scan results exist
		if ( isset( $scan_results['scan_summary'] ) ) {
			$this->render_site_health_dashboard( $scan_results['scan_summary'] );
		}
		?>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Start a Scan', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<div class="nms-scan-modes-grid">
					<div class="nms-scan-mode-card" data-mode="quick">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-search"></span>
						</div>
						<h4><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Fast security check', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'High-risk areas only', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Fast execution', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Checks for web shells', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
					<div class="nms-scan-mode-card" data-mode="standard">
						<div class="nms-recommended-badge"><?php _e( 'Recommended', 'nexifymy-security' ); ?></div>
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield"></span>
						</div>
						<h4><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Full malware scan', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full malware signatures', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Plugin & Theme analysis', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Database security check', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
					<div class="nms-scan-mode-card" data-mode="deep">
						<div class="nms-scan-mode-icon">
							<span class="dashicons dashicons-shield-alt"></span>
						</div>
						<h4><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></h4>
						<p><?php _e( 'Comprehensive analysis', 'nexifymy-security' ); ?></p>
						<ul class="nms-scan-features">
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Core file integrity', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Advanced heuristics', 'nexifymy-security' ); ?></li>
							<li><span class="dashicons dashicons-yes"></span> <?php _e( 'Full site analysis', 'nexifymy-security' ); ?></li>
						</ul>
						<button class="nms-btn nms-btn-primary scan-btn"><?php _e( 'Start Scan', 'nexifymy-security' ); ?></button>
					</div>
				</div>
				<div id="scan-progress" class="nms-scan-progress-panel" style="display: none;">
					<div class="nms-progress-header">
						<span class="dashicons dashicons-update spin"></span>
						<span id="scan-status-text"><?php _e( 'Initializing...', 'nexifymy-security' ); ?></span>
					</div>
					<div class="nms-progress-bar"><div class="nms-progress-fill" style="width: 0%;"></div></div>
					<div class="nms-progress-info">
						<span id="scan-files-count">0 / 0 files</span>
						<span class="nms-progress-percent">0%</span>
					</div>
					<div class="nms-progress-current" style="margin-top: 10px; font-size: 12px; color: #666;">
						<strong><?php _e( 'Current:', 'nexifymy-security' ); ?></strong>
						<code id="scan-current-file" style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">—</code>
					</div>
					<div id="scan-threat-counts" class="nms-threat-counts" style="margin-top: 10px; display: flex; gap: 15px; font-size: 13px;">
						<!-- Filled dynamically by JS -->
					</div>
				</div>
				<div id="scan-results" style="display: none; margin-top: 20px;">
					<div id="results-content"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render site health dashboard.
	 *
	 * @param array $health_summary Health metrics from scan.
	 */
	private function render_site_health_dashboard( $health_summary ) {
		// Load health calculator for display helpers
		require_once NEXIFYMY_SECURITY_PATH . 'modules/site-health-calculator.php';
		$health_calculator = new NexifyMy_Security_Site_Health_Calculator();

		$health_score = $health_summary['health_score'] ?? 0;
		$health_status = $health_summary['health_status'] ?? 'at_risk';
		$display = $health_calculator->get_health_status_display( $health_status );

		$progress_width = $health_score;
		$progress_color = $display['color'];
		?>
		<div class="nms-card nms-health-dashboard" style="margin-bottom: 20px; border-left: 4px solid <?php echo esc_attr( $progress_color ); ?>;">
			<div class="nms-card-header">
				<h3>
					<span class="dashicons dashicons-heart" style="color: <?php echo esc_attr( $progress_color ); ?>;"></span>
					<?php _e( 'Site Security Health', 'nexifymy-security' ); ?>
				</h3>
			</div>
			<div class="nms-card-body">
				<div style="display: flex; align-items: center; gap: 30px; margin-bottom: 25px;">
					<div style="flex: 0 0 auto;">
						<div style="position: relative; width: 120px; height: 120px;">
							<svg viewBox="0 0 100 100" style="transform: rotate(-90deg); width: 100%; height: 100%;">
								<circle cx="50" cy="50" r="42" fill="none" stroke="#e0e0e0" stroke-width="8"></circle>
								<circle cx="50" cy="50" r="42" fill="none" stroke="<?php echo esc_attr( $progress_color ); ?>" stroke-width="8"
									stroke-dasharray="<?php echo esc_attr( ( $health_score / 100 ) * 264 ); ?> 264"
									stroke-linecap="round"></circle>
							</svg>
							<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
								<strong style="font-size: 28px; display: block;"><?php echo esc_html( $health_score ); ?></strong>
								<span style="font-size: 14px; color: #666;">/100</span>
							</div>
						</div>
					</div>
					<div style="flex: 1;">
						<div style="margin-bottom: 15px;">
							<span style="display: inline-block; padding: 6px 16px; background: <?php echo esc_attr( $progress_color ); ?>; color: white; border-radius: 20px; font-weight: 600; font-size: 14px;">
								<?php echo esc_html( $display['icon'] . ' ' . $display['label'] ); ?>
							</span>
						</div>
						<div style="margin-bottom: 10px;">
							<strong><?php _e( 'Files Scanned:', 'nexifymy-security' ); ?></strong>
							<?php echo number_format( $health_summary['total_files_scanned'] ); ?>
						</div>
						<div style="margin-bottom: 10px;">
							<strong style="color: #28a745;"><?php _e( 'Clean Files:', 'nexifymy-security' ); ?></strong>
							<?php echo number_format( $health_summary['clean_files'] ); ?>
							(<?php echo esc_html( $health_summary['clean_percentage'] ); ?>%)
						</div>
						<div>
							<strong style="color: #dc3545;"><?php _e( 'Affected Files:', 'nexifymy-security' ); ?></strong>
							<?php echo number_format( $health_summary['files_with_threats'] ); ?>
							(<?php echo esc_html( $health_summary['affected_percentage'] ); ?>%)
						</div>
					</div>
				</div>

				<?php if ( $health_summary['files_with_threats'] > 0 ) : ?>
					<?php
					$scan_results = get_option( 'nexifymy_scan_results', array() );
					$classification_counts = $scan_results['classification_counts'] ?? array();
					?>
					<div style="padding: 15px; background: #f9f9f9; border-radius: 5px; margin-bottom: 20px;">
						<h4 style="margin-top: 0; margin-bottom: 15px;">
							<span class="dashicons dashicons-warning"></span>
							<?php _e( 'Threat Breakdown:', 'nexifymy-security' ); ?>
						</h4>
						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
							<?php if ( ( $classification_counts['CONFIRMED_MALWARE'] ?? 0 ) > 0 ) : ?>
								<div style="padding: 10px; background: white; border-left: 3px solid #dc3545; border-radius: 3px;">
									<div style="color: #dc3545; font-weight: 600; margin-bottom: 5px;">
										<span class="dashicons dashicons-dismiss"></span> <?php _e( 'Confirmed Malware', 'nexifymy-security' ); ?>
									</div>
									<div style="font-size: 20px; font-weight: bold;">
										<?php echo intval( $classification_counts['CONFIRMED_MALWARE'] ); ?>
										<span style="font-size: 14px; color: #666;"><?php _e( 'files', 'nexifymy-security' ); ?></span>
									</div>
								</div>
							<?php endif; ?>

							<?php if ( ( $classification_counts['SUSPICIOUS_CODE'] ?? 0 ) > 0 ) : ?>
								<div style="padding: 10px; background: white; border-left: 3px solid #ff9800; border-radius: 3px;">
									<div style="color: #ff9800; font-weight: 600; margin-bottom: 5px;">
										<span class="dashicons dashicons-warning"></span> <?php _e( 'Suspicious Code', 'nexifymy-security' ); ?>
									</div>
									<div style="font-size: 20px; font-weight: bold;">
										<?php echo intval( $classification_counts['SUSPICIOUS_CODE'] ); ?>
										<span style="font-size: 14px; color: #666;"><?php _e( 'files', 'nexifymy-security' ); ?></span>
									</div>
								</div>
							<?php endif; ?>

							<?php if ( ( $classification_counts['SECURITY_VULNERABILITY'] ?? 0 ) > 0 ) : ?>
								<div style="padding: 10px; background: white; border-left: 3px solid #ffc107; border-radius: 3px;">
									<div style="color: #ffc107; font-weight: 600; margin-bottom: 5px;">
										<span class="dashicons dashicons-shield"></span> <?php _e( 'Security Vulnerabilities', 'nexifymy-security' ); ?>
									</div>
									<div style="font-size: 20px; font-weight: bold;">
										<?php echo intval( $classification_counts['SECURITY_VULNERABILITY'] ); ?>
										<span style="font-size: 14px; color: #666;"><?php _e( 'files', 'nexifymy-security' ); ?></span>
									</div>
								</div>
							<?php endif; ?>

							<?php if ( ( $classification_counts['CODE_SMELL'] ?? 0 ) > 0 ) : ?>
								<div style="padding: 10px; background: white; border-left: 3px solid #007bff; border-radius: 3px;">
									<div style="color: #007bff; font-weight: 600; margin-bottom: 5px;">
										<span class="dashicons dashicons-info"></span> <?php _e( 'Code Quality Issues', 'nexifymy-security' ); ?>
									</div>
									<div style="font-size: 20px; font-weight: bold;">
										<?php echo intval( $classification_counts['CODE_SMELL'] ); ?>
										<span style="font-size: 14px; color: #666;"><?php _e( 'files', 'nexifymy-security' ); ?></span>
									</div>
								</div>
							<?php endif; ?>
						</div>
					</div>
				<?php endif; ?>

				<div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px;">
					<div style="display: flex; align-items: start; gap: 10px;">
						<span class="dashicons dashicons-lightbulb" style="color: #ff9800; font-size: 20px; margin-top: 2px;"></span>
						<div style="flex: 1;">
							<?php echo wp_kses_post( $health_summary['recommendation'] ); ?>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render quarantine content for tab panel.
	 */
	private function render_quarantine_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$scanner_settings = isset( $settings['scanner'] ) && is_array( $settings['scanner'] ) ? $settings['scanner'] : array();
		$quarantine_mode = $scanner_settings['quarantine_mode'] ?? ( ! empty( $scanner_settings['auto_quarantine_enabled'] ) ? 'auto' : 'manual' );
		?>
		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Quarantine Policy', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description"><?php _e( 'Manual quarantine is recommended for most sites. Auto quarantine only isolates high-confidence confirmed malware.', 'nexifymy-security' ); ?></p>
				<div style="display: flex; gap: 12px; align-items: center;">
					<select id="scanner-quarantine-mode" class="regular-text" style="max-width: 260px;">
						<option value="manual" <?php selected( $quarantine_mode, 'manual' ); ?>><?php _e( 'Manual (Recommended)', 'nexifymy-security' ); ?></option>
						<option value="auto" <?php selected( $quarantine_mode, 'auto' ); ?>><?php _e( 'Auto Quarantine', 'nexifymy-security' ); ?></option>
					</select>
					<button type="button" id="save-quarantine-policy" class="nms-btn nms-btn-primary"><?php _e( 'Save Quarantine Policy', 'nexifymy-security' ); ?></button>
					<span id="quarantine-policy-status"></span>
				</div>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header" style="display: flex; justify-content: space-between; align-items: center;">
				<h3><?php _e( 'Quarantined Files', 'nexifymy-security' ); ?></h3>
				<button class="nms-btn nms-btn-secondary" id="refresh-quarantine"><?php _e( 'Refresh', 'nexifymy-security' ); ?></button>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="quarantine-table">
					<thead>
						<tr>
							<th><?php _e( 'Original Path', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Reason', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Quarantined', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="quarantine-tbody">
						<tr><td colspan="5"><?php _e( 'Loading quarantined files...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Deleted Files (Recoverable)', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="widefat striped" id="deleted-quarantine-table">
					<thead>
						<tr>
							<th><?php _e( 'Original Path', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Size', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Deleted', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Actions', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody id="deleted-quarantine-tbody">
						<tr><td colspan="4"><?php _e( 'Loading deleted files...', 'nexifymy-security' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render malware definitions content for tab panel.
	 */
	private function render_definitions_content() {
		$signature_version = get_option( 'nexifymy_signature_version', '1.0.0' );
		$last_update = get_option( 'nexifymy_signature_last_update', null );
		$signature_count = get_option( 'nexifymy_signature_count', 0 );
		?>
		<div class="nms-stats-row">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-database"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo esc_html( $signature_version ); ?></h4>
					<p><?php _e( 'Version', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-shield"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo number_format( $signature_count ); ?></h4>
					<p><?php _e( 'Signatures', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon purple"><span class="dashicons dashicons-clock"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo $last_update ? human_time_diff( strtotime( $last_update ) ) . ' ago' : __( 'Never', 'nexifymy-security' ); ?></h4>
					<p><?php _e( 'Last Updated', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Update Definitions', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<?php
				$settings = get_option( 'nexifymy_security_settings', array() );
				$auto_update = isset( $settings['signatures']['auto_update'] ) ? $settings['signatures']['auto_update'] : true;
				$next_update = wp_next_scheduled( 'nexifymy_update_signatures' );
				?>
				<table class="form-table" style="margin-bottom: 20px;">
					<tr>
						<th><?php _e( 'Auto-Update', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="auto-update-signatures" <?php checked( $auto_update ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Automatically update malware signatures daily.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th style="vertical-align: middle;"><?php _e( 'Next Update', 'nexifymy-security' ); ?></th>
						<td style="vertical-align: middle;">
							<?php if ( $next_update ) : ?>
								<span style="color: var(--nms-success);"><?php echo human_time_diff( $next_update ) . ' ' . __( 'from now', 'nexifymy-security' ); ?></span>
							<?php else : ?>
								<span style="color: var(--nms-gray-500);"><?php _e( 'Not scheduled', 'nexifymy-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<button class="nms-btn nms-btn-primary" id="update-definitions">
					<span class="dashicons dashicons-update" style="margin-right: 5px;"></span>
					<?php _e( 'Update Now', 'nexifymy-security' ); ?>
				</button>
				<span id="definition-status" style="margin-left: 15px;"></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Render AI Threat Detection content.
	 */
	private function render_ai_detection_content() {
		$ai_status = array();
		if ( isset( $GLOBALS['nexifymy_ai_detection'] ) ) {
			$ai_status = $GLOBALS['nexifymy_ai_detection']->get_status();
		}
		?>
		<!-- AI Status Overview -->
		<div class="nms-stats-row" style="margin-bottom: 24px;">
			<div class="nms-stat-card">
				<div class="nms-stat-icon blue"><span class="dashicons dashicons-superhero"></span></div>
				<div class="nms-stat-content">
					<h4><?php echo isset( $ai_status['learning_status'] ) ? ucfirst( esc_html( $ai_status['learning_status'] ) ) : 'Learning'; ?></h4>
					<p><?php _e( 'AI Status', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon green"><span class="dashicons dashicons-chart-area"></span></div>
				<div class="nms-stat-content">
					<h4 id="ai-total-records"><?php echo isset( $ai_status['total_records'] ) ? number_format( $ai_status['total_records'] ) : '0'; ?></h4>
					<p><?php _e( 'Behavior Records', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon red"><span class="dashicons dashicons-warning"></span></div>
				<div class="nms-stat-content">
					<h4 id="ai-threats-today"><?php echo isset( $ai_status['threats_today'] ) ? number_format( $ai_status['threats_today'] ) : '0'; ?></h4>
					<p><?php _e( 'Threats Today', 'nexifymy-security' ); ?></p>
				</div>
			</div>
			<div class="nms-stat-card">
				<div class="nms-stat-icon purple"><span class="dashicons dashicons-admin-site-alt3"></span></div>
				<div class="nms-stat-content">
					<h4 id="ai-countries"><?php echo isset( $ai_status['known_countries'] ) ? number_format( $ai_status['known_countries'] ) : '0'; ?></h4>
					<p><?php _e( 'Known Countries', 'nexifymy-security' ); ?></p>
				</div>
			</div>
		</div>

		<!-- AI Learning Status -->
		<div class="nms-card" style="margin-bottom: 24px;">
			<div class="nms-card-header">
				<h3><?php _e( 'AI Learning Status', 'nexifymy-security' ); ?></h3>
				<div class="nms-card-actions">
					<button class="nms-btn nms-btn-secondary" id="refresh-ai-status">
						<span class="dashicons dashicons-update"></span> <?php _e( 'Refresh', 'nexifymy-security' ); ?>
					</button>
					<button class="nms-btn nms-btn-danger" id="reset-ai-learning">
						<span class="dashicons dashicons-trash"></span> <?php _e( 'Reset Learning', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>
			<div class="nms-card-body">
				<table class="widefat">
					<tr>
						<th style="width: 30%;"><?php _e( 'Learning Period', 'nexifymy-security' ); ?></th>
						<td><?php _e( '7 days (continuous)', 'nexifymy-security' ); ?></td>
					</tr>
					<tr>
						<th><?php _e( 'Last Learned', 'nexifymy-security' ); ?></th>
						<td id="ai-last-learned"><?php echo isset( $ai_status['last_learned'] ) && $ai_status['last_learned'] ? esc_html( $ai_status['last_learned'] ) : __( 'Never', 'nexifymy-security' ); ?></td>
					</tr>
					<tr>
						<th><?php _e( 'Peak Traffic Hours', 'nexifymy-security' ); ?></th>
						<td id="ai-peak-hours">
							<?php
							if ( ! empty( $ai_status['peak_hours'] ) ) {
								foreach ( $ai_status['peak_hours'] as $hour ) {
									echo '<span class="nms-badge info" style="margin: 2px;">' . str_pad( $hour, 2, '0', STR_PAD_LEFT ) . ':00</span> ';
								}
							} else {
								_e( 'Learning...', 'nexifymy-security' );
							}
							?>
						</td>
					</tr>
				</table>
				<p class="description" style="margin-top: 15px;">
					<?php _e( 'The AI continuously learns normal behavior patterns including traffic hours, geographic locations, user agents, and request patterns. This baseline is used to detect anomalies.', 'nexifymy-security' ); ?>
				</p>
			</div>
		</div>

		<!-- Recent Threats -->
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Recent Threat Detections', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<div id="ai-threats-list">
					<p style="color: var(--nms-gray-500); text-align: center; padding: 20px;">
						<?php _e( 'Loading threat detections...', 'nexifymy-security' ); ?>
					</p>
				</div>
			</div>
		</div>

		<script>
		jQuery(document).ready(function($) {
			// Load AI threats
			function loadAIThreats() {
				$.ajax({
					url: nexifymySecurity.ajaxUrl,
					type: 'POST',
					data: {
						action: 'nexifymy_get_ai_threats',
						nonce: nexifymySecurity.nonce
					},
					success: function(response) {
						if (response && response.success && response.data) {
							displayThreats(response.data);
						}
					}
				});
			}

			function displayThreats(threats) {
				var html = '';
				if (threats && threats.length > 0) {
					html = '<table class="widefat striped">';
					html += '<thead><tr>';
					html += '<th><?php _e( 'IP Address', 'nexifymy-security' ); ?></th>';
					html += '<th><?php _e( 'Threat Score', 'nexifymy-security' ); ?></th>';
					html += '<th><?php _e( 'Anomalies', 'nexifymy-security' ); ?></th>';
					html += '<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>';
					html += '<th><?php _e( 'Time', 'nexifymy-security' ); ?></th>';
					html += '</tr></thead><tbody>';

					threats.reverse().slice(0, 20).forEach(function(threat) {
						var statusClass = threat.status === 'blocked' ? 'danger' : 'warning';
						var scoreClass = threat.score >= 90 ? 'danger' : (threat.score >= 75 ? 'warning' : 'info');
						html += '<tr>';
						html += '<td><code>' + threat.ip + '</code></td>';
						html += '<td><span class="nms-badge ' + scoreClass + '">' + threat.score + '/100</span></td>';
						html += '<td>' + (Array.isArray(threat.anomalies) ? threat.anomalies.join(', ') : threat.anomalies) + '</td>';
						html += '<td><span class="nms-badge ' + statusClass + '">' + threat.status + '</span></td>';
						html += '<td>' + (threat.blocked_at || threat.flagged_at || '') + '</td>';
						html += '</tr>';
					});

					html += '</tbody></table>';
				} else {
					html = '<p style="color: var(--nms-gray-500); text-align: center; padding: 20px;"><?php _e( 'No threats detected yet.', 'nexifymy-security' ); ?></p>';
				}
				$('#ai-threats-list').html(html);
			}

			// Refresh AI status
			$('#refresh-ai-status').on('click', function() {
				var $btn = $(this);
				$btn.prop('disabled', true);

				$.ajax({
					url: nexifymySecurity.ajaxUrl,
					type: 'POST',
					data: {
						action: 'nexifymy_get_ai_status',
						nonce: nexifymySecurity.nonce
					},
					success: function(response) {
						if (response && response.success && response.data) {
							var status = response.data;
							$('#ai-total-records').text(status.total_records.toLocaleString());
							$('#ai-threats-today').text(status.threats_today.toLocaleString());
							$('#ai-countries').text(status.known_countries.toLocaleString());
							$('#ai-last-learned').text(status.last_learned || '<?php _e( 'Never', 'nexifymy-security' ); ?>');

							var hoursHtml = '';
							if (status.peak_hours && status.peak_hours.length > 0) {
								status.peak_hours.forEach(function(hour) {
									hoursHtml += '<span class="nms-badge info" style="margin: 2px;">' + String(hour).padStart(2, '0') + ':00</span> ';
								});
							} else {
								hoursHtml = '<?php _e( 'Learning...', 'nexifymy-security' ); ?>';
							}
							$('#ai-peak-hours').html(hoursHtml);
						}
						$btn.prop('disabled', false);
					},
					error: function() {
						$btn.prop('disabled', false);
					}
				});
			});

			// Reset AI learning
			$('#reset-ai-learning').on('click', function() {
				if (!confirm('<?php _e( 'This will reset all AI learning data and behavior patterns. Continue?', 'nexifymy-security' ); ?>')) {
					return;
				}

				var $btn = $(this);
				$btn.prop('disabled', true).text('<?php _e( 'Resetting...', 'nexifymy-security' ); ?>');

				$.ajax({
					url: nexifymySecurity.ajaxUrl,
					type: 'POST',
					data: {
						action: 'nexifymy_reset_ai_learning',
						nonce: nexifymySecurity.nonce
					},
					success: function(response) {
						if (response && response.success) {
							alert('<?php _e( 'AI learning data reset successfully.', 'nexifymy-security' ); ?>');
							location.reload();
						}
						$btn.prop('disabled', false).html('<span class="dashicons dashicons-trash"></span> <?php _e( 'Reset Learning', 'nexifymy-security' ); ?>');
					},
					error: function() {
						$btn.prop('disabled', false).html('<span class="dashicons dashicons-trash"></span> <?php _e( 'Reset Learning', 'nexifymy-security' ); ?>');
					}
				});
			});

			// Initial load
			loadAIThreats();
		});
		</script>
		<?php
	}

	/**
	 * Render WAF settings content for modules page tab panel.
	 */
	private function render_waf_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$waf_settings = isset( $settings['waf'] ) ? $settings['waf'] : array();
		$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Web Application Firewall (WAF)', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'The WAF protects your site from common web attacks including SQL injection, XSS, and malicious bots.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable WAF Module', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-module-enabled" data-module="waf" <?php checked( ! empty( $modules['waf_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Enable or disable the entire WAF module.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Operation Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="waf-mode" class="regular-text">
								<option value="block" <?php selected( $waf_settings['mode'] ?? 'block', 'block' ); ?>><?php _e( 'Block Mode (Recommended)', 'nexifymy-security' ); ?></option>
								<option value="monitor" <?php selected( $waf_settings['mode'] ?? 'block', 'monitor' ); ?>><?php _e( 'Monitor Mode (Log Only)', 'nexifymy-security' ); ?></option>
								<option value="disabled" <?php selected( $waf_settings['mode'] ?? 'block', 'disabled' ); ?>><?php _e( 'Disabled', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Block Mode: Blocks malicious requests. Monitor Mode: Logs threats without blocking.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-shield-alt"></span> <?php _e( 'Attack Protection', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Block SQL Injection', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-sqli" <?php checked( ! empty( $waf_settings['block_sqli'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Protect against SQL injection attacks in GET/POST parameters.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block XSS Attacks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-xss" <?php checked( ! empty( $waf_settings['block_xss'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Protect against Cross-Site Scripting (XSS) attacks.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Local File Inclusion', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-lfi" <?php checked( ! empty( $waf_settings['block_lfi'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent attackers from including local server files.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Remote File Inclusion', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-rfi" <?php checked( ! empty( $waf_settings['block_rfi'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent inclusion of remote files via URL parameters.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Remote Code Execution', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-rce" <?php checked( ! empty( $waf_settings['block_rce'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Detect and block code execution attempts.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block CSRF Attacks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-csrf" <?php checked( ! empty( $waf_settings['block_csrf'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Protect against Cross-Site Request Forgery.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Directory Traversal', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-traversal" <?php checked( ! empty( $waf_settings['block_traversal'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Prevent access to directories outside the web root.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-rest-api"></span> <?php _e( 'Bot & User Agent Protection', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Block Bad Bots', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-bots" <?php checked( ! empty( $waf_settings['block_bad_bots'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Block known malicious bots and scrapers.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Empty User Agents', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-empty-ua" <?php checked( ! empty( $waf_settings['block_empty_ua'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Block requests without a User-Agent header.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Allowed User Agents', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="waf-allowed-ua" rows="3" class="large-text code"><?php echo esc_textarea( $waf_settings['allowed_user_agents'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One per line. User agents in this list will bypass WAF checks. Example: Googlebot, good-service-bot', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Blocked User Agents', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="waf-blocked-ua" rows="3" class="large-text code"><?php echo esc_textarea( $waf_settings['blocked_user_agents'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One per line. Block specific user agents. Example: bad-bot, scraper', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-settings"></span> <?php _e( 'Request Limits & Filtering', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Max Request Size', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="waf-max-request-size" value="<?php echo intval( $waf_settings['max_request_size'] ?? 10 ); ?>" min="1" max="100" class="small-text"> <?php _e( 'MB', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Block requests larger than this size to prevent DoS attacks.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Max Query String Length', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="waf-max-query-length" value="<?php echo intval( $waf_settings['max_query_length'] ?? 2048 ); ?>" min="256" max="10000" class="small-text"> <?php _e( 'characters', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Block excessively long query strings.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Suspicious File Uploads', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-block-uploads" <?php checked( ! empty( $waf_settings['block_suspicious_uploads'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Block uploads with executable extensions (.php, .exe, .sh, etc.).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Blocked File Extensions', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="waf-blocked-extensions" value="<?php echo esc_attr( $waf_settings['blocked_extensions'] ?? 'php,exe,sh,bat,cmd,com,pif,scr,vbs' ); ?>" class="large-text">
							<p class="description"><?php _e( 'Comma-separated list of file extensions to block in uploads.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-site-alt3"></span> <?php _e( 'IP Access Control', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Whitelisted IPs', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="waf-whitelist-ips" rows="3" class="large-text code"><?php echo esc_textarea( $waf_settings['whitelist_ips'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One IP per line. These IPs will bypass all WAF rules. Example: 192.168.1.1, 10.0.0.0/8', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Blacklisted IPs', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="waf-blacklist-ips" rows="3" class="large-text code"><?php echo esc_textarea( $waf_settings['blacklist_ips'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One IP per line. These IPs will be immediately blocked. Example: 123.45.67.89', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Block Repeated Offenders', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-auto-block" <?php checked( ! empty( $waf_settings['auto_block_repeat'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Automatically blacklist IPs that trigger rules multiple times.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Block Threshold', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="waf-block-threshold" value="<?php echo intval( $waf_settings['block_threshold'] ?? 5 ); ?>" min="1" max="50" class="small-text"> <?php _e( 'violations', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Number of rule violations before automatic blocking.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Auto-Block Duration', 'nexifymy-security' ); ?></th>
						<td>
							<select id="waf-block-duration" class="regular-text">
								<option value="3600" <?php selected( $waf_settings['block_duration'] ?? 86400, 3600 ); ?>><?php _e( '1 Hour', 'nexifymy-security' ); ?></option>
								<option value="21600" <?php selected( $waf_settings['block_duration'] ?? 86400, 21600 ); ?>><?php _e( '6 Hours', 'nexifymy-security' ); ?></option>
								<option value="86400" <?php selected( $waf_settings['block_duration'] ?? 86400, 86400 ); ?>><?php _e( '24 Hours', 'nexifymy-security' ); ?></option>
								<option value="604800" <?php selected( $waf_settings['block_duration'] ?? 86400, 604800 ); ?>><?php _e( '7 Days', 'nexifymy-security' ); ?></option>
								<option value="2592000" <?php selected( $waf_settings['block_duration'] ?? 86400, 2592000 ); ?>><?php _e( '30 Days', 'nexifymy-security' ); ?></option>
								<option value="0" <?php selected( $waf_settings['block_duration'] ?? 86400, 0 ); ?>><?php _e( 'Permanent', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-analytics"></span> <?php _e( 'Logging & Monitoring', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Log Blocked Requests', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-log-blocked" <?php checked( ! empty( $waf_settings['log_blocked'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Keep logs of all blocked requests for analysis.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Allowed Requests', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-log-allowed" <?php checked( ! empty( $waf_settings['log_allowed'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Log all requests that pass WAF checks (high disk usage).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Enable Email Alerts', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="waf-email-alerts" <?php checked( ! empty( $waf_settings['email_alerts'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Send email notifications when critical attacks are detected.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Alert Threshold', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="waf-alert-threshold" value="<?php echo intval( $waf_settings['alert_threshold'] ?? 10 ); ?>" min="1" max="100" class="small-text"> <?php _e( 'attacks per hour', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Send alert after this many attacks in one hour.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-waf-module-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save WAF Settings', 'nexifymy-security' ); ?></button>
					<span id="waf-module-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Scanner settings content for modules page tab panel.
	 */
	private function render_scanner_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$scanner_settings = isset( $settings['scanner'] ) ? $settings['scanner'] : array();
		$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		$bg_settings = isset( $settings['background_scan'] ) ? $settings['background_scan'] : array();
		$excluded_paths = $scanner_settings['excluded_paths'] ?? array();
		$excluded_paths_text = is_array( $excluded_paths ) ? implode( "\n", $excluded_paths ) : (string) $excluded_paths;
		$quarantine_mode = $scanner_settings['quarantine_mode'] ?? ( ! empty( $scanner_settings['auto_quarantine_enabled'] ) ? 'auto' : 'manual' );
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-search"></span> <?php _e( 'Scanner Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Configure malware scanner behavior and scheduled scanning options.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Scanner Module', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-module-enabled" data-module="scanner" <?php checked( ! empty( $modules['scanner_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Enable or disable the malware scanner.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-tools"></span> <?php _e( 'Scan Configuration', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Default Scan Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-default-mode" class="regular-text">
								<option value="quick" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'quick' ); ?>><?php _e( 'Quick Scan', 'nexifymy-security' ); ?></option>
								<option value="standard" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'standard' ); ?>><?php _e( 'Standard Scan', 'nexifymy-security' ); ?></option>
								<option value="deep" <?php selected( $scanner_settings['default_mode'] ?? 'standard', 'deep' ); ?>><?php _e( 'Deep Scan', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Quick: Core files only. Standard: Core + themes/plugins. Deep: All files.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Max File Size', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scanner-max-size" value="<?php echo intval( $scanner_settings['max_file_size_kb'] ?? 2048 ); ?>" min="100" max="10240" class="small-text"> <?php _e( 'KB', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Files larger than this will be skipped during scanning.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Timeout', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scanner-timeout" value="<?php echo intval( $scanner_settings['timeout'] ?? 300 ); ?>" min="60" max="3600" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Maximum time for a single scan operation.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Memory Limit', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scanner-memory" value="<?php echo intval( $scanner_settings['memory_limit'] ?? 256 ); ?>" min="128" max="1024" class="small-text"> <?php _e( 'MB', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Memory allocated for scanning operations.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Sensitivity', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-sensitivity" class="regular-text">
								<option value="low" <?php selected( $scanner_settings['sensitivity'] ?? 'medium', 'low' ); ?>><?php _e( 'Low (Less false positives)', 'nexifymy-security' ); ?></option>
								<option value="medium" <?php selected( $scanner_settings['sensitivity'] ?? 'medium', 'medium' ); ?>><?php _e( 'Medium (Balanced)', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $scanner_settings['sensitivity'] ?? 'medium', 'high' ); ?>><?php _e( 'High (Maximum detection)', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Higher sensitivity may produce more false positives.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-search"></span> <?php _e( 'Scan Targets', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Scan WordPress Core', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-scan-core" <?php checked( ! empty( $scanner_settings['scan_core'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Check core files for modifications and malware.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Themes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-scan-themes" <?php checked( ! empty( $scanner_settings['scan_themes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Scan all installed themes for malware.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Plugins', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-scan-plugins" <?php checked( ! empty( $scanner_settings['scan_plugins'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Scan all installed plugins for malware.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Uploads Directory', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-scan-uploads" <?php checked( ! empty( $scanner_settings['scan_uploads'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Check uploaded files for malicious content.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Custom Directories', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="scanner-custom-paths" rows="3" class="large-text code"><?php echo esc_textarea( $scanner_settings['custom_paths'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One path per line. Absolute paths to additional directories to scan.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-yes-alt"></span> <?php _e( 'Detection Methods', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Signature-Based Detection', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-use-signatures" <?php checked( ! empty( $scanner_settings['use_signatures'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Use malware signature database for detection.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Heuristic Analysis', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-use-heuristics" <?php checked( ! empty( $scanner_settings['use_heuristics'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Detect unknown threats using behavioral analysis.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'File Integrity Check', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-check-integrity" <?php checked( ! empty( $scanner_settings['check_integrity'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Compare core files with official WordPress checksums.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Check for Backdoors', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-check-backdoors" <?php checked( ! empty( $scanner_settings['check_backdoors'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Detect hidden backdoor scripts and shells.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Check for Obfuscation', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-check-obfuscation" <?php checked( ! empty( $scanner_settings['check_obfuscation'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Flag heavily obfuscated or encoded code.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-calendar-alt"></span> <?php _e( 'Scheduled Scans', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Enable Scheduled Scans', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-background-enabled" <?php checked( ! empty( $modules['background_scan_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Automatically run scans in the background.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Schedule', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-schedule" class="regular-text">
								<option value="hourly" <?php selected( $bg_settings['schedule'] ?? 'daily', 'hourly' ); ?>><?php _e( 'Hourly', 'nexifymy-security' ); ?></option>
								<option value="twicedaily" <?php selected( $bg_settings['schedule'] ?? 'daily', 'twicedaily' ); ?>><?php _e( 'Twice Daily', 'nexifymy-security' ); ?></option>
								<option value="daily" <?php selected( $bg_settings['schedule'] ?? 'daily', 'daily' ); ?>><?php _e( 'Daily (Recommended)', 'nexifymy-security' ); ?></option>
								<option value="weekly" <?php selected( $bg_settings['schedule'] ?? 'daily', 'weekly' ); ?>><?php _e( 'Weekly', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Quarantine Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="scanner-quarantine-mode" class="regular-text">
								<option value="manual" <?php selected( $quarantine_mode, 'manual' ); ?>><?php _e( 'Manual (Recommended)', 'nexifymy-security' ); ?></option>
								<option value="auto" <?php selected( $quarantine_mode, 'auto' ); ?>><?php _e( 'Auto Quarantine', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Manual mode is safer and recommended. Auto mode quarantines only high-confidence confirmed malware.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email Scan Reports', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="scanner-email-reports" <?php checked( ! empty( $scanner_settings['email_reports'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Send scan results via email after each scan.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-no-alt"></span> <?php _e( 'Exclusions', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Excluded Paths', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="scanner-excluded-paths" rows="3" class="large-text code"><?php echo esc_textarea( $excluded_paths_text ); ?></textarea>
							<p class="description"><?php _e( 'One path per line. Directories to skip during scans.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Excluded Extensions', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="scanner-excluded-ext" value="<?php echo esc_attr( implode( ', ', $scanner_settings['excluded_extensions'] ?? array( 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip' ) ) ); ?>" class="large-text">
							<p class="description"><?php _e( 'Comma-separated list of file extensions to skip (e.g., jpg, png, pdf).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Excluded File Patterns', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="scanner-excluded-patterns" rows="3" class="large-text code"><?php echo esc_textarea( $scanner_settings['excluded_patterns'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One pattern per line. Regex patterns for files to exclude (e.g., .*\.min\.js).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-scanner-module-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Scanner Settings', 'nexifymy-security' ); ?></button>
					<span id="scanner-module-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render firewall rules content for tab panel.
	 */
	private function render_firewall_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$waf_settings = isset( $settings['waf'] ) ? $settings['waf'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Web Application Firewall', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable WAF', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="waf-enabled" <?php checked( ! empty( $waf_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Protection Level', 'nexifymy-security' ); ?></th>
						<td>
							<select id="waf-level">
								<option value="low" <?php selected( $waf_settings['level'] ?? 'medium', 'low' ); ?>><?php _e( 'Low', 'nexifymy-security' ); ?></option>
								<option value="medium" <?php selected( $waf_settings['level'] ?? 'medium', 'medium' ); ?>><?php _e( 'Medium', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $waf_settings['level'] ?? 'medium', 'high' ); ?>><?php _e( 'High', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-waf-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="waf-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render login protection content for tab panel.
	 */
	private function render_login_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$login_settings = isset( $settings['login_protection'] ) ? $settings['login_protection'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Login Protection', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Protection', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="login-enabled" <?php checked( ! empty( $login_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Max Attempts', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="login-max-attempts" value="<?php echo intval( $login_settings['max_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'Lockout Duration', 'nexifymy-security' ); ?></th>
						<td><input type="number" id="login-lockout" value="<?php echo intval( $login_settings['lockout_duration'] ?? 30 ); ?>" min="5" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-login-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="login-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render geo blocking content for tab panel.
	 */
	private function render_geo_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$geo_settings = isset( $settings['geo_blocking'] ) ? $settings['geo_blocking'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Geo Blocking', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Geo Blocking', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="geo-enabled" <?php checked( ! empty( $geo_settings['enabled'] ) ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Block Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="geo-mode">
								<option value="blacklist" <?php selected( $geo_settings['mode'] ?? 'blacklist', 'blacklist' ); ?>><?php _e( 'Blacklist (Block Listed)', 'nexifymy-security' ); ?></option>
								<option value="whitelist" <?php selected( $geo_settings['mode'] ?? 'blacklist', 'whitelist' ); ?>><?php _e( 'Whitelist (Allow Only)', 'nexifymy-security' ); ?></option>
							</select>
							<p class="description"><?php _e( 'Blacklist: Block selected countries. Whitelist: Allow only selected countries.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Available Countries', 'nexifymy-security' ); ?></th>
						<td>
							<div style="display: flex; gap: 20px;">
								<!-- Available Countries Checkboxes -->
								<div style="flex: 1; max-height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px;">
									<p style="margin-top: 0; font-weight: 600;"><?php _e( 'Select Countries:', 'nexifymy-security' ); ?></p>
									<?php
									$selected = $geo_settings['countries'] ?? array();
									$countries = array(
										'US' => 'United States', 'CN' => 'China', 'RU' => 'Russia', 'IN' => 'India', 'BR' => 'Brazil',
										'GB' => 'United Kingdom', 'FR' => 'France', 'DE' => 'Germany', 'JP' => 'Japan', 'CA' => 'Canada',
										'AU' => 'Australia', 'IT' => 'Italy', 'ES' => 'Spain', 'MX' => 'Mexico', 'KR' => 'South Korea',
										'NL' => 'Netherlands', 'TR' => 'Turkey', 'SA' => 'Saudi Arabia', 'CH' => 'Switzerland', 'PL' => 'Poland',
										'BE' => 'Belgium', 'SE' => 'Sweden', 'NO' => 'Norway', 'AT' => 'Austria', 'DK' => 'Denmark',
										'FI' => 'Finland', 'SG' => 'Singapore', 'MY' => 'Malaysia', 'TH' => 'Thailand', 'PH' => 'Philippines',
										'VN' => 'Vietnam', 'PK' => 'Pakistan', 'BD' => 'Bangladesh', 'NG' => 'Nigeria', 'EG' => 'Egypt',
										'ZA' => 'South Africa', 'AR' => 'Argentina', 'CO' => 'Colombia', 'CL' => 'Chile', 'PE' => 'Peru',
										'ID' => 'Indonesia', 'IR' => 'Iran', 'IQ' => 'Iraq', 'IL' => 'Israel', 'AE' => 'UAE',
										'UA' => 'Ukraine', 'RO' => 'Romania', 'GR' => 'Greece', 'CZ' => 'Czech Republic', 'PT' => 'Portugal',
									);
									asort( $countries );
									foreach ( $countries as $code => $name ) {
										if ( ! in_array( $code, $selected, true ) ) {
											printf(
												'<label style="display: block; margin-bottom: 5px;"><input type="checkbox" class="geo-country-check" value="%s"> %s (%s)</label>',
												esc_attr( $code ),
												esc_html( $name ),
												esc_html( $code )
											);
										}
									}
									?>
								</div>

								<!-- Add/Remove Buttons -->
								<div style="display: flex; flex-direction: column; justify-content: center; gap: 10px;">
									<button type="button" id="geo-add-countries" class="nms-btn nms-btn-primary" style="white-space: nowrap;">
										<span class="dashicons dashicons-arrow-right-alt2"></span> <?php _e( 'Add to List', 'nexifymy-security' ); ?>
									</button>
									<button type="button" id="geo-remove-countries" class="nms-btn nms-btn-secondary" style="white-space: nowrap;">
										<span class="dashicons dashicons-arrow-left-alt2"></span> <?php _e( 'Remove', 'nexifymy-security' ); ?>
									</button>
								</div>

								<!-- Selected Countries List -->
								<div style="flex: 1; max-height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px; background: #f9f9f9;">
									<p style="margin-top: 0; font-weight: 600;"><?php _e( 'Selected Countries:', 'nexifymy-security' ); ?></p>
									<div id="geo-selected-list">
										<?php
										foreach ( $selected as $code ) {
											if ( isset( $countries[ $code ] ) ) {
												printf(
													'<label style="display: block; margin-bottom: 5px;"><input type="checkbox" class="geo-selected-check" value="%s"> %s (%s)</label>',
													esc_attr( $code ),
													esc_html( $countries[ $code ] ),
													esc_html( $code )
												);
											}
										}
										if ( empty( $selected ) ) {
											echo '<p class="description" style="margin: 0;">' . __( 'No countries selected yet.', 'nexifymy-security' ) . '</p>';
										}
										?>
									</div>
								</div>
							</div>
							<p class="description" style="margin-top: 10px;"><?php _e( 'Select countries from left, click "Add to List" to add them. Selected countries will be blocked (Blacklist) or allowed (Whitelist) based on mode above.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-geo-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="geo-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render rate limiter content for tab panel.
	 */
	private function render_rate_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$rate_settings = isset( $settings['rate_limiter'] ) ? $settings['rate_limiter'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><span class="dashicons dashicons-clock"></span> <?php _e( 'Rate Limiting', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Protect against brute force and DoS attacks by limiting request frequency per IP address.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Rate Limiting', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="rate-enabled" data-module="rate_limiter" <?php checked( ! empty( $rate_settings['enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Enable or disable the rate limiting module.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-lock"></span> <?php _e( 'Login Protection', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Max Login Attempts', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-login-attempts" value="<?php echo intval( $rate_settings['max_login_attempts'] ?? 5 ); ?>" min="1" max="20" class="small-text"> <?php _e( 'attempts', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Maximum failed login attempts before lockout.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Login Attempt Window', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-login-window" value="<?php echo intval( $rate_settings['login_window'] ?? 15 ); ?>" min="1" max="60" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Time window for counting failed login attempts.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Login Lockout Duration', 'nexifymy-security' ); ?></th>
						<td>
							<select id="rate-login-lockout" class="regular-text">
								<option value="300" <?php selected( $rate_settings['login_lockout'] ?? 1800, 300 ); ?>><?php _e( '5 Minutes', 'nexifymy-security' ); ?></option>
								<option value="900" <?php selected( $rate_settings['login_lockout'] ?? 1800, 900 ); ?>><?php _e( '15 Minutes', 'nexifymy-security' ); ?></option>
								<option value="1800" <?php selected( $rate_settings['login_lockout'] ?? 1800, 1800 ); ?>><?php _e( '30 Minutes', 'nexifymy-security' ); ?></option>
								<option value="3600" <?php selected( $rate_settings['login_lockout'] ?? 1800, 3600 ); ?>><?php _e( '1 Hour', 'nexifymy-security' ); ?></option>
								<option value="86400" <?php selected( $rate_settings['login_lockout'] ?? 1800, 86400 ); ?>><?php _e( '24 Hours', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Notify on Lockout', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="rate-login-notify" <?php checked( ! empty( $rate_settings['login_notify'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Send email notification when an IP is locked out.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-rest-api"></span> <?php _e( 'API Rate Limiting', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'API Requests per Minute', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-api-requests" value="<?php echo intval( $rate_settings['api_requests_per_minute'] ?? 60 ); ?>" min="10" max="500" class="small-text">
							<p class="description"><?php _e( 'Maximum API requests per minute per IP.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'API Burst Allowance', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-api-burst" value="<?php echo intval( $rate_settings['api_burst'] ?? 10 ); ?>" min="5" max="100" class="small-text">
							<p class="description"><?php _e( 'Allow short bursts above the rate limit.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Block Excessive API Users', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="rate-api-block" <?php checked( ! empty( $rate_settings['api_block'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Temporarily block IPs that exceed API rate limits.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-links"></span> <?php _e( 'General Request Limiting', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Page Requests per Minute', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-page-requests" value="<?php echo intval( $rate_settings['page_requests_per_minute'] ?? 120 ); ?>" min="10" max="1000" class="small-text">
							<p class="description"><?php _e( 'Maximum page requests per minute per IP.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'AJAX Requests per Minute', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-ajax-requests" value="<?php echo intval( $rate_settings['ajax_requests_per_minute'] ?? 200 ); ?>" min="10" max="1000" class="small-text">
							<p class="description"><?php _e( 'Maximum AJAX requests per minute per IP.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Search Requests per Minute', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-search-requests" value="<?php echo intval( $rate_settings['search_requests_per_minute'] ?? 10 ); ?>" min="1" max="100" class="small-text">
							<p class="description"><?php _e( 'Maximum search requests per minute to prevent database exhaustion.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Comment Posting Rate', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-comment-requests" value="<?php echo intval( $rate_settings['comment_requests_per_minute'] ?? 5 ); ?>" min="1" max="50" class="small-text"> <?php _e( 'per minute', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Limit comment submissions to prevent spam.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'Advanced Options', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Block Duration', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="rate-duration" value="<?php echo intval( $rate_settings['block_duration'] ?? 300 ); ?>" min="60" max="86400" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'How long to block an IP after rate limit exceeded.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Whitelisted IPs', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="rate-whitelist" rows="3" class="large-text code"><?php echo esc_textarea( $rate_settings['whitelist_ips'] ?? '' ); ?></textarea>
							<p class="description"><?php _e( 'One IP per line. These IPs bypass all rate limits.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Trust Proxy Headers', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="rate-trust-proxy" <?php checked( ! empty( $rate_settings['trust_proxy'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Use X-Forwarded-For header for IP detection (only if behind CDN/proxy).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Rate Limit Violations', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="rate-log-violations" <?php checked( ! empty( $rate_settings['log_violations'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Keep logs of all rate limit violations for analysis.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Response Code on Block', 'nexifymy-security' ); ?></th>
						<td>
							<select id="rate-response-code" class="regular-text">
								<option value="403" <?php selected( $rate_settings['response_code'] ?? 429, 403 ); ?>><?php _e( '403 Forbidden', 'nexifymy-security' ); ?></option>
								<option value="429" <?php selected( $rate_settings['response_code'] ?? 429, 429 ); ?>><?php _e( '429 Too Many Requests (Recommended)', 'nexifymy-security' ); ?></option>
								<option value="503" <?php selected( $rate_settings['response_code'] ?? 429, 503 ); ?>><?php _e( '503 Service Unavailable', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-rate-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<span id="rate-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Notifications page (standalone).
	 */
	public function render_notifications_page() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-bell"></span> <?php _e( 'Notifications', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'View and manage security alerts and notifications.', 'nexifymy-security' ); ?></p>
			</div>
			<?php $this->render_notifications_content(); ?>
		</div>
		<?php
	}

	/**
	 * Render email settings content for Settings page.
	 */
	private function render_email_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$email = isset( $settings['email_alerts'] ) ? $settings['email_alerts'] : array();
		$defaults = array(
			'enabled'          => false,
			'recipient'        => get_option( 'admin_email' ),
			'from_name'        => get_bloginfo( 'name' ),
			'from_email'       => 'security@' . parse_url( home_url(), PHP_URL_HOST ),
			'alert_threats'    => true,
			'alert_lockouts'   => true,
			'alert_waf'        => false,
			'alert_login'      => false,
			'daily_summary'    => false,
			'weekly_report'    => true,
			'throttle_minutes' => 60,
		);
		$email = wp_parse_args( $email, $defaults );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Email Alert Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Email Alerts', 'nexifymy-security' ); ?></th>
						<td><label class="nms-toggle"><input type="checkbox" id="email-enabled" <?php checked( $email['enabled'] ); ?>><span class="nms-toggle-slider"></span></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Recipient Email', 'nexifymy-security' ); ?></th>
						<td>
							<input type="email" id="email-recipient" value="<?php echo esc_attr( $email['recipient'] ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Primary email address for security alerts.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'From Name', 'nexifymy-security' ); ?></th>
						<td><input type="text" id="email-from-name" value="<?php echo esc_attr( $email['from_name'] ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th><?php _e( 'From Email', 'nexifymy-security' ); ?></th>
						<td><input type="email" id="email-from-email" value="<?php echo esc_attr( $email['from_email'] ); ?>" class="regular-text"></td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Alert Types', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Security Alerts', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" id="alert-threats" <?php checked( $email['alert_threats'] ); ?>> <?php _e( 'Threat Detected (malware, suspicious files)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-lockouts" <?php checked( $email['alert_lockouts'] ); ?>> <?php _e( 'IP Lockouts (brute force attempts)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-waf" <?php checked( $email['alert_waf'] ); ?>> <?php _e( 'WAF Blocks (attacked blocked by firewall)', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="alert-login" <?php checked( $email['alert_login'] ); ?>> <?php _e( 'Admin Logins (successful admin logins)', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Periodic Reports', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" id="daily-summary" <?php checked( $email['daily_summary'] ); ?>> <?php _e( 'Daily Status Summary', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" id="weekly-report" <?php checked( $email['weekly_report'] ); ?>> <?php _e( 'Weekly Security Report', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Throttle Period', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="throttle-minutes" value="<?php echo intval( $email['throttle_minutes'] ); ?>" min="0" max="1440" class="small-text"> <?php _e( 'minutes', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Prevent duplicate alerts within this time period. Set to 0 to disable throttling.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-email-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Email Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-email" class="nms-btn nms-btn-secondary"><?php _e( 'Send Test Email', 'nexifymy-security' ); ?></button>
					<span id="email-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render import/export content for Settings page.
	 */
	private function render_import_export_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Export Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Export your NexifyMy Security settings to a JSON file. This includes all module configurations, firewall rules, IP lists, and scan settings.', 'nexifymy-security' ); ?></p>
				<p>
					<label><input type="checkbox" id="export-logs" checked> <?php _e( 'Include security logs (last 30 days)', 'nexifymy-security' ); ?></label><br>
					<label><input type="checkbox" id="export-ip-lists" checked> <?php _e( 'Include IP whitelist/blacklist', 'nexifymy-security' ); ?></label><br>
					<label><input type="checkbox" id="export-scan-results" checked> <?php _e( 'Include last scan results', 'nexifymy-security' ); ?></label>
				</p>
				<p class="submit">
					<button type="button" id="export-settings" class="nms-btn nms-btn-primary"><span class="dashicons dashicons-download"></span> <?php _e( 'Export Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Import Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Import settings from a previously exported JSON file. This will overwrite your current settings.', 'nexifymy-security' ); ?></p>
				<p class="warning" style="color: #d63638; background: #fcf0f1; padding: 10px; border-radius: 4px;">
					<span class="dashicons dashicons-warning"></span>
					<?php _e( 'Warning: Importing will replace all current settings. Make sure to export your current settings first as a backup.', 'nexifymy-security' ); ?>
				</p>
				<input type="file" id="import-file" accept=".json" style="margin: 10px 0;">
				<p class="submit">
					<button type="button" id="import-settings" class="nms-btn nms-btn-secondary"><span class="dashicons dashicons-upload"></span> <?php _e( 'Import Settings', 'nexifymy-security' ); ?></button>
					<span id="import-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Reset to Defaults', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<p><?php _e( 'Reset all NexifyMy Security settings to their default values. This action cannot be undone.', 'nexifymy-security' ); ?></p>
				<p class="submit">
					<button type="button" id="reset-settings" class="nms-btn" style="background: #d63638; color: white;"><span class="dashicons dashicons-trash"></span> <?php _e( 'Reset All Settings', 'nexifymy-security' ); ?></button>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render advanced settings content for Settings page.
	 */
	private function render_advanced_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$advanced = isset( $settings['advanced'] ) ? $settings['advanced'] : array();
		$defaults = array(
			'delete_on_uninstall' => false,
			'debug_mode'          => false,
			'disable_xmlrpc'      => true,
			'disable_rest_users'  => true,
			'hide_wp_version'     => true,
			'disable_file_editor' => true,
			'block_author_scans'  => true,
			'block_bad_requests'  => true,
			'block_empty_ua'      => false,
			'performance_mode'    => 'balanced',
			'scan_timeout'        => 300,
			'request_size_limit'  => 10240,
		);
		$advanced = wp_parse_args( $advanced, $defaults );
		?>
		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Security Hardening', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'XML-RPC', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-xmlrpc" <?php checked( $advanced['disable_xmlrpc'] ); ?>> <?php _e( 'Disable XML-RPC (prevents pingback attacks)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'REST API Users', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-rest-users" <?php checked( $advanced['disable_rest_users'] ); ?>> <?php _e( 'Disable public user enumeration via REST API', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'WP Version', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="hide-wp-version" <?php checked( $advanced['hide_wp_version'] ); ?>> <?php _e( 'Hide WordPress version from source code', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'File Editor', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="disable-file-editor" <?php checked( $advanced['disable_file_editor'] ); ?>> <?php _e( 'Disable theme and plugin editor', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Author Scans', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-author-scans" <?php checked( $advanced['block_author_scans'] ); ?>> <?php _e( 'Block author enumeration scans (?author=1)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Bad Requests', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-bad-requests" <?php checked( $advanced['block_bad_requests'] ); ?>> <?php _e( 'Block malformed requests and suspicious query strings', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Empty User Agent', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="block-empty-ua" <?php checked( $advanced['block_empty_ua'] ); ?>> <?php _e( 'Block requests with empty user-agent (may block some legitimate bots)', 'nexifymy-security' ); ?></label></td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Performance Settings', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Performance Mode', 'nexifymy-security' ); ?></th>
						<td>
							<select id="performance-mode">
								<option value="low" <?php selected( $advanced['performance_mode'], 'low' ); ?>><?php _e( 'Low Impact (fewer checks, faster)', 'nexifymy-security' ); ?></option>
								<option value="balanced" <?php selected( $advanced['performance_mode'], 'balanced' ); ?>><?php _e( 'Balanced (recommended)', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $advanced['performance_mode'], 'high' ); ?>><?php _e( 'High Security (more checks, slower)', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Scan Timeout', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="scan-timeout" value="<?php echo intval( $advanced['scan_timeout'] ); ?>" min="60" max="3600" class="small-text"> <?php _e( 'seconds', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Maximum time for malware scans before timeout.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Request Size Limit', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="request-size-limit" value="<?php echo intval( $advanced['request_size_limit'] ); ?>" min="1024" max="102400" class="small-text"> KB
							<p class="description"><?php _e( 'Maximum request body size to scan. Larger requests will be skipped.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="nms-card">
			<div class="nms-card-header"><h3><?php _e( 'Plugin Options', 'nexifymy-security' ); ?></h3></div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Debug Mode', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="debug-mode" <?php checked( $advanced['debug_mode'] ); ?>> <?php _e( 'Enable debug logging (for troubleshooting only)', 'nexifymy-security' ); ?></label></td>
					</tr>
					<tr>
						<th><?php _e( 'Uninstall Behavior', 'nexifymy-security' ); ?></th>
						<td><label><input type="checkbox" id="delete-on-uninstall" <?php checked( $advanced['delete_on_uninstall'] ); ?>> <?php _e( 'Delete all plugin data when uninstalling', 'nexifymy-security' ); ?></label></td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-advanced-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Advanced Settings', 'nexifymy-security' ); ?></button>
					<span id="advanced-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}
	/**
	 * Render the Analytics tab content.
	 */
	public function render_analytics_tab() {
		$data = array();
		if ( isset( $GLOBALS['nexifymy_analytics'] ) ) {
			$data = $GLOBALS['nexifymy_analytics']->get_chart_data( 7 );
		}

		// Fallback data if module not loaded or empty
		if ( empty( $data['labels'] ) ) {
			$data = array(
				'labels' => array( 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ),
				'datasets' => array(
					'threats' => array( 0, 0, 0, 1, 0, 2, 0 ),
					'blocked' => array( 5, 8, 12, 7, 9, 15, 10 ),
					'logins'  => array( 2, 1, 0, 3, 1, 0, 1 ),
				)
			);
		}
		?>
			<h1 class="wp-heading-inline screen-reader-text"><?php _e( 'Security Analytics', 'nexifymy-security' ); ?></h1>
			<hr class="wp-header-end">
			<div class="nexifymy-header">
				<h2><span class="dashicons dashicons-chart-bar"></span> <?php _e( 'Security Analytics', 'nexifymy-security' ); ?></h2>
				<p class="description"><?php _e( 'Detailed insights into your website security performance.', 'nexifymy-security' ); ?></p>
			</div>

		<div class="nms-card">
			<div class="nms-card-header">
				<h3><?php _e( 'Threat Detection & Blocking - Last 7 Days', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<canvas id="nms-threats-chart" width="400" height="150"></canvas>
			</div>
		</div>

		<div class="nms-grid-2">
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Login Attempts', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<canvas id="nms-logins-chart" width="400" height="200"></canvas>
				</div>
			</div>
			
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Top Detection Reasons', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<ul class="nms-list-stats">
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-shield"></span> <?php _e( 'SQL Injection', 'nexifymy-security' ); ?></span>
							<span class="nms-badge warning">12 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-code-standards"></span> <?php _e( 'XSS Attack', 'nexifymy-security' ); ?></span>
							<span class="nms-badge warning">5 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-admin-network"></span> <?php _e( 'Brute Force', 'nexifymy-security' ); ?></span>
							<span class="nms-badge danger">42 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
						<li>
							<span class="nms-stat-label"><span class="dashicons dashicons-hidden"></span> <?php _e( 'Directory Traversal', 'nexifymy-security' ); ?></span>
							<span class="nms-badge info">3 <?php _e( 'blocked', 'nexifymy-security' ); ?></span>
						</li>
					</ul>
				</div>
			</div>
		</div>

		<script>
		document.addEventListener('DOMContentLoaded', function() {
			if (typeof Chart === 'undefined') return;
			
			const ctxThreats = document.getElementById('nms-threats-chart').getContext('2d');
			new Chart(ctxThreats, {
				type: 'line',
				data: {
					labels: <?php echo json_encode( $data['labels'] ); ?>,
					datasets: [{
						label: 'Threats Blocked',
						data: <?php echo json_encode( $data['datasets']['blocked'] ); ?>,
						borderColor: '#4f46e5',
						backgroundColor: 'rgba(79, 70, 229, 0.1)',
						borderWidth: 2,
						tension: 0.4,
						fill: true,
						pointBackgroundColor: '#ffffff',
						pointBorderColor: '#4f46e5',
						pointRadius: 4
					}, {
						label: 'Malware Detected',
						data: <?php echo json_encode( $data['datasets']['threats'] ); ?>,
						borderColor: '#dc2626',
						backgroundColor: 'rgba(220, 38, 38, 0.05)',
						borderWidth: 2,
						tension: 0.4,
						fill: false,
						borderDash: [5, 5]
					}]
				},
				options: {
					responsive: true,
					plugins: {
						legend: { position: 'top' },
						tooltip: {
							mode: 'index',
							intersect: false,
							backgroundColor: 'rgba(255, 255, 255, 0.9)',
							titleColor: '#1e293b',
							bodyColor: '#64748b',
							borderColor: '#e2e8f0',
							borderWidth: 1
						}
					},
					scales: {
						y: { beginAtZero: true, grid: { borderDash: [2, 2] } },
						x: { grid: { display: false } }
					}
				}
			});

			const ctxLogins = document.getElementById('nms-logins-chart').getContext('2d');
			new Chart(ctxLogins, {
				type: 'bar',
				data: {
					labels: <?php echo json_encode( $data['labels'] ); ?>,
					datasets: [{
						label: 'Failed Logins',
						data: <?php echo json_encode( $data['datasets']['logins'] ); ?>,
						backgroundColor: '#f59e0b',
						borderRadius: 4
					}]
				},
				options: {
					responsive: true,
					plugins: { legend: { display: false } },
					scales: {
						y: { beginAtZero: true }
					}
				}
			});
		});
		</script>
		<?php
	}



	/**
	 * Render the Integrations page.
	 */
	public function render_integrations_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		$settings = get_option( 'nexifymy_security_settings', array() );
		$integrations = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-admin-plugins"></span> <?php _e( 'Integrations', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Connect your security monitoring to SIEM, ticketing, communication, and CI/CD platforms.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-screenoptions"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'siem' ? 'active' : ''; ?>" data-tab="siem">
					<span class="dashicons dashicons-database"></span> <?php _e( 'SIEM', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'ticketing' ? 'active' : ''; ?>" data-tab="ticketing">
					<span class="dashicons dashicons-tickets-alt"></span> <?php _e( 'Ticketing', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'communication' ? 'active' : ''; ?>" data-tab="communication">
					<span class="dashicons dashicons-email"></span> <?php _e( 'Communication', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'cicd' ? 'active' : ''; ?>" data-tab="cicd">
					<span class="dashicons dashicons-admin-tools"></span> <?php _e( 'CI/CD', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'webhooks' ? 'active' : ''; ?>" data-tab="webhooks">
					<span class="dashicons dashicons-rest-api"></span> <?php _e( 'Webhooks', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<!-- Overview Tab -->
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block' : 'none'; ?>;">
					<?php $this->render_integrations_overview(); ?>
				</div>

				<!-- SIEM Tab -->
				<div id="tab-siem" class="nms-tab-panel <?php echo $active_tab === 'siem' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'siem' ? 'block' : 'none'; ?>;">
					<?php $this->render_siem_integration(); ?>
				</div>

				<!-- Ticketing Tab -->
				<div id="tab-ticketing" class="nms-tab-panel <?php echo $active_tab === 'ticketing' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'ticketing' ? 'block' : 'none'; ?>;">
					<?php $this->render_ticketing_integration(); ?>
				</div>

				<!-- Communication Tab -->
				<div id="tab-communication" class="nms-tab-panel <?php echo $active_tab === 'communication' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'communication' ? 'block' : 'none'; ?>;">
					<?php $this->render_communication_integration(); ?>
				</div>

				<!-- CI/CD Tab -->
				<div id="tab-cicd" class="nms-tab-panel <?php echo $active_tab === 'cicd' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'cicd' ? 'block' : 'none'; ?>;">
					<?php $this->render_cicd_integration(); ?>
				</div>

				<!-- Webhooks Tab -->
				<div id="tab-webhooks" class="nms-tab-panel <?php echo $active_tab === 'webhooks' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'webhooks' ? 'block' : 'none'; ?>;">
					<?php $this->render_webhooks_integration(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render integrations overview.
	 */
	private function render_integrations_overview() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$integrations = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		?>
		<div class="nms-integration-grid">
			<!-- SIEM Card -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-database"></span> <?php _e( 'SIEM Integration', 'nexifymy-security' ); ?></h3>
					<span class="nms-badge <?php echo ! empty( $integrations['siem_enabled'] ) ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
						<?php echo ! empty( $integrations['siem_enabled'] ) ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
					</span>
				</div>
				<div class="nms-card-body">
					<p><?php _e( 'Send security events to Splunk, Elasticsearch, or other SIEM platforms for centralized monitoring and analysis.', 'nexifymy-security' ); ?></p>
					<p><strong><?php _e( 'Supported:', 'nexifymy-security' ); ?></strong> Splunk, Elasticsearch, Generic HTTP</p>
					<a href="?page=nexifymy-security-integrations&tab=siem" class="nms-btn nms-btn-primary"><?php _e( 'Configure', 'nexifymy-security' ); ?></a>
				</div>
			</div>

			<!-- Ticketing Card -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-tickets-alt"></span> <?php _e( 'Ticketing Systems', 'nexifymy-security' ); ?></h3>
					<span class="nms-badge <?php echo ! empty( $integrations['jira_enabled'] ) || ! empty( $integrations['servicenow_enabled'] ) ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
						<?php echo ! empty( $integrations['jira_enabled'] ) || ! empty( $integrations['servicenow_enabled'] ) ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
					</span>
				</div>
				<div class="nms-card-body">
					<p><?php _e( 'Automatically create tickets for security incidents in your project management systems.', 'nexifymy-security' ); ?></p>
					<p><strong><?php _e( 'Supported:', 'nexifymy-security' ); ?></strong> Jira, ServiceNow</p>
					<a href="?page=nexifymy-security-integrations&tab=ticketing" class="nms-btn nms-btn-primary"><?php _e( 'Configure', 'nexifymy-security' ); ?></a>
				</div>
			</div>

			<!-- Communication Card -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-email"></span> <?php _e( 'Communication Platforms', 'nexifymy-security' ); ?></h3>
					<span class="nms-badge <?php echo ! empty( $integrations['slack_enabled'] ) || ! empty( $integrations['discord_enabled'] ) || ! empty( $integrations['teams_enabled'] ) ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
						<?php echo ! empty( $integrations['slack_enabled'] ) || ! empty( $integrations['discord_enabled'] ) || ! empty( $integrations['teams_enabled'] ) ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
					</span>
				</div>
				<div class="nms-card-body">
					<p><?php _e( 'Get instant notifications in your team communication channels when security events occur.', 'nexifymy-security' ); ?></p>
					<p><strong><?php _e( 'Supported:', 'nexifymy-security' ); ?></strong> Slack, Discord, Microsoft Teams</p>
					<a href="?page=nexifymy-security-integrations&tab=communication" class="nms-btn nms-btn-primary"><?php _e( 'Configure', 'nexifymy-security' ); ?></a>
				</div>
			</div>

			<!-- CI/CD Card -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-admin-tools"></span> <?php _e( 'CI/CD Pipeline', 'nexifymy-security' ); ?></h3>
					<span class="nms-badge <?php echo ! empty( $integrations['cicd_enabled'] ) ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
						<?php echo ! empty( $integrations['cicd_enabled'] ) ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
					</span>
				</div>
				<div class="nms-card-body">
					<p><?php _e( 'Integrate security scanning into your deployment pipeline with webhooks and API access.', 'nexifymy-security' ); ?></p>
					<p><strong><?php _e( 'Supported:', 'nexifymy-security' ); ?></strong> GitHub Actions, GitLab CI, Jenkins, CircleCI, Travis CI</p>
					<a href="?page=nexifymy-security-integrations&tab=cicd" class="nms-btn nms-btn-primary"><?php _e( 'Configure', 'nexifymy-security' ); ?></a>
				</div>
			</div>

			<!-- Webhooks Card -->
			<div class="nms-card">
				<div class="nms-card-header">
					<h3><span class="dashicons dashicons-rest-api"></span> <?php _e( 'Custom Webhooks', 'nexifymy-security' ); ?></h3>
					<span class="nms-badge <?php echo ! empty( $integrations['custom_webhooks_enabled'] ) ? 'nms-badge-success' : 'nms-badge-secondary'; ?>">
						<?php echo ! empty( $integrations['custom_webhooks_enabled'] ) ? __( 'Active', 'nexifymy-security' ) : __( 'Inactive', 'nexifymy-security' ); ?>
					</span>
				</div>
				<div class="nms-card-body">
					<p><?php _e( 'Send security events to any HTTP endpoint with custom headers and authentication.', 'nexifymy-security' ); ?></p>
					<p><strong><?php _e( 'Format:', 'nexifymy-security' ); ?></strong> JSON POST requests</p>
					<a href="?page=nexifymy-security-integrations&tab=webhooks" class="nms-btn nms-btn-primary"><?php _e( 'Configure', 'nexifymy-security' ); ?></a>
				</div>
			</div>
		</div>

		<div class="nms-card" style="margin-top: 20px;">
			<div class="nms-card-header">
				<h3><?php _e( 'Available Events', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th><?php _e( 'Event', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Description', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Severity', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><code>threat_detected</code></td>
							<td><?php _e( 'High-scoring threat detected by AI analysis', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-danger"><?php _e( 'Critical', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>malware_found</code></td>
							<td><?php _e( 'Malware detected during file scanning', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-danger"><?php _e( 'Critical', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>plugin_vulnerability</code></td>
							<td><?php _e( 'Known vulnerability found in installed plugin', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-warning"><?php _e( 'High', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>user_locked</code></td>
							<td><?php _e( 'User or IP address locked out due to suspicious activity', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-warning"><?php _e( 'High', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>login_failed</code></td>
							<td><?php _e( 'Failed login attempt detected', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-info"><?php _e( 'Medium', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>core_file_modified</code></td>
							<td><?php _e( 'WordPress core file has been modified', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-warning"><?php _e( 'High', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>scan_completed</code></td>
							<td><?php _e( 'Security scan has finished execution', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-success"><?php _e( 'Info', 'nexifymy-security' ); ?></span></td>
						</tr>
						<tr>
							<td><code>settings_changed</code></td>
							<td><?php _e( 'Security settings have been modified', 'nexifymy-security' ); ?></td>
							<td><span class="nms-badge nms-badge-info"><?php _e( 'Medium', 'nexifymy-security' ); ?></span></td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render SIEM integration settings.
	 */
	private function render_siem_integration() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$siem = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-database"></span> <?php _e( 'SIEM Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Forward security events to your Security Information and Event Management (SIEM) platform for centralized logging and analysis.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable SIEM Integration', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="siem-enabled" <?php checked( ! empty( $siem['siem_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'SIEM Platform', 'nexifymy-security' ); ?></th>
						<td>
							<select id="siem-type" class="regular-text">
								<option value="splunk" <?php selected( $siem['siem_type'] ?? 'splunk', 'splunk' ); ?>><?php _e( 'Splunk (HTTP Event Collector)', 'nexifymy-security' ); ?></option>
								<option value="elasticsearch" <?php selected( $siem['siem_type'] ?? 'splunk', 'elasticsearch' ); ?>><?php _e( 'Elasticsearch', 'nexifymy-security' ); ?></option>
								<option value="qradar" <?php selected( $siem['siem_type'] ?? 'splunk', 'qradar' ); ?>><?php _e( 'IBM QRadar', 'nexifymy-security' ); ?></option>
								<option value="arcsight" <?php selected( $siem['siem_type'] ?? 'splunk', 'arcsight' ); ?>><?php _e( 'ArcSight', 'nexifymy-security' ); ?></option>
								<option value="sumo" <?php selected( $siem['siem_type'] ?? 'splunk', 'sumo' ); ?>><?php _e( 'Sumo Logic', 'nexifymy-security' ); ?></option>
								<option value="datadog" <?php selected( $siem['siem_type'] ?? 'splunk', 'datadog' ); ?>><?php _e( 'Datadog', 'nexifymy-security' ); ?></option>
								<option value="generic" <?php selected( $siem['siem_type'] ?? 'splunk', 'generic' ); ?>><?php _e( 'Generic HTTP Endpoint', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Endpoint URL', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="siem-endpoint" value="<?php echo esc_attr( $siem['siem_endpoint'] ?? '' ); ?>" class="large-text" placeholder="https://splunk.company.com:8088/services/collector">
							<p class="description"><?php _e( 'Full HTTP/HTTPS endpoint URL for your SIEM platform.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Authentication Token', 'nexifymy-security' ); ?></th>
						<td>
							<input type="password" id="siem-token" value="<?php echo esc_attr( $siem['siem_token'] ?? '' ); ?>" class="large-text" placeholder="HEC Token or API Key">
							<p class="description"><?php _e( 'API token, HEC token, or authentication key.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Index/Source', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="siem-index" value="<?php echo esc_attr( $siem['siem_index'] ?? 'wordpress_security' ); ?>" class="regular-text">
							<p class="description"><?php _e( 'Index name or source identifier for event categorization.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Event Format', 'nexifymy-security' ); ?></th>
						<td>
							<select id="siem-format" class="regular-text">
								<option value="json" <?php selected( $siem['siem_format'] ?? 'json', 'json' ); ?>><?php _e( 'JSON', 'nexifymy-security' ); ?></option>
								<option value="cef" <?php selected( $siem['siem_format'] ?? 'json', 'cef' ); ?>><?php _e( 'CEF (Common Event Format)', 'nexifymy-security' ); ?></option>
								<option value="leef" <?php selected( $siem['siem_format'] ?? 'json', 'leef' ); ?>><?php _e( 'LEEF (Log Event Extended Format)', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Events to Forward', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="siem-events[]" value="all" <?php checked( in_array( 'all', $siem['siem_events'] ?? array( 'all' ) ) ); ?>> <?php _e( 'All Events', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="siem-events[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $siem['siem_events'] ?? array() ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="siem-events[]" value="malware_found" <?php checked( in_array( 'malware_found', $siem['siem_events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="siem-events[]" value="login_failed" <?php checked( in_array( 'login_failed', $siem['siem_events'] ?? array() ) ); ?>> <?php _e( 'Failed Logins', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="siem-events[]" value="user_locked" <?php checked( in_array( 'user_locked', $siem['siem_events'] ?? array() ) ); ?>> <?php _e( 'User Lockouts', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'SSL Verification', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="siem-ssl-verify" <?php checked( ! empty( $siem['siem_ssl_verify'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Verify SSL certificates (recommended for production).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-siem-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save SIEM Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-siem" class="nms-btn nms-btn-secondary"><?php _e( 'Test Connection', 'nexifymy-security' ); ?></button>
					<span id="siem-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render ticketing integration settings.
	 */
	private function render_ticketing_integration() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$integrations = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		?>
		<!-- Jira Settings -->
		<div class="nms-card" style="margin-bottom: 20px;">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-tickets-alt"></span> <?php _e( 'Jira Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Automatically create Jira tickets for security incidents and vulnerabilities.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Jira', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="jira-enabled" <?php checked( ! empty( $integrations['jira_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Jira Cloud URL', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="jira-url" value="<?php echo esc_attr( $integrations['jira_url'] ?? '' ); ?>" class="large-text" placeholder="https://company.atlassian.net">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Email', 'nexifymy-security' ); ?></th>
						<td>
							<input type="email" id="jira-email" value="<?php echo esc_attr( $integrations['jira_email'] ?? '' ); ?>" class="regular-text" placeholder="security@company.com">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'API Token', 'nexifymy-security' ); ?></th>
						<td>
							<input type="password" id="jira-token" value="<?php echo esc_attr( $integrations['jira_api_token'] ?? '' ); ?>" class="large-text">
							<p class="description"><?php _e( 'Generate from: https://id.atlassian.com/manage-profile/security/api-tokens', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Project Key', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="jira-project" value="<?php echo esc_attr( $integrations['jira_project_key'] ?? '' ); ?>" class="small-text" placeholder="SEC">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Issue Type', 'nexifymy-security' ); ?></th>
						<td>
							<select id="jira-issue-type" class="regular-text">
								<option value="Bug" <?php selected( $integrations['jira_issue_type'] ?? 'Bug', 'Bug' ); ?>><?php _e( 'Bug', 'nexifymy-security' ); ?></option>
								<option value="Task" <?php selected( $integrations['jira_issue_type'] ?? 'Bug', 'Task' ); ?>><?php _e( 'Task', 'nexifymy-security' ); ?></option>
								<option value="Story" <?php selected( $integrations['jira_issue_type'] ?? 'Bug', 'Story' ); ?>><?php _e( 'Story', 'nexifymy-security' ); ?></option>
								<option value="Incident" <?php selected( $integrations['jira_issue_type'] ?? 'Bug', 'Incident' ); ?>><?php _e( 'Incident', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Priority', 'nexifymy-security' ); ?></th>
						<td>
							<select id="jira-priority" class="regular-text">
								<option value="Highest" <?php selected( $integrations['jira_priority'] ?? 'High', 'Highest' ); ?>><?php _e( 'Highest', 'nexifymy-security' ); ?></option>
								<option value="High" <?php selected( $integrations['jira_priority'] ?? 'High', 'High' ); ?>><?php _e( 'High', 'nexifymy-security' ); ?></option>
								<option value="Medium" <?php selected( $integrations['jira_priority'] ?? 'High', 'Medium' ); ?>><?php _e( 'Medium', 'nexifymy-security' ); ?></option>
								<option value="Low" <?php selected( $integrations['jira_priority'] ?? 'High', 'Low' ); ?>><?php _e( 'Low', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Events to Create Tickets', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="jira-events[]" value="malware_found" <?php checked( in_array( 'malware_found', $integrations['jira_events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="jira-events[]" value="plugin_vulnerability" <?php checked( in_array( 'plugin_vulnerability', $integrations['jira_events'] ?? array() ) ); ?>> <?php _e( 'Plugin Vulnerabilities', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="jira-events[]" value="core_file_modified" <?php checked( in_array( 'core_file_modified', $integrations['jira_events'] ?? array() ) ); ?>> <?php _e( 'Core File Modifications', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="jira-events[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $integrations['jira_events'] ?? array() ) ); ?>> <?php _e( 'High-Severity Threats', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-jira-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Jira Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-jira" class="nms-btn nms-btn-secondary"><?php _e( 'Test Connection', 'nexifymy-security' ); ?></button>
					<span id="jira-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>

		<!-- ServiceNow Settings -->
		<div class="nms-card" style="margin-bottom: 20px;">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-tickets-alt"></span> <?php _e( 'ServiceNow Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Create incidents in ServiceNow for critical security events.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable ServiceNow', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="servicenow-enabled" <?php checked( ! empty( $integrations['servicenow_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Instance Name', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="servicenow-instance" value="<?php echo esc_attr( $integrations['servicenow_instance'] ?? '' ); ?>" class="regular-text" placeholder="company.service-now.com">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Username', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="servicenow-username" value="<?php echo esc_attr( $integrations['servicenow_username'] ?? '' ); ?>" class="regular-text">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Password', 'nexifymy-security' ); ?></th>
						<td>
							<input type="password" id="servicenow-password" value="<?php echo esc_attr( $integrations['servicenow_password'] ?? '' ); ?>" class="large-text">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Table Name', 'nexifymy-security' ); ?></th>
						<td>
							<select id="servicenow-table" class="regular-text">
								<option value="incident" <?php selected( $integrations['servicenow_table'] ?? 'incident', 'incident' ); ?>><?php _e( 'Incident', 'nexifymy-security' ); ?></option>
								<option value="problem" <?php selected( $integrations['servicenow_table'] ?? 'incident', 'problem' ); ?>><?php _e( 'Problem', 'nexifymy-security' ); ?></option>
								<option value="security_incident" <?php selected( $integrations['servicenow_table'] ?? 'incident', 'security_incident' ); ?>><?php _e( 'Security Incident', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Impact Level', 'nexifymy-security' ); ?></th>
						<td>
							<select id="servicenow-impact" class="regular-text">
								<option value="1" <?php selected( $integrations['servicenow_impact'] ?? '2', '1' ); ?>><?php _e( '1 - High', 'nexifymy-security' ); ?></option>
								<option value="2" <?php selected( $integrations['servicenow_impact'] ?? '2', '2' ); ?>><?php _e( '2 - Medium', 'nexifymy-security' ); ?></option>
								<option value="3" <?php selected( $integrations['servicenow_impact'] ?? '2', '3' ); ?>><?php _e( '3 - Low', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Urgency Level', 'nexifymy-security' ); ?></th>
						<td>
							<select id="servicenow-urgency" class="regular-text">
								<option value="1" <?php selected( $integrations['servicenow_urgency'] ?? '2', '1' ); ?>><?php _e( '1 - High', 'nexifymy-security' ); ?></option>
								<option value="2" <?php selected( $integrations['servicenow_urgency'] ?? '2', '2' ); ?>><?php _e( '2 - Medium', 'nexifymy-security' ); ?></option>
								<option value="3" <?php selected( $integrations['servicenow_urgency'] ?? '2', '3' ); ?>><?php _e( '3 - Low', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-servicenow-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save ServiceNow Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-servicenow" class="nms-btn nms-btn-secondary"><?php _e( 'Test Connection', 'nexifymy-security' ); ?></button>
					<span id="servicenow-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render communication platform integration.
	 */
	private function render_communication_integration() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$integrations = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		?>
		
		<!-- Slack Settings -->
		<div class="nms-card" style="margin-bottom: 20px;">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-format-chat"></span> <?php _e( 'Slack Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Slack', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="slack-enabled" <?php checked( ! empty( $integrations['slack_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Webhook URL', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="slack-webhook" value="<?php echo esc_attr( $integrations['slack_webhook_url'] ?? '' ); ?>" class="large-text" placeholder="https://hooks.slack.com/services/YOUR/WEBHOOK/URL">
							<p class="description"><?php _e( 'Create webhook at: https://api.slack.com/messaging/webhooks', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Channel', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="slack-channel" value="<?php echo esc_attr( $integrations['slack_channel'] ?? '#security' ); ?>" class="regular-text" placeholder="#security">
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Events to Notify', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="slack-events[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $integrations['slack_events'] ?? array() ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="slack-events[]" value="malware_found" <?php checked( in_array( 'malware_found', $integrations['slack_events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="slack-events[]" value="login_failed" <?php checked( in_array( 'login_failed', $integrations['slack_events'] ?? array() ) ); ?>> <?php _e( 'Failed Logins', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="slack-events[]" value="scan_completed" <?php checked( in_array( 'scan_completed', $integrations['slack_events'] ?? array() ) ); ?>> <?php _e( 'Scan Completed', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-slack-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Slack Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-slack" class="nms-btn nms-btn-secondary"><?php _e( 'Test Notification', 'nexifymy-security' ); ?></button>
					<span id="slack-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>

		<!-- Discord Settings -->
		<div class="nms-card" style="margin-bottom: 20px;">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-format-chat"></span> <?php _e( 'Discord Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Discord', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="discord-enabled" <?php checked( ! empty( $integrations['discord_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Webhook URL', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="discord-webhook" value="<?php echo esc_attr( $integrations['discord_webhook_url'] ?? '' ); ?>" class="large-text" placeholder="https://discord.com/api/webhooks/YOUR_WEBHOOK">
							<p class="description"><?php _e( 'Create webhook in Discord Server Settings > Integrations > Webhooks', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Events to Notify', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="discord-events[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $integrations['discord_events'] ?? array() ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="discord-events[]" value="malware_found" <?php checked( in_array( 'malware_found', $integrations['discord_events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="discord-events[]" value="scan_completed" <?php checked( in_array( 'scan_completed', $integrations['discord_events'] ?? array() ) ); ?>> <?php _e( 'Scan Completed', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-discord-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Discord Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-discord" class="nms-btn nms-btn-secondary"><?php _e( 'Test Notification', 'nexifymy-security' ); ?></button>
					<span id="discord-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>

		<!-- Microsoft Teams Settings -->
		<div class="nms-card" style="margin-bottom: 20px;">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-format-chat"></span> <?php _e( 'Microsoft Teams Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Teams', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="teams-enabled" <?php checked( ! empty( $integrations['teams_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Webhook URL', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="teams-webhook" value="<?php echo esc_attr( $integrations['teams_webhook_url'] ?? '' ); ?>" class="large-text" placeholder="https://outlook.office.com/webhook/YOUR_WEBHOOK">
							<p class="description"><?php _e( 'Create webhook: Teams > Channel > Connectors > Incoming Webhook', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Events to Notify', 'nexifymy-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="teams-events[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $integrations['teams_events'] ?? array() ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="teams-events[]" value="malware_found" <?php checked( in_array( 'malware_found', $integrations['teams_events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label><br>
							<label><input type="checkbox" name="teams-events[]" value="scan_completed" <?php checked( in_array( 'scan_completed', $integrations['teams_events'] ?? array() ) ); ?>> <?php _e( 'Scan Completed', 'nexifymy-security' ); ?></label>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="button" id="save-teams-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Teams Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="test-teams" class="nms-btn nms-btn-secondary"><?php _e( 'Test Notification', 'nexifymy-security' ); ?></button>
					<span id="teams-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render CI/CD integration settings.
	 */
	private function render_cicd_integration() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$cicd = isset( $settings['integrations'] ) ? $settings['integrations'] : array();
		$api_key = get_option( 'nexifymy_cicd_api_key', '' );
		if ( empty( $api_key ) ) {
			$api_key = wp_generate_password( 32, false );
			update_option( 'nexifymy_cicd_api_key', $api_key );
		}
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-admin-tools"></span> <?php _e( 'CI/CD Pipeline Integration', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Integrate security scanning into your continuous integration and deployment pipelines.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable CI/CD Integration', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="cicd-enabled" <?php checked( ! empty( $cicd['cicd_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'API Key', 'nexifymy-security' ); ?></th>
						<td>
							<input type="text" id="cicd-api-key" value="<?php echo esc_attr( $api_key ); ?>" class="large-text" readonly>
							<button type="button" id="regenerate-api-key" class="button"><?php _e( 'Regenerate', 'nexifymy-security' ); ?></button>
							<p class="description"><?php _e( 'Use this key to authenticate API requests from your CI/CD pipeline.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Webhook URL for Results', 'nexifymy-security' ); ?></th>
						<td>
							<input type="url" id="cicd-webhook-url" value="<?php echo esc_attr( $cicd['cicd_webhook_url'] ?? '' ); ?>" class="large-text" placeholder="https://ci.company.com/webhook">
							<p class="description"><?php _e( 'Optional: Send scan results to your CI/CD platform.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Fail Build on Malware', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="cicd-fail-on-malware" <?php checked( ! empty( $cicd['cicd_fail_on_malware'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Return error code if malware is detected (fails CI/CD build).', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Fail Build on Vulnerabilities', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="cicd-fail-on-vuln" <?php checked( ! empty( $cicd['cicd_fail_on_vulnerabilities'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Return error code if vulnerabilities are found.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Minimum Severity to Fail', 'nexifymy-security' ); ?></th>
						<td>
							<select id="cicd-min-severity" class="regular-text">
								<option value="critical" <?php selected( $cicd['cicd_min_severity'] ?? 'high', 'critical' ); ?>><?php _e( 'Critical Only', 'nexifymy-security' ); ?></option>
								<option value="high" <?php selected( $cicd['cicd_min_severity'] ?? 'high', 'high' ); ?>><?php _e( 'High or Above', 'nexifymy-security' ); ?></option>
								<option value="medium" <?php selected( $cicd['cicd_min_severity'] ?? 'high', 'medium' ); ?>><?php _e( 'Medium or Above', 'nexifymy-security' ); ?></option>
								<option value="low" <?php selected( $cicd['cicd_min_severity'] ?? 'high', 'low' ); ?>><?php _e( 'Any Severity', 'nexifymy-security' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<h3 style="margin-top: 30px;"><?php _e( 'API Endpoints', 'nexifymy-security' ); ?></h3>
				<table class="widefat">
					<thead>
						<tr>
							<th><?php _e( 'Endpoint', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Method', 'nexifymy-security' ); ?></th>
							<th><?php _e( 'Description', 'nexifymy-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><code>/wp-json/nexifymy-security/v1/scan</code></td>
							<td>POST</td>
							<td><?php _e( 'Trigger a security scan', 'nexifymy-security' ); ?></td>
						</tr>
						<tr>
							<td><code>/wp-json/nexifymy-security/v1/scan/status</code></td>
							<td>GET</td>
							<td><?php _e( 'Get latest scan status', 'nexifymy-security' ); ?></td>
						</tr>
						<tr>
							<td><code>/wp-json/nexifymy-security/v1/scan/results</code></td>
							<td>GET</td>
							<td><?php _e( 'Get scan results (JSON)', 'nexifymy-security' ); ?></td>
						</tr>
						<tr>
							<td><code>/wp-json/nexifymy-security/v1/vulnerabilities</code></td>
							<td>GET</td>
							<td><?php _e( 'List known vulnerabilities', 'nexifymy-security' ); ?></td>
						</tr>
					</tbody>
				</table>

				<h3 style="margin-top: 30px;"><?php _e( 'Example: GitHub Actions', 'nexifymy-security' ); ?></h3>
				<pre class="nms-code-block"><code>name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger WordPress Security Scan
        run: |
          curl -X POST \
            -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" \
            -H "Content-Type: application/json" \
            <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan' ) ); ?>

      - name: Get Scan Results
        run: |
          curl -X GET \
            -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" \
            <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan/results' ) ); ?></code></pre>

				<h3 style="margin-top: 30px;"><?php _e( 'Example: GitLab CI', 'nexifymy-security' ); ?></h3>
				<pre class="nms-code-block"><code>security_scan:
  stage: test
  script:
    - curl -X POST -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan' ) ); ?>

    - sleep 30
    - curl -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan/results' ) ); ?></code></pre>

				<h3 style="margin-top: 30px;"><?php _e( 'Example: Jenkins Pipeline', 'nexifymy-security' ); ?></h3>
				<pre class="nms-code-block"><code>pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'curl -X POST -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan' ) ); ?>'
                sh 'sleep 30'
                sh 'curl -H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" <?php echo esc_url( rest_url( 'nexifymy-security/v1/scan/results' ) ); ?>'
            }
        }
    }
}</code></pre>

				<p class="submit">
					<button type="button" id="save-cicd-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save CI/CD Settings', 'nexifymy-security' ); ?></button>
					<span id="cicd-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render custom webhooks settings.
	 */
	private function render_webhooks_integration() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$webhooks = isset( $settings['integrations']['custom_webhooks'] ) ? $settings['integrations']['custom_webhooks'] : array();
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-rest-api"></span> <?php _e( 'Custom Webhooks', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<p class="description" style="margin-bottom: 20px;"><?php _e( 'Send security events to any HTTP endpoint with custom configuration.', 'nexifymy-security' ); ?></p>
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Custom Webhooks', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="webhooks-enabled" <?php checked( ! empty( $settings['integrations']['custom_webhooks_enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
				</table>

				<div id="webhooks-list">
					<?php foreach ( $webhooks as $index => $webhook ) : ?>
						<div class="nms-webhook-item nms-card" style="margin-top: 20px; background: #f5f5f5;">
							<div class="nms-card-header" style="display: flex; justify-content: space-between;">
								<h4><?php echo esc_html( $webhook['name'] ?? 'Webhook ' . ( $index + 1 ) ); ?></h4>
								<button type="button" class="button remove-webhook" data-index="<?php echo esc_attr( $index ); ?>"><?php _e( 'Remove', 'nexifymy-security' ); ?></button>
							</div>
							<div class="nms-card-body">
								<table class="form-table">
									<tr>
										<th><?php _e( 'Name', 'nexifymy-security' ); ?></th>
										<td><input type="text" name="webhook_name[]" value="<?php echo esc_attr( $webhook['name'] ?? '' ); ?>" class="regular-text"></td>
									</tr>
									<tr>
										<th><?php _e( 'URL', 'nexifymy-security' ); ?></th>
										<td><input type="url" name="webhook_url[]" value="<?php echo esc_attr( $webhook['url'] ?? '' ); ?>" class="large-text"></td>
									</tr>
									<tr>
										<th><?php _e( 'Method', 'nexifymy-security' ); ?></th>
										<td>
											<select name="webhook_method[]" class="regular-text">
												<option value="POST" <?php selected( $webhook['method'] ?? 'POST', 'POST' ); ?>>POST</option>
												<option value="PUT" <?php selected( $webhook['method'] ?? 'POST', 'PUT' ); ?>>PUT</option>
												<option value="PATCH" <?php selected( $webhook['method'] ?? 'POST', 'PATCH' ); ?>>PATCH</option>
											</select>
										</td>
									</tr>
									<tr>
										<th><?php _e( 'Headers', 'nexifymy-security' ); ?></th>
										<td>
											<textarea name="webhook_headers[]" rows="3" class="large-text code"><?php echo esc_textarea( json_encode( $webhook['headers'] ?? array(), JSON_PRETTY_PRINT ) ); ?></textarea>
											<p class="description"><?php _e( 'JSON format. Example: {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}', 'nexifymy-security' ); ?></p>
										</td>
									</tr>
									<tr>
										<th><?php _e( 'Events', 'nexifymy-security' ); ?></th>
										<td>
											<label><input type="checkbox" name="webhook_events_<?php echo esc_attr( $index ); ?>[]" value="all" <?php checked( in_array( 'all', $webhook['events'] ?? array() ) ); ?>> <?php _e( 'All Events', 'nexifymy-security' ); ?></label><br>
											<label><input type="checkbox" name="webhook_events_<?php echo esc_attr( $index ); ?>[]" value="threat_detected" <?php checked( in_array( 'threat_detected', $webhook['events'] ?? array() ) ); ?>> <?php _e( 'Threat Detected', 'nexifymy-security' ); ?></label><br>
											<label><input type="checkbox" name="webhook_events_<?php echo esc_attr( $index ); ?>[]" value="malware_found" <?php checked( in_array( 'malware_found', $webhook['events'] ?? array() ) ); ?>> <?php _e( 'Malware Found', 'nexifymy-security' ); ?></label>
										</td>
									</tr>
								</table>
							</div>
						</div>
					<?php endforeach; ?>
				</div>

				<p style="margin-top: 20px;">
					<button type="button" id="add-webhook" class="button"><?php _e( 'Add Webhook', 'nexifymy-security' ); ?></button>
				</p>

				<p class="submit">
					<button type="button" id="save-webhooks-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Webhook Settings', 'nexifymy-security' ); ?></button>
					<span id="webhooks-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Supply Chain Security page.
	 */
	public function render_supply_chain_page() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-networking"></span> <?php _e( 'Supply Chain Security', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Dependency scanning, third-party script monitoring, and CDN integrity verification.', 'nexifymy-security' ); ?></p>
			</div>
			<?php $this->render_supply_chain_content(); ?>
		</div>
		<?php
	}

	/**
	 * Render Compliance & Reporting page.
	 */
	public function render_compliance_page() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-yes-alt"></span> <?php _e( 'Compliance & Reporting', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'GDPR, CCPA, HIPAA compliance modules and comprehensive security audit reports.', 'nexifymy-security' ); ?></p>
			</div>
			<?php $this->render_compliance_content(); ?>
		</div>
		<?php
	}

	/**
	 * Render Recommendations (Proactive Security) page.
	 */
	public function render_recommendations_page() {
		$recommendations = $this->get_security_recommendations();
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-lightbulb"></span> <?php _e( 'Security Recommendations', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Proactive security suggestions and automated hardening recommendations.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-card">
				<div class="nms-card-header">
					<h3><?php _e( 'Recommended Actions', 'nexifymy-security' ); ?></h3>
				</div>
				<div class="nms-card-body">
					<?php if ( empty( $recommendations ) ) : ?>
						<div class="nms-empty-state">
							<span class="dashicons dashicons-yes-alt" style="font-size: 48px; width: 48px; height: 48px; color: #22c55e;"></span>
							<h3><?php _e( 'All Clear!', 'nexifymy-security' ); ?></h3>
							<p><?php _e( 'No security recommendations at this time. Your site is well protected.', 'nexifymy-security' ); ?></p>
						</div>
					<?php else : ?>
						<div class="nms-recommendations-list">
							<?php foreach ( $recommendations as $rec ) : ?>
								<div class="nms-recommendation-item" style="padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 15px;">
									<div style="display: flex; align-items: flex-start; gap: 15px;">
										<div class="nms-rec-icon" style="flex-shrink: 0; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; background: <?php echo esc_attr( $rec['bg_color'] ); ?>; border-radius: 8px; color: <?php echo esc_attr( $rec['icon_color'] ); ?>;">
											<span class="dashicons dashicons-<?php echo esc_attr( $rec['icon'] ); ?>"></span>
										</div>
										<div style="flex: 1;">
											<h4 style="margin: 0 0 8px 0; font-size: 16px;"><?php echo esc_html( $rec['title'] ); ?></h4>
											<p style="margin: 0 0 12px 0; color: #64748b;"><?php echo esc_html( $rec['description'] ); ?></p>
											<div style="display: flex; gap: 10px; align-items: center;">
												<span class="nms-badge nms-badge-<?php echo esc_attr( $rec['severity'] ?? 'info' ); ?>">
													<?php echo esc_html( ucfirst( $rec['severity'] ?? 'info' ) ); ?>
												</span>
												<?php if ( ! empty( $rec['auto_fix'] ) ) : ?>
													<button class="nms-btn nms-btn-sm nms-btn-primary" data-action="<?php echo esc_attr( $rec['fix_action'] ?? '' ); ?>">
														<?php _e( 'Auto-Fix', 'nexifymy-security' ); ?>
													</button>
												<?php endif; ?>
												<?php if ( ! empty( $rec['link'] ) ) : ?>
													<a href="<?php echo esc_url( $rec['link'] ); ?>" class="nms-btn nms-btn-sm nms-btn-secondary">
														<?php _e( 'Configure', 'nexifymy-security' ); ?>
													</a>
												<?php endif; ?>
											</div>
										</div>
									</div>
								</div>
							<?php endforeach; ?>
						</div>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Get security recommendations based on current settings.
	 */
	private function get_security_recommendations() {
		$recommendations = array();
		$settings = get_option( 'nexifymy_security_settings', array() );
		$modules = isset( $settings['modules'] ) ? $settings['modules'] : array();
		$fw_settings = isset( $settings['firewall'] ) ? $settings['firewall'] : array();

		// Check Firewall
		if ( empty( $fw_settings['enabled'] ) ) {
			$recommendations[] = array(
				'title'       => __( 'Enable Web Application Firewall', 'nexifymy-security' ),
				'description' => __( 'Protect your site from malicious traffic and attacks.', 'nexifymy-security' ),
				'icon'        => 'shield-alt',
				'bg_color'    => '#fee2e2',
				'icon_color'  => '#dc2626',
				'severity'    => 'critical',
				'auto_fix'    => false,
				'link'        => admin_url( 'admin.php?page=nexifymy-security-firewall' ),
			);
		}

		// Check Malware Signatures
		$sig_status = isset( $GLOBALS['nexifymy_signatures'] ) && method_exists( $GLOBALS['nexifymy_signatures'], 'get_status' ) 
			? $GLOBALS['nexifymy_signatures']->get_status() 
			: array();
		
		$last_update = isset( $sig_status['last_update']['updated_at'] ) ? strtotime( $sig_status['last_update']['updated_at'] ) : 0;
		$days_since = ( time() - $last_update ) / DAY_IN_SECONDS;

		if ( $days_since > 7 ) {
			$recommendations[] = array(
				'title'       => __( 'Update Malware Definitons', 'nexifymy-security' ),
				'description' => __( 'Your virus definitions are out of date. Update now for best protection.', 'nexifymy-security' ),
				'icon'        => 'update',
				'bg_color'    => '#fef3c7',
				'icon_color'  => '#d97706',
				'severity'    => 'high',
				'auto_fix'    => false,
				'link'        => admin_url( 'admin.php?page=nexifymy-security-scanner' ),
			);
		}

		// Check 2FA
		if ( empty( $modules['two_factor_enabled'] ) ) {
			$recommendations[] = array(
				'title'       => __( 'Enable Two-Factor Authentication', 'nexifymy-security' ),
				'description' => __( 'Add an extra layer of security by requiring a second form of authentication.', 'nexifymy-security' ),
				'icon'        => 'smartphone',
				'bg_color'    => '#fef3c7',
				'icon_color'  => '#d97706',
				'severity'    => 'warning',
				'auto_fix'    => true,
				'fix_action'  => 'enable_2fa',
			);
		}

		// Check CAPTCHA
		if ( empty( $modules['captcha_enabled'] ) ) {
			$recommendations[] = array(
				'title'       => __( 'Enable CAPTCHA Protection', 'nexifymy-security' ),
				'description' => __( 'Protect login and registration forms from automated bot attacks.', 'nexifymy-security' ),
				'icon'        => 'shield',
				'bg_color'    => '#eef2ff',
				'icon_color'  => '#4f46e5',
				'severity'    => 'info',
				'auto_fix'    => true,
				'fix_action'  => 'enable_captcha',
			);
		}

		// Check Hide Login
		if ( empty( $modules['hide_login_enabled'] ) ) {
			$recommendations[] = array(
				'title'       => __( 'Hide WordPress Login URL', 'nexifymy-security' ),
				'description' => __( 'Change the default wp-admin login URL to prevent automated attacks.', 'nexifymy-security' ),
				'icon'        => 'hidden',
				'bg_color'    => '#e0f2fe',
				'icon_color'  => '#0284c7',
				'severity'    => 'info',
				'auto_fix'    => false,
				'link'        => admin_url( 'admin.php?page=nexifymy-security-modules&tab=hidelogin' ),
			);
		}

		// Check File Editor
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$recommendations[] = array(
				'title'       => __( 'Disable File Editor', 'nexifymy-security' ),
				'description' => __( 'Disable the built-in theme and plugin editor to prevent code injection.', 'nexifymy-security' ),
				'icon'        => 'edit',
				'bg_color'    => '#fee2e2',
				'icon_color'  => '#dc2626',
				'severity'    => 'critical',
				'auto_fix'    => true,
				'fix_action'  => 'disable_file_editor',
			);
		}

		// Check SSL
		if ( ! is_ssl() ) {
			$recommendations[] = array(
				'title'       => __( 'Enable SSL/HTTPS', 'nexifymy-security' ),
				'description' => __( 'Your site is not using HTTPS. Enable SSL certificate for secure connections.', 'nexifymy-security' ),
				'icon'        => 'lock',
				'bg_color'    => '#fee2e2',
				'icon_color'  => '#dc2626',
				'severity'    => 'critical',
				'auto_fix'    => false,
			);
		}

		return $recommendations;
	}

	/**
	 * Render the Activity Log page with tabs.
	 */
	public function render_activity_log_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap nexifymy-security-wrap nms-tabbed-page">
			<div class="nms-page-header">
				<h1><span class="dashicons dashicons-clipboard"></span> <?php _e( 'Activity Log', 'nexifymy-security' ); ?></h1>
				<p><?php _e( 'Comprehensive user activity tracking, login monitoring, and system event logging.', 'nexifymy-security' ); ?></p>
			</div>

			<div class="nms-page-tabs">
				<button class="nms-page-tab <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" data-tab="overview">
					<span class="dashicons dashicons-chart-area"></span> <?php _e( 'Overview', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'login' ? 'active' : ''; ?>" data-tab="login">
					<span class="dashicons dashicons-admin-users"></span> <?php _e( 'Login Activity', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'users' ? 'active' : ''; ?>" data-tab="users">
					<span class="dashicons dashicons-groups"></span> <?php _e( 'User Activity', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'content' ? 'active' : ''; ?>" data-tab="content">
					<span class="dashicons dashicons-edit-page"></span> <?php _e( 'Content Changes', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'system' ? 'active' : ''; ?>" data-tab="system">
					<span class="dashicons dashicons-admin-generic"></span> <?php _e( 'System Events', 'nexifymy-security' ); ?>
				</button>
				<button class="nms-page-tab <?php echo $active_tab === 'settings' ? 'active' : ''; ?>" data-tab="settings">
					<span class="dashicons dashicons-admin-settings"></span> <?php _e( 'Settings', 'nexifymy-security' ); ?>
				</button>
			</div>

			<div class="nms-tab-content">
				<div id="tab-overview" class="nms-tab-panel <?php echo $active_tab === 'overview' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'overview' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_overview_content(); ?>
				</div>
				<div id="tab-login" class="nms-tab-panel <?php echo $active_tab === 'login' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'login' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_login_content(); ?>
				</div>
				<div id="tab-users" class="nms-tab-panel <?php echo $active_tab === 'users' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'users' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_users_content(); ?>
				</div>
				<div id="tab-content" class="nms-tab-panel <?php echo $active_tab === 'content' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'content' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_content_content(); ?>
				</div>
				<div id="tab-system" class="nms-tab-panel <?php echo $active_tab === 'system' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'system' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_system_content(); ?>
				</div>
				<div id="tab-settings" class="nms-tab-panel <?php echo $active_tab === 'settings' ? 'active' : ''; ?>" style="display: <?php echo $active_tab === 'settings' ? 'block !important' : 'none !important'; ?>;">
					<?php $this->render_activity_settings_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Activity Log Overview content.
	 */
	private function render_activity_overview_content() {
		$activity_log = new NexifyMy_Security_Activity_Log();
		$stats = $activity_log->get_stats( 30 );
		$recent = $activity_log->get_entries( array( 'per_page' => 10, 'page' => 1 ) );
		
		// Calculate some derived values.
		$security_score = 100;
		if ( $stats['failed_logins'] > 50 ) {
			$security_score -= 20;
		} elseif ( $stats['failed_logins'] > 20 ) {
			$security_score -= 10;
		}
		if ( count( $stats['suspicious_ips'] ?? array() ) > 5 ) {
			$security_score -= 15;
		}
		if ( ( $stats['critical'] ?? 0 ) > 0 ) {
			$security_score -= 10;
		}
		$security_score = max( 0, $security_score );
		$security_class = $security_score >= 80 ? 'green' : ( $security_score >= 50 ? 'orange' : 'red' );
		?>
		<!-- Period Selector -->
		<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
			<h2 style="margin: 0; display: flex; align-items: center; gap: 10px;">
				<span class="dashicons dashicons-chart-area"></span>
				<?php _e( 'Activity Dashboard', 'nexifymy-security' ); ?>
			</h2>
			<div style="display: flex; gap: 10px; align-items: center;">
				<span style="color: var(--nms-gray-500);"><?php _e( 'Last 30 days', 'nexifymy-security' ); ?></span>
				<button class="nms-btn nms-btn-secondary" id="refresh-stats">
					<span class="dashicons dashicons-update"></span> <?php _e( 'Refresh', 'nexifymy-security' ); ?>
				</button>
			</div>
		</div>

		<!-- Top Stats Row - Primary Metrics -->
		<div class="nms-stats-row" style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px;">
			<!-- Total Events -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body" style="text-align: center; padding: 20px;">
					<div class="nms-stat-icon blue" style="margin: 0 auto 8px; width: 40px; height: 40px;"><span class="dashicons dashicons-chart-bar"></span></div>
					<div style="font-size: 26px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['total'] ?? 0 ); ?></div>
					<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'Total Events', 'nexifymy-security' ); ?></div>
				</div>
			</div>
			<!-- Events Today -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body" style="text-align: center; padding: 20px;">
					<div class="nms-stat-icon cyan" style="margin: 0 auto 8px; width: 40px; height: 40px;"><span class="dashicons dashicons-calendar-alt"></span></div>
					<div style="font-size: 26px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['today'] ?? 0 ); ?></div>
					<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'Today', 'nexifymy-security' ); ?></div>
				</div>
			</div>
			<!-- Unique Users -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body" style="text-align: center; padding: 20px;">
					<div class="nms-stat-icon purple" style="margin: 0 auto 8px; width: 40px; height: 40px;"><span class="dashicons dashicons-groups"></span></div>
					<div style="font-size: 26px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['unique_users'] ?? 0 ); ?></div>
					<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'Unique Users', 'nexifymy-security' ); ?></div>
				</div>
			</div>
			<!-- Unique IPs -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body" style="text-align: center; padding: 20px;">
					<div class="nms-stat-icon teal" style="margin: 0 auto 8px; width: 40px; height: 40px;"><span class="dashicons dashicons-admin-site-alt3"></span></div>
					<div style="font-size: 26px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['unique_ips'] ?? 0 ); ?></div>
					<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'Unique IPs', 'nexifymy-security' ); ?></div>
				</div>
			</div>
			<!-- Avg per Day -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-body" style="text-align: center; padding: 20px;">
					<div class="nms-stat-icon gray" style="margin: 0 auto 8px; width: 40px; height: 40px;"><span class="dashicons dashicons-performance"></span></div>
					<div style="font-size: 26px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['avg_events_per_day'] ?? 0, 1 ); ?></div>
					<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'Avg/Day', 'nexifymy-security' ); ?></div>
				</div>
			</div>
		</div>

		<!-- Login & Authentication Stats -->
		<div class="nms-card" style="margin-bottom: 25px;">
			<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
				<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
					<span class="dashicons dashicons-lock" style="color: var(--nms-primary);"></span>
					<?php _e( 'Login & Authentication', 'nexifymy-security' ); ?>
				</h3>
			</div>
			<div class="nms-card-body" style="padding: 25px;">
				<div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px;">
					<!-- Successful Logins -->
					<div style="text-align: center; padding: 20px; background: var(--nms-success-bg, #ecfdf5); border-radius: 12px;">
						<span class="dashicons dashicons-yes-alt" style="font-size: 28px; color: var(--nms-success); margin-bottom: 10px;"></span>
						<div style="font-size: 28px; font-weight: 700; color: var(--nms-success);"><?php echo number_format( $stats['logins'] ?? 0 ); ?></div>
						<div style="font-size: 12px; color: var(--nms-gray-600); margin-top: 4px;"><?php _e( 'Successful Logins', 'nexifymy-security' ); ?></div>
					</div>
					<!-- Failed Logins -->
					<div style="text-align: center; padding: 20px; background: var(--nms-danger-bg, #fef2f2); border-radius: 12px;">
						<span class="dashicons dashicons-dismiss" style="font-size: 28px; color: var(--nms-danger); margin-bottom: 10px;"></span>
						<div style="font-size: 28px; font-weight: 700; color: var(--nms-danger);"><?php echo number_format( $stats['failed_logins'] ?? 0 ); ?></div>
						<div style="font-size: 12px; color: var(--nms-gray-600); margin-top: 4px;"><?php _e( 'Failed Logins', 'nexifymy-security' ); ?></div>
					</div>
					<!-- Logouts -->
					<div style="text-align: center; padding: 20px; background: var(--nms-info-bg, #eff6ff); border-radius: 12px;">
						<span class="dashicons dashicons-migrate" style="font-size: 28px; color: var(--nms-info); margin-bottom: 10px;"></span>
						<div style="font-size: 28px; font-weight: 700; color: var(--nms-info);"><?php echo number_format( $stats['logouts'] ?? 0 ); ?></div>
						<div style="font-size: 12px; color: var(--nms-gray-600); margin-top: 4px;"><?php _e( 'Logouts', 'nexifymy-security' ); ?></div>
					</div>
					<!-- Success Rate -->
					<div style="text-align: center; padding: 20px; background: var(--nms-gray-100, #f3f4f6); border-radius: 12px;">
						<span class="dashicons dashicons-awards" style="font-size: 28px; color: var(--nms-primary); margin-bottom: 10px;"></span>
						<div style="font-size: 28px; font-weight: 700; color: var(--nms-gray-900);"><?php echo $stats['login_success_rate'] ?? 100; ?>%</div>
						<div style="font-size: 12px; color: var(--nms-gray-600); margin-top: 4px;"><?php _e( 'Success Rate', 'nexifymy-security' ); ?></div>
					</div>
					<!-- Password Resets -->
					<div style="text-align: center; padding: 20px; background: var(--nms-warning-bg, #fffbeb); border-radius: 12px;">
						<span class="dashicons dashicons-admin-network" style="font-size: 28px; color: var(--nms-warning-dark, #d97706); margin-bottom: 10px;"></span>
						<div style="font-size: 28px; font-weight: 700; color: var(--nms-warning-dark, #d97706);"><?php echo number_format( $stats['password_resets'] ?? 0 ); ?></div>
						<div style="font-size: 12px; color: var(--nms-gray-600); margin-top: 4px;"><?php _e( 'Password Resets', 'nexifymy-security' ); ?></div>
					</div>
				</div>
			</div>
		</div>

		<!-- Two Column Layout: User Management & Content Activity -->
		<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
			<!-- User Management Stats -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-admin-users" style="color: var(--nms-purple);"></span>
						<?php _e( 'User Management', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body">
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Users Created', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-success);"><?php echo number_format( $stats['users_created'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Users Deleted', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-danger);"><?php echo number_format( $stats['users_deleted'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Role Changes', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-warning-dark, #d97706);"><?php echo number_format( $stats['role_changes'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Profile Updates', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-info);"><?php echo number_format( $stats['profile_updates'] ?? 0 ); ?></strong>
						</div>
					</div>
				</div>
			</div>

			<!-- Content Activity Stats -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-edit-page" style="color: var(--nms-info);"></span>
						<?php _e( 'Content Activity', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body">
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Posts Created', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-success);"><?php echo number_format( $stats['posts_created'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Posts Updated', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-info);"><?php echo number_format( $stats['posts_updated'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Posts Published', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-primary);"><?php echo number_format( $stats['posts_published'] ?? 0 ); ?></strong>
						</div>
						<div style="padding: 15px; background: var(--nms-gray-50); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
							<span style="color: var(--nms-gray-600);"><?php _e( 'Media Uploads', 'nexifymy-security' ); ?></span>
							<strong style="font-size: 18px; color: var(--nms-purple);"><?php echo number_format( $stats['media_uploads'] ?? 0 ); ?></strong>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- System Activity Stats -->
		<div class="nms-card" style="margin-bottom: 25px;">
			<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
				<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
					<span class="dashicons dashicons-admin-generic" style="color: var(--nms-warning-dark, #d97706);"></span>
					<?php _e( 'System Activity', 'nexifymy-security' ); ?>
				</h3>
			</div>
			<div class="nms-card-body" style="padding: 25px;">
				<div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px;">
					<div style="text-align: center; padding: 15px; background: var(--nms-gray-50); border-radius: 10px;">
						<span class="dashicons dashicons-plugins-checked" style="font-size: 24px; color: var(--nms-success); margin-bottom: 8px;"></span>
						<div style="font-size: 24px; font-weight: 700;"><?php echo number_format( $stats['plugins_activated'] ?? 0 ); ?></div>
						<div style="font-size: 11px; color: var(--nms-gray-500);"><?php _e( 'Plugins Activated', 'nexifymy-security' ); ?></div>
					</div>
					<div style="text-align: center; padding: 15px; background: var(--nms-gray-50); border-radius: 10px;">
						<span class="dashicons dashicons-admin-plugins" style="font-size: 24px; color: var(--nms-gray-400); margin-bottom: 8px;"></span>
						<div style="font-size: 24px; font-weight: 700;"><?php echo number_format( $stats['plugins_deactivated'] ?? 0 ); ?></div>
						<div style="font-size: 11px; color: var(--nms-gray-500);"><?php _e( 'Plugins Deactivated', 'nexifymy-security' ); ?></div>
					</div>
					<div style="text-align: center; padding: 15px; background: var(--nms-gray-50); border-radius: 10px;">
						<span class="dashicons dashicons-update-alt" style="font-size: 24px; color: var(--nms-info); margin-bottom: 8px;"></span>
						<div style="font-size: 24px; font-weight: 700;"><?php echo number_format( $stats['plugins_updated'] ?? 0 ); ?></div>
						<div style="font-size: 11px; color: var(--nms-gray-500);"><?php _e( 'Plugins Updated', 'nexifymy-security' ); ?></div>
					</div>
					<div style="text-align: center; padding: 15px; background: var(--nms-gray-50); border-radius: 10px;">
						<span class="dashicons dashicons-admin-appearance" style="font-size: 24px; color: var(--nms-purple); margin-bottom: 8px;"></span>
						<div style="font-size: 24px; font-weight: 700;"><?php echo number_format( $stats['theme_switches'] ?? 0 ); ?></div>
						<div style="font-size: 11px; color: var(--nms-gray-500);"><?php _e( 'Theme Switches', 'nexifymy-security' ); ?></div>
					</div>
					<div style="text-align: center; padding: 15px; background: var(--nms-gray-50); border-radius: 10px;">
						<span class="dashicons dashicons-admin-settings" style="font-size: 24px; color: var(--nms-warning-dark, #d97706); margin-bottom: 8px;"></span>
						<div style="font-size: 24px; font-weight: 700;"><?php echo number_format( $stats['option_updates'] ?? 0 ); ?></div>
						<div style="font-size: 11px; color: var(--nms-gray-500);"><?php _e( 'Option Changes', 'nexifymy-security' ); ?></div>
					</div>
				</div>
			</div>
		</div>

		<!-- Peak Activity & Event Types -->
		<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
			<!-- Peak Activity Insights -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-clock" style="color: var(--nms-info);"></span>
						<?php _e( 'Peak Activity Insights', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body">
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
						<div style="padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; color: #fff;">
							<div style="font-size: 11px; opacity: 0.8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;"><?php _e( 'Peak Hour', 'nexifymy-security' ); ?></div>
							<div style="font-size: 28px; font-weight: 700;"><?php echo sprintf( '%02d:00', $stats['peak_hour'] ?? 0 ); ?></div>
							<div style="font-size: 12px; opacity: 0.8;"><?php echo number_format( $stats['peak_hour_count'] ?? 0 ); ?> <?php _e( 'events', 'nexifymy-security' ); ?></div>
						</div>
						<div style="padding: 20px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); border-radius: 10px; color: #fff;">
							<div style="font-size: 11px; opacity: 0.8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;"><?php _e( 'Busiest Day', 'nexifymy-security' ); ?></div>
							<div style="font-size: 20px; font-weight: 700;"><?php echo ! empty( $stats['peak_day'] ) ? esc_html( gmdate( 'M j', strtotime( $stats['peak_day'] ) ) ) : '—'; ?></div>
							<div style="font-size: 12px; opacity: 0.8;"><?php echo number_format( $stats['peak_day_count'] ?? 0 ); ?> <?php _e( 'events', 'nexifymy-security' ); ?></div>
						</div>
						<div style="padding: 20px; background: var(--nms-gray-100); border-radius: 10px;">
							<div style="font-size: 11px; color: var(--nms-gray-500); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;"><?php _e( 'This Hour', 'nexifymy-security' ); ?></div>
							<div style="font-size: 28px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['this_hour'] ?? 0 ); ?></div>
							<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'events', 'nexifymy-security' ); ?></div>
						</div>
						<div style="padding: 20px; background: var(--nms-gray-100); border-radius: 10px;">
							<div style="font-size: 11px; color: var(--nms-gray-500); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;"><?php _e( 'Database Size', 'nexifymy-security' ); ?></div>
							<div style="font-size: 28px; font-weight: 700; color: var(--nms-gray-900);"><?php echo number_format( $stats['db_rows'] ?? 0 ); ?></div>
							<div style="font-size: 12px; color: var(--nms-gray-500);"><?php _e( 'total records', 'nexifymy-security' ); ?></div>
						</div>
					</div>
				</div>
			</div>

			<!-- Top Event Types -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-list-view" style="color: var(--nms-primary);"></span>
						<?php _e( 'Top Event Types', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body">
					<?php if ( ! empty( $stats['by_event_type'] ) ) : ?>
						<?php 
						$max_count = max( array_column( $stats['by_event_type'], 'count' ) );
						foreach ( array_slice( $stats['by_event_type'], 0, 6 ) as $event ) : 
							$percentage = $max_count > 0 ? ( $event->count / $max_count ) * 100 : 0;
						?>
							<div style="margin-bottom: 12px;">
								<div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
									<span style="font-size: 13px; color: var(--nms-gray-700);"><?php echo esc_html( ucwords( str_replace( '_', ' ', $event->event_type ) ) ); ?></span>
									<span style="font-size: 13px; font-weight: 600; color: var(--nms-gray-900);"><?php echo number_format( $event->count ); ?></span>
								</div>
								<div style="height: 6px; background: var(--nms-gray-200); border-radius: 3px; overflow: hidden;">
									<div style="height: 100%; width: <?php echo esc_attr( $percentage ); ?>%; background: linear-gradient(90deg, var(--nms-primary), var(--nms-primary-light, var(--nms-primary))); border-radius: 3px;"></div>
								</div>
							</div>
						<?php endforeach; ?>
					<?php else : ?>
						<p class="description"><?php _e( 'No event data available yet.', 'nexifymy-security' ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		</div>

		<!-- Three Column: Most Active Users, Suspicious IPs, Event Groups -->
		<div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 25px;">
			<!-- Most Active Users -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-businessman" style="color: var(--nms-purple);"></span>
						<?php _e( 'Most Active Users', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body" style="padding: 0;">
					<?php if ( ! empty( $stats['active_users'] ) ) : ?>
						<table class="widefat" style="border: none;">
							<tbody>
								<?php foreach ( array_slice( $stats['active_users'], 0, 5 ) as $index => $user ) : ?>
									<tr style="<?php echo $index % 2 === 0 ? 'background: var(--nms-gray-50);' : ''; ?>">
										<td style="padding: 12px 15px;">
											<strong><?php echo esc_html( $user->username ); ?></strong>
											<br><small style="color: var(--nms-gray-500);"><?php echo esc_html( ucfirst( $user->user_role ) ); ?></small>
										</td>
										<td style="text-align: right; padding: 12px 15px;">
											<span class="nms-badge nms-badge-primary"><?php echo number_format( $user->count ); ?></span>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php else : ?>
						<div style="padding: 20px; text-align: center; color: var(--nms-gray-500);">
							<?php _e( 'No user activity yet.', 'nexifymy-security' ); ?>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<!-- Suspicious IPs -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-shield" style="color: var(--nms-danger);"></span>
						<?php _e( 'Suspicious IPs', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body" style="padding: 0;">
					<?php if ( ! empty( $stats['suspicious_ips'] ) ) : ?>
						<table class="widefat" style="border: none;">
							<tbody>
								<?php foreach ( array_slice( $stats['suspicious_ips'], 0, 5 ) as $index => $ip ) : ?>
									<tr style="<?php echo $index % 2 === 0 ? 'background: var(--nms-gray-50);' : ''; ?>">
										<td style="padding: 12px 15px;"><code><?php echo esc_html( $ip->ip_address ); ?></code></td>
										<td style="text-align: right; padding: 12px 15px;">
											<span class="nms-badge nms-badge-danger"><?php echo intval( $ip->count ); ?> <?php _e( 'fails', 'nexifymy-security' ); ?></span>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php else : ?>
						<div style="padding: 20px; text-align: center; color: var(--nms-success);">
							<span class="dashicons dashicons-yes-alt"></span> <?php _e( 'No suspicious IPs detected.', 'nexifymy-security' ); ?>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<!-- Severity Breakdown -->
			<div class="nms-card" style="margin: 0;">
				<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200);">
					<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-warning" style="color: var(--nms-warning-dark, #d97706);"></span>
						<?php _e( 'Event Severity', 'nexifymy-security' ); ?>
					</h3>
				</div>
				<div class="nms-card-body">
					<?php 
					$severity_colors = array(
						'info'     => array( 'bg' => '#eff6ff', 'color' => '#3b82f6' ),
						'low'      => array( 'bg' => '#f0fdf4', 'color' => '#22c55e' ),
						'medium'   => array( 'bg' => '#fefce8', 'color' => '#eab308' ),
						'warning'  => array( 'bg' => '#fff7ed', 'color' => '#f97316' ),
						'high'     => array( 'bg' => '#fef2f2', 'color' => '#ef4444' ),
						'critical' => array( 'bg' => '#fef2f2', 'color' => '#dc2626' ),
					);
					if ( ! empty( $stats['by_severity'] ) ) :
						foreach ( $stats['by_severity'] as $severity => $count ) :
							$colors = $severity_colors[ $severity ] ?? array( 'bg' => '#f3f4f6', 'color' => '#6b7280' );
					?>
						<div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 15px; margin-bottom: 8px; background: <?php echo esc_attr( $colors['bg'] ); ?>; border-radius: 8px; border-left: 4px solid <?php echo esc_attr( $colors['color'] ); ?>;">
							<span style="font-weight: 500; color: <?php echo esc_attr( $colors['color'] ); ?>; text-transform: capitalize;"><?php echo esc_html( $severity ); ?></span>
							<strong style="font-size: 16px;"><?php echo number_format( $count ); ?></strong>
						</div>
					<?php 
						endforeach;
					else : ?>
						<p class="description"><?php _e( 'No severity data available.', 'nexifymy-security' ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		</div>

		<!-- Recent Activity -->
		<div class="nms-card">
			<div class="nms-card-header" style="border-bottom: 1px solid var(--nms-gray-200); display: flex; justify-content: space-between; align-items: center;">
				<h3 style="margin: 0; display: flex; align-items: center; gap: 8px;">
					<span class="dashicons dashicons-backup" style="color: var(--nms-gray-600);"></span>
					<?php _e( 'Recent Activity', 'nexifymy-security' ); ?>
				</h3>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=nexifymy-security-activity-log&tab=login' ) ); ?>" class="nms-btn nms-btn-secondary" style="font-size: 12px; padding: 6px 12px;">
					<?php _e( 'View All', 'nexifymy-security' ); ?> →
				</a>
			</div>
			<div class="nms-card-body" style="padding: 0;">
				<?php if ( ! empty( $recent['entries'] ) ) : ?>
					<table class="widefat" style="border: none;">
						<thead style="background: var(--nms-gray-50);">
							<tr>
								<th style="padding: 12px 15px;"><?php _e( 'Time', 'nexifymy-security' ); ?></th>
								<th style="padding: 12px 15px;"><?php _e( 'User', 'nexifymy-security' ); ?></th>
								<th style="padding: 12px 15px;"><?php _e( 'Event', 'nexifymy-security' ); ?></th>
								<th style="padding: 12px 15px;"><?php _e( 'Description', 'nexifymy-security' ); ?></th>
								<th style="padding: 12px 15px;"><?php _e( 'IP Address', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $recent['entries'] as $index => $entry ) : 
								$badge_class = 'nms-badge-secondary';
								if ( $entry->severity === 'warning' ) {
									$badge_class = 'nms-badge-warning';
								} elseif ( $entry->severity === 'critical' || $entry->severity === 'error' || $entry->severity === 'high' ) {
									$badge_class = 'nms-badge-danger';
								} elseif ( $entry->event_type === 'login_success' ) {
									$badge_class = 'nms-badge-success';
								} elseif ( $entry->event_type === 'login_failed' ) {
									$badge_class = 'nms-badge-danger';
								}
							?>
								<tr style="<?php echo $index % 2 === 0 ? 'background: var(--nms-gray-50);' : ''; ?>">
									<td style="padding: 12px 15px;"><small><?php echo esc_html( human_time_diff( strtotime( $entry->created_at ), current_time( 'timestamp' ) ) ); ?> <?php _e( 'ago', 'nexifymy-security' ); ?></small></td>
									<td style="padding: 12px 15px;"><strong><?php echo esc_html( $entry->username ?: '—' ); ?></strong></td>
									<td style="padding: 12px 15px;">
										<span class="nms-badge <?php echo esc_attr( $badge_class ); ?>"><?php echo esc_html( ucwords( str_replace( '_', ' ', $entry->event_type ) ) ); ?></span>
									</td>
									<td style="padding: 12px 15px;"><?php echo esc_html( wp_trim_words( $entry->description, 8, '...' ) ); ?></td>
									<td style="padding: 12px 15px;"><code style="font-size: 11px;"><?php echo esc_html( $entry->ip_address ); ?></code></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php else : ?>
					<div style="padding: 40px; text-align: center; color: var(--nms-gray-500);">
						<span class="dashicons dashicons-clipboard" style="font-size: 48px; margin-bottom: 15px;"></span>
						<p><?php _e( 'No activity recorded yet. Activity will appear here once users start performing actions.', 'nexifymy-security' ); ?></p>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Login Activity content.
	 */
	private function render_activity_login_content() {
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-admin-users"></span> <?php _e( 'Login Activity', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<!-- Filters -->
				<div class="nms-filters" style="display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; align-items: flex-end;">
					<div>
						<label for="login-filter-username" style="display: block; margin-bottom: 5px; font-weight: 500;"><?php _e( 'Username', 'nexifymy-security' ); ?></label>
						<input type="text" id="login-filter-username" class="regular-text" placeholder="<?php _e( 'Search username...', 'nexifymy-security' ); ?>">
					</div>
					<div>
						<label for="login-filter-status" style="display: block; margin-bottom: 5px; font-weight: 500;"><?php _e( 'Status', 'nexifymy-security' ); ?></label>
						<select id="login-filter-status" class="regular-text">
							<option value=""><?php _e( 'All', 'nexifymy-security' ); ?></option>
							<option value="login_success"><?php _e( 'Successful Login', 'nexifymy-security' ); ?></option>
							<option value="login_failed"><?php _e( 'Failed Login', 'nexifymy-security' ); ?></option>
							<option value="logout"><?php _e( 'Logout', 'nexifymy-security' ); ?></option>
						</select>
					</div>
					<div>
						<label for="login-filter-date-from" style="display: block; margin-bottom: 5px; font-weight: 500;"><?php _e( 'From Date', 'nexifymy-security' ); ?></label>
						<input type="date" id="login-filter-date-from" class="regular-text">
					</div>
					<div>
						<label for="login-filter-date-to" style="display: block; margin-bottom: 5px; font-weight: 500;"><?php _e( 'To Date', 'nexifymy-security' ); ?></label>
						<input type="date" id="login-filter-date-to" class="regular-text">
					</div>
					<div>
						<button type="button" id="login-filter-apply" class="nms-btn nms-btn-primary">
							<span class="dashicons dashicons-search"></span> <?php _e( 'Filter', 'nexifymy-security' ); ?>
						</button>
						<button type="button" id="login-filter-reset" class="nms-btn nms-btn-secondary">
							<?php _e( 'Reset', 'nexifymy-security' ); ?>
						</button>
					</div>
				</div>

				<!-- Results Table -->
				<div id="login-activity-results">
					<?php $this->render_login_activity_table(); ?>
				</div>

				<!-- Export Buttons -->
				<div style="margin-top: 20px; display: flex; gap: 10px;">
					<button type="button" id="export-login-csv" class="nms-btn nms-btn-secondary">
						<span class="dashicons dashicons-download"></span> <?php _e( 'Export CSV', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render login activity table.
	 */
	private function render_login_activity_table() {
		$activity_log = new NexifyMy_Security_Activity_Log();
		$results = $activity_log->get_entries( array(
			'event_group' => 'authentication',
			'per_page'    => 25,
			'page'        => 1,
		) );
		?>
		<?php if ( ! empty( $results['entries'] ) ) : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php _e( 'Date/Time', 'nexifymy-security' ); ?></th>
						<th><?php _e( 'Username', 'nexifymy-security' ); ?></th>
						<th><?php _e( 'Status', 'nexifymy-security' ); ?></th>
						<th><?php _e( 'IP Address', 'nexifymy-security' ); ?></th>
						<th><?php _e( 'User Agent', 'nexifymy-security' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $results['entries'] as $entry ) : ?>
						<tr>
							<td><small><?php echo esc_html( $entry->created_at ); ?></small></td>
							<td><strong><?php echo esc_html( $entry->username ); ?></strong></td>
							<td>
								<?php
								$icon = 'yes-alt';
								$badge = 'nms-badge-success';
								$label = __( 'Login', 'nexifymy-security' );
								if ( $entry->event_type === 'login_failed' ) {
									$icon = 'warning';
									$badge = 'nms-badge-danger';
									$label = __( 'Failed', 'nexifymy-security' );
								} elseif ( $entry->event_type === 'logout' ) {
									$icon = 'migrate';
									$badge = 'nms-badge-secondary';
									$label = __( 'Logout', 'nexifymy-security' );
								}
								?>
								<span class="nms-badge <?php echo esc_attr( $badge ); ?>">
									<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span>
									<?php echo esc_html( $label ); ?>
								</span>
							</td>
							<td><code><?php echo esc_html( $entry->ip_address ); ?></code></td>
							<td><small title="<?php echo esc_attr( $entry->user_agent ); ?>"><?php echo esc_html( wp_trim_words( $entry->user_agent, 5, '...' ) ); ?></small></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<div style="margin-top: 15px; text-align: center;">
				<span class="description"><?php printf( __( 'Showing %d of %d entries', 'nexifymy-security' ), count( $results['entries'] ), $results['total'] ); ?></span>
			</div>
		<?php else : ?>
			<p class="description"><?php _e( 'No login activity recorded yet.', 'nexifymy-security' ); ?></p>
		<?php endif;
	}

	/**
	 * Render User Activity content.
	 */
	private function render_activity_users_content() {
		$activity_log = new NexifyMy_Security_Activity_Log();
		$results = $activity_log->get_entries( array(
			'event_group' => 'user',
			'per_page'    => 25,
			'page'        => 1,
		) );
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-groups"></span> <?php _e( 'User Activity', 'nexifymy-security' ); ?></h3>
				<p class="description"><?php _e( 'Profile changes, role changes, user creation, and deletion events.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-card-body">
				<?php if ( ! empty( $results['entries'] ) ) : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'Date/Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'User', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Event Type', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Description', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'IP Address', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $results['entries'] as $entry ) : ?>
								<tr>
									<td><small><?php echo esc_html( $entry->created_at ); ?></small></td>
									<td><strong><?php echo esc_html( $entry->username ); ?></strong></td>
									<td>
										<?php
										$badge = 'nms-badge-secondary';
										if ( $entry->event_type === 'role_change' ) {
											$badge = 'nms-badge-warning';
										} elseif ( $entry->event_type === 'user_deleted' ) {
											$badge = 'nms-badge-danger';
										} elseif ( $entry->event_type === 'user_created' ) {
											$badge = 'nms-badge-success';
										}
										?>
										<span class="nms-badge <?php echo esc_attr( $badge ); ?>"><?php echo esc_html( str_replace( '_', ' ', $entry->event_type ) ); ?></span>
									</td>
									<td><?php echo esc_html( $entry->description ); ?></td>
									<td><code><?php echo esc_html( $entry->ip_address ); ?></code></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<div style="margin-top: 15px; text-align: center;">
						<span class="description"><?php printf( __( 'Showing %d of %d entries', 'nexifymy-security' ), count( $results['entries'] ), $results['total'] ); ?></span>
					</div>
				<?php else : ?>
					<p class="description"><?php _e( 'No user activity recorded yet.', 'nexifymy-security' ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Content Changes content.
	 */
	private function render_activity_content_content() {
		$activity_log = new NexifyMy_Security_Activity_Log();
		$results = $activity_log->get_entries( array(
			'event_group' => 'content',
			'per_page'    => 25,
			'page'        => 1,
		) );
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-edit-page"></span> <?php _e( 'Content Changes', 'nexifymy-security' ); ?></h3>
				<p class="description"><?php _e( 'Post/page edits, publishing, media uploads, and content deletion.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-card-body">
				<?php if ( ! empty( $results['entries'] ) ) : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'Date/Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'User', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Action', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Content', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Description', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $results['entries'] as $entry ) : ?>
								<tr>
									<td><small><?php echo esc_html( $entry->created_at ); ?></small></td>
									<td><strong><?php echo esc_html( $entry->username ); ?></strong></td>
									<td>
										<?php
										$badge = 'nms-badge-secondary';
										if ( strpos( $entry->event_type, 'published' ) !== false ) {
											$badge = 'nms-badge-success';
										} elseif ( strpos( $entry->event_type, 'deleted' ) !== false || strpos( $entry->event_type, 'trashed' ) !== false ) {
											$badge = 'nms-badge-danger';
										} elseif ( strpos( $entry->event_type, 'updated' ) !== false ) {
											$badge = 'nms-badge-warning';
										}
										?>
										<span class="nms-badge <?php echo esc_attr( $badge ); ?>"><?php echo esc_html( str_replace( '_', ' ', $entry->event_type ) ); ?></span>
									</td>
									<td>
										<?php if ( $entry->object_name ) : ?>
											<strong><?php echo esc_html( $entry->object_name ); ?></strong>
											<small>(<?php echo esc_html( $entry->object_type ); ?>)</small>
										<?php else : ?>
											<span class="description">-</span>
										<?php endif; ?>
									</td>
									<td><small><?php echo esc_html( wp_trim_words( $entry->description, 10, '...' ) ); ?></small></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<div style="margin-top: 15px; text-align: center;">
						<span class="description"><?php printf( __( 'Showing %d of %d entries', 'nexifymy-security' ), count( $results['entries'] ), $results['total'] ); ?></span>
					</div>
				<?php else : ?>
					<p class="description"><?php _e( 'No content changes recorded yet.', 'nexifymy-security' ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render System Events content.
	 */
	private function render_activity_system_content() {
		$activity_log = new NexifyMy_Security_Activity_Log();
		$results = $activity_log->get_entries( array(
			'event_group' => 'system',
			'per_page'    => 25,
			'page'        => 1,
		) );
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'System Events', 'nexifymy-security' ); ?></h3>
				<p class="description"><?php _e( 'Plugin/theme activations, updates, option changes, and exports.', 'nexifymy-security' ); ?></p>
			</div>
			<div class="nms-card-body">
				<?php if ( ! empty( $results['entries'] ) ) : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php _e( 'Date/Time', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'User', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Event Type', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Object', 'nexifymy-security' ); ?></th>
								<th><?php _e( 'Description', 'nexifymy-security' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $results['entries'] as $entry ) : ?>
								<tr>
									<td><small><?php echo esc_html( $entry->created_at ); ?></small></td>
									<td><strong><?php echo esc_html( $entry->username ); ?></strong></td>
									<td>
										<?php
										$badge = 'nms-badge-secondary';
										if ( strpos( $entry->event_type, 'activated' ) !== false ) {
											$badge = 'nms-badge-success';
										} elseif ( strpos( $entry->event_type, 'deactivated' ) !== false || strpos( $entry->event_type, 'deleted' ) !== false ) {
											$badge = 'nms-badge-danger';
										} elseif ( strpos( $entry->event_type, 'updated' ) !== false ) {
											$badge = 'nms-badge-warning';
										}
										?>
										<span class="nms-badge <?php echo esc_attr( $badge ); ?>"><?php echo esc_html( str_replace( '_', ' ', $entry->event_type ) ); ?></span>
									</td>
									<td>
										<?php if ( $entry->object_name ) : ?>
											<code><?php echo esc_html( $entry->object_name ); ?></code>
										<?php else : ?>
											<span class="description">-</span>
										<?php endif; ?>
									</td>
									<td><small><?php echo esc_html( wp_trim_words( $entry->description, 8, '...' ) ); ?></small></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<div style="margin-top: 15px; text-align: center;">
						<span class="description"><?php printf( __( 'Showing %d of %d entries', 'nexifymy-security' ), count( $results['entries'] ), $results['total'] ); ?></span>
					</div>
				<?php else : ?>
					<p class="description"><?php _e( 'No system events recorded yet.', 'nexifymy-security' ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render Activity Log Settings content.
	 */
	private function render_activity_settings_content() {
		$settings = get_option( 'nexifymy_security_settings', array() );
		$activity_settings = isset( $settings['activity_log'] ) ? $settings['activity_log'] : array();
		
		$defaults = array(
			'enabled'             => true,
			'log_logins'          => true,
			'log_failed_logins'   => true,
			'log_logouts'         => true,
			'log_profile_changes' => true,
			'log_role_changes'    => true,
			'log_user_creation'   => true,
			'log_user_deletion'   => true,
			'log_password_changes'=> true,
			'log_post_changes'    => true,
			'log_page_changes'    => true,
			'log_media_uploads'   => true,
			'log_plugin_changes'  => true,
			'log_theme_changes'   => true,
			'log_option_changes'  => true,
			'retention_days'      => 90,
			'excluded_users'      => '',
		);
		$activity_settings = wp_parse_args( $activity_settings, $defaults );
		?>
		<div class="nms-card">
			<div class="nms-card-header">
				<h3><span class="dashicons dashicons-admin-settings"></span> <?php _e( 'Activity Log Settings', 'nexifymy-security' ); ?></h3>
			</div>
			<div class="nms-card-body">
				<table class="form-table">
					<tr>
						<th><?php _e( 'Enable Activity Logging', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-enabled" <?php checked( ! empty( $activity_settings['enabled'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
							<p class="description"><?php _e( 'Master switch to enable or disable all activity logging.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-users"></span> <?php _e( 'Authentication Events', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Log Successful Logins', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-logins" <?php checked( ! empty( $activity_settings['log_logins'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Failed Login Attempts', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-failed-logins" <?php checked( ! empty( $activity_settings['log_failed_logins'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Logouts', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-logouts" <?php checked( ! empty( $activity_settings['log_logouts'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-groups"></span> <?php _e( 'User Events', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Log Profile Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-profile" <?php checked( ! empty( $activity_settings['log_profile_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Role Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-roles" <?php checked( ! empty( $activity_settings['log_role_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log User Creation/Deletion', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-users" <?php checked( ! empty( $activity_settings['log_user_creation'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-edit-page"></span> <?php _e( 'Content Events', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Log Post/Page Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-posts" <?php checked( ! empty( $activity_settings['log_post_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Media Uploads', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-media" <?php checked( ! empty( $activity_settings['log_media_uploads'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-admin-generic"></span> <?php _e( 'System Events', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Log Plugin Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-plugins" <?php checked( ! empty( $activity_settings['log_plugin_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Theme Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-themes" <?php checked( ! empty( $activity_settings['log_theme_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Log Option Changes', 'nexifymy-security' ); ?></th>
						<td>
							<label class="nms-toggle">
								<input type="checkbox" id="activity-log-options" <?php checked( ! empty( $activity_settings['log_option_changes'] ) ); ?>>
								<span class="nms-toggle-slider"></span>
							</label>
						</td>
					</tr>
					<tr class="nms-form-section-header">
						<th colspan="2"><h4><span class="dashicons dashicons-database"></span> <?php _e( 'Data Retention', 'nexifymy-security' ); ?></h4></th>
					</tr>
					<tr>
						<th><?php _e( 'Retention Period', 'nexifymy-security' ); ?></th>
						<td>
							<input type="number" id="activity-log-retention" value="<?php echo intval( $activity_settings['retention_days'] ); ?>" min="7" max="365" class="small-text"> <?php _e( 'days', 'nexifymy-security' ); ?>
							<p class="description"><?php _e( 'Activity logs older than this will be automatically deleted.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php _e( 'Excluded Users', 'nexifymy-security' ); ?></th>
						<td>
							<textarea id="activity-log-excluded-users" class="large-text" rows="3" placeholder="<?php _e( 'One username per line', 'nexifymy-security' ); ?>"><?php echo esc_textarea( is_array( $activity_settings['excluded_users'] ) ? implode( "\n", $activity_settings['excluded_users'] ) : $activity_settings['excluded_users'] ); ?></textarea>
							<p class="description"><?php _e( 'Activity from these users will not be logged.', 'nexifymy-security' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit" style="display: flex; gap: 10px; align-items: center;">
					<button type="button" id="save-activity-log-settings" class="nms-btn nms-btn-primary"><?php _e( 'Save Settings', 'nexifymy-security' ); ?></button>
					<button type="button" id="purge-activity-log" class="nms-btn nms-btn-danger"><?php _e( 'Purge All Logs', 'nexifymy-security' ); ?></button>
					<span id="activity-log-status" style="margin-left: 15px;"></span>
				</p>
			</div>
		</div>
		<?php
	}
	/**
	 * Render the Analytics page.
	 */
	public function render_analytics_page() {
		?>
		<div class="wrap nexifymy-security-wrap">
			<div class="nms-header">
				<div class="nms-header-left">
					<div class="nms-logo">
						<span class="dashicons dashicons-chart-pie"></span>
					</div>
					<div class="nms-header-title">
						<h2><?php _e( 'Security Analytics', 'nexifymy-security' ); ?></h2>
						<p><?php _e( 'Detailed insights into your site traffic and security events', 'nexifymy-security' ); ?></p>
					</div>
				</div>
				<div class="nms-header-actions">
					<select id="analytics-range" class="nms-select">
						<option value="7"><?php _e( 'Last 7 Days', 'nexifymy-security' ); ?></option>
						<option value="30" selected><?php _e( 'Last 30 Days', 'nexifymy-security' ); ?></option>
						<option value="90"><?php _e( 'Last 90 Days', 'nexifymy-security' ); ?></option>
					</select>
					<button id="refresh-analytics" class="nms-btn nms-btn-secondary">
						<span class="dashicons dashicons-update"></span>
						<?php _e( 'Refresh', 'nexifymy-security' ); ?>
					</button>
				</div>
			</div>

			<div class="nms-main-content">
				
				<!-- Loading State -->
				<div id="analytics-loading" style="display: none; text-align: center; padding: 50px;">
					<span class="dashicons dashicons-update spin" style="font-size: 40px; width: 40px; height: 40px; color: var(--nms-primary);"></span>
					<p><?php _e( 'Loading analytics data...', 'nexifymy-security' ); ?></p>
				</div>

				<!-- Dashboard Content -->
				<div id="analytics-dashboard">
					
					<!-- Summary Cards -->
					<div class="nms-stats-row">
						<div class="nms-stat-card">
							<div class="nms-stat-icon blue">
								<span class="dashicons dashicons-visibility"></span>
							</div>
							<div class="nms-stat-content">
								<h4 id="stats-total-views">--</h4>
								<p><?php _e( 'Total Page Views', 'nexifymy-security' ); ?></p>
							</div>
						</div>
						<div class="nms-stat-card">
							<div class="nms-stat-icon purple">
								<span class="dashicons dashicons-groups"></span>
							</div>
							<div class="nms-stat-content">
								<h4 id="stats-unique-visitors">--</h4>
								<p><?php _e( 'Unique Visitors', 'nexifymy-security' ); ?></p>
							</div>
						</div>
						<div class="nms-stat-card">
							<div class="nms-stat-icon red">
								<span class="dashicons dashicons-shield"></span>
							</div>
							<div class="nms-stat-content">
								<h4 id="stats-blocked-requests">--</h4>
								<p><?php _e( 'Blocked Requests', 'nexifymy-security' ); ?></p>
							</div>
						</div>
						<div class="nms-stat-card">
							<div class="nms-stat-icon green">
								<span class="dashicons dashicons-admin-site-alt3"></span>
							</div>
							<div class="nms-stat-content">
								<h4 id="stats-top-country">--</h4>
								<p><?php _e( 'Top Country', 'nexifymy-security' ); ?></p>
							</div>
						</div>
					</div>

					<!-- Main Charts Row -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h3><?php _e( 'Traffic Overview', 'nexifymy-security' ); ?></h3>
						</div>
						<div class="nms-card-body">
							<div style="height: 300px; position: relative;">
								<canvas id="chart-traffic-overview"></canvas>
							</div>
						</div>
					</div>

					<!-- Secondary Charts Grid -->
					<div class="nms-grid-3" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px;">
						
						<!-- Browser Distribution -->
						<div class="nms-card" style="margin-bottom: 0;">
							<div class="nms-card-header">
								<h3><?php _e( 'Browsers', 'nexifymy-security' ); ?></h3>
							</div>
							<div class="nms-card-body">
								<div style="height: 250px; position: relative;">
									<canvas id="chart-browsers"></canvas>
								</div>
							</div>
						</div>

						<!-- OS Distribution -->
						<div class="nms-card" style="margin-bottom: 0;">
							<div class="nms-card-header">
								<h3><?php _e( 'Operating Systems', 'nexifymy-security' ); ?></h3>
							</div>
							<div class="nms-card-body">
								<div style="height: 250px; position: relative;">
									<canvas id="chart-os"></canvas>
								</div>
							</div>
						</div>

						<!-- Device Type -->
						<div class="nms-card" style="margin-bottom: 0;">
							<div class="nms-card-header">
								<h3><?php _e( 'Device Types', 'nexifymy-security' ); ?></h3>
							</div>
							<div class="nms-card-body">
								<div style="height: 250px; position: relative;">
									<canvas id="chart-devices"></canvas>
								</div>
							</div>
						</div>
					</div>

					<!-- Data Tables Grid -->
					<div class="nms-grid-2">
						
						<!-- Top Pages -->
						<div class="nms-card">
							<div class="nms-card-header">
								<h3><?php _e( 'Top Pages', 'nexifymy-security' ); ?></h3>
							</div>
							<div class="nms-card-body">
								<table class="widefat striped" id="table-top-pages">
									<thead>
										<tr>
											<th><?php _e( 'URL', 'nexifymy-security' ); ?></th>
											<th style="width: 80px; text-align: right;"><?php _e( 'Views', 'nexifymy-security' ); ?></th>
										</tr>
									</thead>
									<tbody>
										<tr><td colspan="2" class="loading-placeholder">-</td></tr>
									</tbody>
								</table>
							</div>
						</div>

						<!-- Top Referrers -->
						<div class="nms-card">
							<div class="nms-card-header">
								<h3><?php _e( 'Top Referrers', 'nexifymy-security' ); ?></h3>
							</div>
							<div class="nms-card-body">
								<table class="widefat striped" id="table-top-referrers">
									<thead>
										<tr>
											<th><?php _e( 'Source', 'nexifymy-security' ); ?></th>
											<th style="width: 80px; text-align: right;"><?php _e( 'Count', 'nexifymy-security' ); ?></th>
										</tr>
									</thead>
									<tbody>
										<tr><td colspan="2" class="loading-placeholder">-</td></tr>
									</tbody>
								</table>
							</div>
						</div>

					</div>

					<!-- Geo Distribution -->
					<div class="nms-card">
						<div class="nms-card-header">
							<h3><?php _e( 'Geographic Distribution', 'nexifymy-security' ); ?></h3>
						</div>
						<div class="nms-card-body">
							<div id="geo-map-container" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
								<div class="geo-table-wrapper">
									<table class="widefat striped" id="table-geo">
										<thead>
											<tr>
												<th><?php _e( 'Country', 'nexifymy-security' ); ?></th>
												<th><?php _e( 'Code', 'nexifymy-security' ); ?></th>
												<th style="text-align: right;"><?php _e( 'Visitors', 'nexifymy-security' ); ?></th>
											</tr>
										</thead>
										<tbody>
											<tr><td colspan="3" class="loading-placeholder">-</td></tr>
										</tbody>
									</table>
								</div>
								<div class="geo-chart-wrapper">
									<div style="height: 300px; position: relative;">
										<canvas id="chart-geo"></canvas>
									</div>
								</div>
							</div>
						</div>
					</div>

				</div>
			</div>
		</div>
		<?php
	}
}
