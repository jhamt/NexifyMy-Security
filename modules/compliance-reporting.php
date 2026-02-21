<?php
/**
 * Compliance & Reporting Module.
 * Generates automated security audit reports with PDF export.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class NexifyMy_Security_Compliance {
	/**
	 * Option key for report history.
	 */
	const REPORTS_OPTION = 'nexifymy_compliance_reports';

	/**
	 * Reports directory.
	 */
	const REPORTS_DIR = 'nexifymy-reports';

	/**
	 * Compliance report table suffix.
	*/
	const COMPLIANCE_REPORTS_TABLE = 'nexifymy_compliance_reports';

	/**
	 * GDPR request table suffix.
	*/
	const GDPR_REQUESTS_TABLE = 'nexifymy_gdpr_requests';
	/**
	 * Default settings.
	 */
	private static $defaults = array(
		'enabled'             => true,
		'auto_generate'       => true,
		'schedule'            => 'weekly',  // daily, weekly, monthly.
		'email_reports'       => true,
		'include_gdpr'        => true,
		'include_security'    => true,
		'include_performance' => true,
		'include_threats'     => true,
		'report_format'       => 'html',    // html, pdf.
		'retention_days'      => 90,
	);

	/**
	 * Compliance checks.
	 */
	private $compliance_checks = array();

	/**
	 * Initialize the module.
	 */
	public function init() {

		$this->define_compliance_checks();
		$this->maybe_create_tables();

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// Schedule automatic reports.
		if ( ! empty( $settings['auto_generate'] ) ) {
			add_action( 'nexifymy_generate_report', array( $this, 'generate_scheduled_report' ) );

			if ( ! wp_next_scheduled( 'nexifymy_generate_report' ) ) {
				$schedule = $settings['schedule'];
				wp_schedule_event( time(), $schedule, 'nexifymy_generate_report' );
			}
		}

		// Cleanup old reports.
		add_action( 'nexifymy_cleanup_reports', array( $this, 'cleanup_old_reports' ) );
		if ( ! wp_next_scheduled( 'nexifymy_cleanup_reports' ) ) {
			wp_schedule_event( time(), 'daily', 'nexifymy_cleanup_reports' );
		}

		// Keep GDPR Article 30 data flow record updated monthly.
		add_action( 'nexifymy_generate_data_map_report', array( $this, 'generate_scheduled_data_map_report' ) );
		if ( ! wp_next_scheduled( 'nexifymy_generate_data_map_report' ) ) {
			wp_schedule_event( time(), 'monthly', 'nexifymy_generate_data_map_report' );
		}

		// Register custom WordPress privacy eraser.
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_privacy_erasers' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_nexifymy_generate_report', array( $this, 'ajax_generate_report' ) );
		add_action( 'wp_ajax_nexifymy_get_reports', array( $this, 'ajax_get_reports' ) );
		add_action( 'wp_ajax_nexifymy_download_report', array( $this, 'ajax_download_report' ) );
		add_action( 'wp_ajax_nexifymy_run_compliance_check', array( $this, 'ajax_run_compliance_check' ) );
		add_action( 'wp_ajax_nexifymy_get_data_map', array( $this, 'ajax_get_data_map' ) );
		add_action( 'wp_ajax_nexifymy_export_data_map', array( $this, 'ajax_export_data_map' ) );
		add_action( 'wp_ajax_nexifymy_erase_user_data', array( $this, 'ajax_erase_user_data' ) );
		add_action( 'wp_ajax_nexifymy_verify_erasure', array( $this, 'ajax_verify_erasure' ) );
	}

	/**
	 * Create compliance-related database tables if needed.
	 *
	 * @return void
	 */
	public function maybe_create_tables() {

		global $wpdb;

		if ( empty( $wpdb ) || ! function_exists( 'dbDelta' ) ) {
			$upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
			if ( file_exists( $upgrade_file ) ) {
				require_once $upgrade_file;
			}
		}

		if ( empty( $wpdb ) || ! function_exists( 'dbDelta' ) ) {
			return;
		}

		$charset_collate = $wpdb->get_charset_collate();
		$reports_table   = $wpdb->prefix . self::COMPLIANCE_REPORTS_TABLE;
		$requests_table  = $wpdb->prefix . self::GDPR_REQUESTS_TABLE;

		$reports_sql = "CREATE TABLE IF NOT EXISTS {$reports_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			report_id varchar(64) NOT NULL,
			report_type varchar(32) NOT NULL DEFAULT 'security_audit',
			generated_at datetime NOT NULL,
			generated_by bigint(20) unsigned NOT NULL DEFAULT 0,
			summary_score smallint(5) unsigned DEFAULT 0,
			report_data longtext NOT NULL,
			file_path text NULL,
			PRIMARY KEY (id),
			KEY report_id (report_id),
			KEY report_type (report_type),
			KEY generated_at (generated_at)
		) {$charset_collate};";

		$requests_sql = "CREATE TABLE IF NOT EXISTS {$requests_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			request_type varchar(32) NOT NULL DEFAULT 'erasure',
			requested_at datetime NOT NULL,
			completed_at datetime NULL,
			completed_by bigint(20) unsigned NOT NULL DEFAULT 0,
			status varchar(32) NOT NULL DEFAULT 'pending',
			details longtext NULL,
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY request_type (request_type),
			KEY status (status),
			KEY requested_at (requested_at)
		) {$charset_collate};";

		dbDelta( $reports_sql );
		dbDelta( $requests_sql );
	}
	/**
	 * Get module settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$all_settings = NexifyMy_Security_Settings::get_all();
			if ( isset( $all_settings['compliance'] ) ) {
				return wp_parse_args( $all_settings['compliance'], self::$defaults );
			}
		}
		return self::$defaults;
	}

	/**
	 * Define compliance checks.
	 */
	private function define_compliance_checks() {
		$this->compliance_checks = array(
			// GDPR Compliance.
			'gdpr'     => array(
				'name'   => 'GDPR Compliance',
				'checks' => array(
					'ssl_enabled'      => array(
						'name'        => 'SSL/HTTPS Encryption',
						'description' => 'Data must be encrypted in transit.',
						'check'       => array( $this, 'check_ssl_enabled' ),
						'weight'      => 'critical',
					),
					'privacy_policy'   => array(
						'name'        => 'Privacy Policy Page',
						'description' => 'Site must have a privacy policy.',
						'check'       => array( $this, 'check_privacy_policy' ),
						'weight'      => 'critical',
					),
					'data_retention'   => array(
						'name'        => 'Log Retention Policy',
						'description' => 'Logs should be automatically purged.',
						'check'       => array( $this, 'check_log_retention' ),
						'weight'      => 'high',
					),
					'user_data_export' => array(
						'name'        => 'User Data Export',
						'description' => 'WordPress data export tools are available.',
						'check'       => array( $this, 'check_data_export' ),
						'weight'      => 'high',
					),
					'cookie_consent'   => array(
						'name'        => 'Cookie Consent',
						'description' => 'Cookie consent mechanism is recommended.',
						'check'       => array( $this, 'check_cookie_consent' ),
						'weight'      => 'medium',
					),
				),
			),

			// Security Posture.
			'security' => array(
				'name'   => 'Security Posture',
				'checks' => array(
					'firewall_enabled' => array(
						'name'        => 'Web Application Firewall',
						'description' => 'WAF should be active.',
						'check'       => array( $this, 'check_firewall_enabled' ),
						'weight'      => 'critical',
					),
					'2fa_available'    => array(
						'name'        => 'Two-Factor Authentication',
						'description' => '2FA should be available for users.',
						'check'       => array( $this, 'check_2fa_available' ),
						'weight'      => 'high',
					),
					'strong_passwords' => array(
						'name'        => 'Password Policy',
						'description' => 'Strong password requirements enforced.',
						'check'       => array( $this, 'check_password_policy' ),
						'weight'      => 'high',
					),
					'login_protection' => array(
						'name'        => 'Brute Force Protection',
						'description' => 'Rate limiting on login attempts.',
						'check'       => array( $this, 'check_login_protection' ),
						'weight'      => 'critical',
					),
					'file_integrity'   => array(
						'name'        => 'File Integrity Monitoring',
						'description' => 'Scanner checks for file changes.',
						'check'       => array( $this, 'check_file_integrity' ),
						'weight'      => 'high',
					),
					'updates_current'  => array(
						'name'        => 'Software Updates',
						'description' => 'WordPress core and plugins are up to date.',
						'check'       => array( $this, 'check_updates_current' ),
						'weight'      => 'critical',
					),
				),
			),

			// Access Control.
			'access'   => array(
				'name'   => 'Access Control',
				'checks' => array(
					'admin_users'          => array(
						'name'        => 'Administrator Accounts',
						'description' => 'Number of admin users should be minimal.',
						'check'       => array( $this, 'check_admin_users' ),
						'weight'      => 'medium',
					),
					'no_admin_username'    => array(
						'name'        => 'Default Username',
						'description' => 'No user with "admin" username.',
						'check'       => array( $this, 'check_no_admin_username' ),
						'weight'      => 'high',
					),
					'file_editor_disabled' => array(
						'name'        => 'File Editor Disabled',
						'description' => 'WordPress file editor is disabled.',
						'check'       => array( $this, 'check_file_editor_disabled' ),
						'weight'      => 'high',
					),
				),
			),

			// Data Protection.
			'data'     => array(
				'name'   => 'Data Protection',
				'checks' => array(
					'database_backups'  => array(
						'name'        => 'Database Backups',
						'description' => 'Regular database backups are scheduled.',
						'check'       => array( $this, 'check_database_backups' ),
						'weight'      => 'critical',
					),
					'db_prefix_changed' => array(
						'name'        => 'Database Prefix',
						'description' => 'Not using default wp_ prefix.',
						'check'       => array( $this, 'check_db_prefix' ),
						'weight'      => 'medium',
					),
				),
			),
		);
	}

	/*
	 * =========================================================================
	 * COMPLIANCE CHECKS
	 * =========================================================================
	 */

	private function check_ssl_enabled() {
		return is_ssl();
	}

	private function check_privacy_policy() {
		return (bool) get_option( 'wp_page_for_privacy_policy' );
	}

	private function check_log_retention() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['logging']['retention_days'] );
		}
		return false;
	}

	private function check_data_export() {
		// WordPress 4.9.6+ has data export tools.
		global $wp_version;
		return version_compare( $wp_version, '4.9.6', '>=' );
	}

	private function check_cookie_consent() {
		// Check for common cookie consent plugins.
		$cookie_plugins = array(
			'cookie-notice/cookie-notice.php',
			'cookie-law-info/cookie-law-info.php',
			'gdpr-cookie-consent/gdpr-cookie-consent.php',
		);

		foreach ( $cookie_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				return true;
			}
		}

		return false;
	}

	private function check_firewall_enabled() {

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
				return nexifymy_security_is_module_enabled( $settings, 'waf_enabled', true );
			}
			if ( isset( $settings['modules']['waf_enabled'] ) ) {
				return ! empty( $settings['modules']['waf_enabled'] );
			}
			return ! empty( $settings['waf']['enabled'] ) || ! empty( $settings['firewall']['enabled'] );
		}
		return false;
	}

	private function check_2fa_available() {

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
				return nexifymy_security_is_module_enabled( $settings, 'two_factor_enabled', true );
			}
			if ( isset( $settings['modules']['two_factor_enabled'] ) ) {
				return ! empty( $settings['modules']['two_factor_enabled'] );
			}
			return ! empty( $settings['two_factor']['enabled'] ) || ! empty( $settings['2fa']['enabled'] );
		}
		return false;
	}
	private function check_password_policy() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['password']['enabled'] );
		}
		return false;
	}

	private function check_login_protection() {

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
				return nexifymy_security_is_module_enabled( $settings, 'rate_limiter_enabled', true );
			}
			if ( isset( $settings['modules']['rate_limiter_enabled'] ) ) {
				return ! empty( $settings['modules']['rate_limiter_enabled'] );
			}
			return ! empty( $settings['rate_limiter']['enabled'] );
		}
		return false;
	}

	private function check_file_integrity() {

		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			if ( function_exists( 'nexifymy_security_is_module_enabled' ) ) {
				return nexifymy_security_is_module_enabled( $settings, 'scanner_enabled', true );
			}
			if ( isset( $settings['modules']['scanner_enabled'] ) ) {
				return ! empty( $settings['modules']['scanner_enabled'] );
			}
			return ! empty( $settings['scanner']['enabled'] );
		}
		return false;
	}
	private function check_updates_current() {
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$plugin_updates    = get_plugin_updates();
		$core              = get_preferred_from_update_core();
		$core_needs_update = $core && $core->response === 'upgrade';

		return empty( $plugin_updates ) && ! $core_needs_update;
	}

	private function check_admin_users() {
		$admins = get_users( array( 'role' => 'administrator' ) );
		return count( $admins ) <= 3;
	}

	private function check_no_admin_username() {
		return ! username_exists( 'admin' );
	}

	private function check_file_editor_disabled() {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	}

	private function check_database_backups() {
		if ( class_exists( 'NexifyMy_Security_Settings' ) ) {
			$settings = NexifyMy_Security_Settings::get_all();
			return ! empty( $settings['database']['backup_enabled'] );
		}
		return false;
	}

	private function check_db_prefix() {

		global $wpdb;
		return $wpdb->prefix !== 'wp_';
	}

	/**
	 * Escape an SQL identifier (table/column).
	 *
	 * @param string $identifier Identifier.
	 * @return string
	 */
	private function escape_identifier( $identifier ) {

		return '`' . str_replace( '`', '``', (string) $identifier ) . '`';
	}

	/**
	 * Check if a table exists.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function table_exists( $table_name ) {

		global $wpdb;

		$table_name = esc_sql( (string) $table_name );
		$query      = "SHOW TABLES LIKE '{$table_name}'";
		return $wpdb->get_var( $query ) === $table_name;
	}

	/**
	 * Determine whether column type can hold textual PII.
	 *
	 * @param string $column_type SQL column type.
	 * @return bool
	 */
	private function is_textual_column_type( $column_type ) {

		$type = strtolower( (string) $column_type );

		return false !== strpos( $type, 'char' )
			|| false !== strpos( $type, 'text' )
			|| false !== strpos( $type, 'blob' )
			|| false !== strpos( $type, 'json' )
			|| false !== strpos( $type, 'enum' )
			|| false !== strpos( $type, 'set' )
			|| false !== strpos( $type, 'binary' );
	}

	/**
	 * PII regex patterns for DB matching.
	 *
	 * @return array
	 */
	private function get_pii_patterns() {

		return array(
			'email'       => '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
			'phone'       => '[+]?[0-9][0-9\\-\\(\\)\\s\\.]{7,}',
			'credit_card' => '[0-9]{13,19}',
			'ssn'         => '[0-9]{3}-[0-9]{2}-[0-9]{4}',
			'ip_address'  => '([0-9]{1,3}\\.){3}[0-9]{1,3}',
		);
	}

	/**
	 * Infer likely PII types by column name.
	 *
	 * @param string $column_name Column name.
	 * @return string[]
	 */
	private function detect_pii_types_from_column( $column_name ) {

		$name = strtolower( (string) $column_name );

		$type_map = array(
			'email'       => array( 'email', 'e-mail' ),
			'name'        => array( 'name', 'first_name', 'last_name', 'display_name', 'full_name' ),
			'phone'       => array( 'phone', 'mobile', 'telephone' ),
			'address'     => array( 'address', 'street', 'city', 'state', 'zip', 'postcode', 'country' ),
			'ip_address'  => array( 'ip', 'ip_address', 'client_ip' ),
			'user_agent'  => array( 'user_agent', 'browser', 'device' ),
			'ssn'         => array( 'ssn', 'social_security' ),
			'credit_card' => array( 'credit_card', 'card_number', 'cc_' ),
		);

		$matches = array();

		foreach ( $type_map as $type => $keywords ) {
			foreach ( $keywords as $keyword ) {
				if ( false !== strpos( $name, $keyword ) ) {
					$matches[] = $type;
					break;
				}
			}
		}

		return array_values( array_unique( $matches ) );
	}

	/**
	 * Count matching rows for a specific PII type in a column.
	 *
	 * @param string $table Table name.
	 * @param string $column Column name.
	 * @param string $pii_type PII type.
	 * @return int
	 */
	private function count_pii_matches( $table, $column, $pii_type ) {

		global $wpdb;

		$table_sql  = $this->escape_identifier( $table );
		$column_sql = $this->escape_identifier( $column );
		$patterns   = $this->get_pii_patterns();
		$where_sql  = "{$column_sql} IS NOT NULL AND {$column_sql} <> ''";

		if ( isset( $patterns[ $pii_type ] ) ) {
			$pattern    = esc_sql( $patterns[ $pii_type ] );
			$where_sql .= " AND {$column_sql} REGEXP '{$pattern}'";
		}

		$query = "SELECT COUNT(*) FROM {$table_sql} WHERE {$where_sql}";
		return (int) $wpdb->get_var( $query );
	}

	/**
	 * Scan database tables for likely PII storage.
	 *
	 * @return array
	 */
	public function scan_for_pii() {

		global $wpdb;

		$tables  = $wpdb->get_col( 'SHOW TABLES' );
		$results = array();

		if ( empty( $tables ) ) {
			return $results;
		}

		foreach ( $tables as $table ) {
			$table_name = (string) $table;
			$columns    = $wpdb->get_results( 'DESCRIBE ' . $this->escape_identifier( $table_name ), ARRAY_A );

			if ( empty( $columns ) ) {
				continue;
			}

			$table_results = array();

			foreach ( $columns as $column ) {
				$column_name = (string) ( $column['Field'] ?? '' );
				$column_type = (string) ( $column['Type'] ?? '' );

				if ( '' === $column_name || ! $this->is_textual_column_type( $column_type ) ) {
					continue;
				}

				$likely_types = $this->detect_pii_types_from_column( $column_name );
				if ( empty( $likely_types ) ) {
					continue;
				}

				$column_hits = array();
				foreach ( $likely_types as $pii_type ) {
					$count = $this->count_pii_matches( $table_name, $column_name, $pii_type );
					if ( $count > 0 ) {
						$column_hits[ $pii_type ] = $count;
					}
				}

				if ( ! empty( $column_hits ) ) {
						$table_results[ $column_name ] = $column_hits;
				}
			}

			if ( ! empty( $table_results ) ) {
				$results[ $table_name ] = $table_results;
			}
		}

		return $results;
	}

	/**
	 * Discover third-party services from options/settings.
	 *
	 * @return array
	 */
	private function discover_third_party_services() {

		global $wpdb;

		$services = array();
		$matches  = array(
			'google'    => 'Google Analytics',
			'ga_'       => 'Google Analytics',
			'g_tag'     => 'Google Analytics',
			'stripe'    => 'Stripe',
			'mailchimp' => 'Mailchimp',
			'facebook'  => 'Meta/Facebook',
			'hubspot'   => 'HubSpot',
			'segment'   => 'Segment',
		);

		$options_table = $wpdb->prefix . 'options';

		if ( $this->table_exists( $options_table ) ) {
			foreach ( $matches as $needle => $label ) {
				$needle_sql = esc_sql( $needle );
				$query      = "SELECT option_name FROM {$this->escape_identifier( $options_table )}
					WHERE option_name LIKE '%{$needle_sql}%'
					LIMIT 20";
				$rows       = $wpdb->get_results( $query, ARRAY_A );

				if ( ! empty( $rows ) ) {
					$services[ $label ] = $label;
				}
			}
		}

		$settings   = get_option( 'nexifymy_security_settings', array() );
		$serialized = function_exists( 'maybe_serialize' ) ? maybe_serialize( $settings ) : serialize( $settings );
		foreach ( $matches as $needle => $label ) {
			if ( false !== stripos( (string) $serialized, $needle ) ) {
				$services[ $label ] = $label;
			}
		}

		return array_values( $services );
	}

	/**
	 * Collect external script domains captured by Supply Chain module.
	 *
	 * @return array
	 */
	private function collect_external_script_domains() {

		$domains = array();

		if ( isset( $GLOBALS['nexifymy_supply_chain'] ) && method_exists( $GLOBALS['nexifymy_supply_chain'], 'get_cached_external_scripts' ) ) {
			$external = $GLOBALS['nexifymy_supply_chain']->get_cached_external_scripts();
			$scripts  = array_merge( $external['verified'] ?? array(), $external['unverified'] ?? array() );
			foreach ( $scripts as $script ) {
				if ( ! empty( $script['host'] ) ) {
					$domains[ $script['host'] ] = $script['host'];
				}
			}
		}

		if ( empty( $domains ) ) {
			$scripts = get_transient( 'nexifymy_external_scripts' );
			if ( is_array( $scripts ) ) {
				foreach ( $scripts as $script ) {
					if ( ! empty( $script['host'] ) ) {
						$domains[ $script['host'] ] = $script['host'];
					}
				}
			}
		}

		return array_values( $domains );
	}

	/**
	 * Discover registered REST API routes.
	 *
	 * @return array
	 */
	private function discover_rest_endpoints() {

		$endpoints = array();

		if ( function_exists( 'rest_get_server' ) ) {
			$server = rest_get_server();
			if ( $server && method_exists( $server, 'get_routes' ) ) {
				$routes    = array_keys( (array) $server->get_routes() );
				$endpoints = array_slice( $routes, 0, 300 );
			}
		}

		return $endpoints;
	}

	/**
	 * Map a table/column to likely processing purpose.
	 *
	 * @param string $table Table name.
	 * @param string $column Column name.
	 * @return string
	 */
	private function map_location_purpose( $table, $column ) {

		$location = strtolower( $table . '.' . $column );

		if ( false !== strpos( $location, 'users' ) || false !== strpos( $location, 'usermeta' ) ) {
				return 'User authentication and account management';
		}
		if ( false !== strpos( $location, 'comment' ) ) {
			return 'Comment moderation and anti-spam analysis';
		}
		if ( false !== strpos( $location, 'order' ) || false !== strpos( $location, 'woocommerce' ) ) {
			return 'Order fulfillment and financial record keeping';
		}
		if ( false !== strpos( $location, 'log' ) || false !== strpos( $location, 'traffic' ) ) {
			return 'Security monitoring, fraud detection, and incident response';
		}
		if ( false !== strpos( $location, 'newsletter' ) || false !== strpos( $location, 'mailchimp' ) ) {
			return 'Marketing communications';
		}

		return 'Operational website processing';
	}

	/**
	 * Map data location to likely retention policy.
	 *
	 * @param string $table Table name.
	 * @param string $column Column name.
	 * @return string
	 */
	private function map_retention_policy( $table, $column ) {

		$location = strtolower( $table . '.' . $column );

		if ( false !== strpos( $location, 'log' ) || false !== strpos( $location, 'traffic' ) ) {
			return '30 days';
		}
		if ( false !== strpos( $location, 'comment' ) ) {
			return 'Indefinite (unless user requests erasure)';
		}
		if ( false !== strpos( $location, 'order' ) || false !== strpos( $location, 'woocommerce' ) ) {
			return '7 years (tax/accounting obligations)';
		}

		return 'Indefinite';
	}

	/**
	 * Map PII type to default legal basis.
	 *
	 * @param string $pii_type PII type.
	 * @return string
	 */
	private function map_legal_basis( $pii_type ) {

		switch ( $pii_type ) {
			case 'email':
			case 'name':
				return 'Contract';
			case 'ip_address':
			case 'user_agent':
				return 'Legitimate interest';
			case 'phone':
			case 'address':
			case 'credit_card':
				return 'Contract';
			default:
				return 'Consent';
		}
	}

	/**
	 * Build a structured map of data storage/transmission/logging flows.
	 *
	 * @return array
	 */
	public function map_data_flows() {

		global $wpdb;

		$pii_storage          = $this->scan_for_pii();
		$third_party_services = $this->discover_third_party_services();
		$external_domains     = $this->collect_external_script_domains();
		$rest_endpoints       = $this->discover_rest_endpoints();

		$logged_locations = array(
			'Activity logs' => $this->table_exists( $wpdb->prefix . 'nexifymy_activity_log' ),
			'Behavior logs' => $this->table_exists( $wpdb->prefix . 'nexifymy_behavior_log' ),
			'Threat logs'   => $this->table_exists( $wpdb->prefix . 'nexifymy_threat_log' ),
		);

		return array(
			'generated_at'          => current_time( 'mysql' ),
			'stored'                => $pii_storage,
			'transmitted'           => array(
				'rest_endpoints'          => $rest_endpoints,
				'email_transmissions'     => array( 'wp_mail', 'admin alerts', 'scheduled reports' ),
				'third_party_services'    => $third_party_services,
				'external_script_domains' => $external_domains,
			),
			'logged'                => array_filter( $logged_locations ),
			'cross_border_transfer' => array(
				'detected' => ! empty( $third_party_services ) || ! empty( $external_domains ),
				'note'     => ( ! empty( $third_party_services ) || ! empty( $external_domains ) )
				? 'Review SCC/DPA terms for third-party processors and CDNs.'
					: 'No obvious cross-border processors detected from plugin telemetry.',
			),
		);
	}

	/**
	 * Generate GDPR Article 30 style data map report.
	 *
	 * @param string $format array|json|html.
	 * @return array|string
	 */
	public function generate_data_map_report( $format = 'array' ) {

		$data_flows = $this->map_data_flows();
		$stored     = $data_flows['stored'] ?? array();
		$sharing    = $data_flows['transmitted']['third_party_services'] ?? array();

		$records_by_type = array();

		foreach ( $stored as $table => $columns ) {
			foreach ( $columns as $column => $types ) {
				foreach ( $types as $pii_type => $count ) {
					if ( ! isset( $records_by_type[ $pii_type ] ) ) {
						$records_by_type[ $pii_type ] = array(
							'data_element'        => ucwords( str_replace( '_', ' ', $pii_type ) ),
							'location'            => array(),
							'purpose'             => array(),
							'retention'           => array(),
							'third_party_sharing' => array(),
							'legal_basis'         => $this->map_legal_basis( $pii_type ),
							'rows_detected'       => 0,
						);
					}

					$records_by_type[ $pii_type ]['location'][]          = $table . '.' . $column;
					$records_by_type[ $pii_type ]['purpose'][]           = $this->map_location_purpose( $table, $column );
					$records_by_type[ $pii_type ]['retention'][]         = $this->map_retention_policy( $table, $column );
					$records_by_type[ $pii_type ]['rows_detected']      += (int) $count;
					$records_by_type[ $pii_type ]['third_party_sharing'] = array_values( array_unique( $sharing ) );
				}
			}
		}

		$records = array();
		foreach ( $records_by_type as $type => $row ) {
			$records[] = array(
				'pii_type'            => $type,
				'data_element'        => $row['data_element'],
				'location'            => implode( ', ', array_unique( $row['location'] ) ),
				'purpose'             => implode( '; ', array_unique( $row['purpose'] ) ),
				'retention'           => implode( '; ', array_unique( $row['retention'] ) ),
				'third_party_sharing' => empty( $row['third_party_sharing'] ) ? 'None detected' : implode( ', ', $row['third_party_sharing'] ),
				'legal_basis'         => $row['legal_basis'],
				'rows_detected'       => (int) $row['rows_detected'],
			);
		}

		$report = array(
			'report_id'    => uniqid( 'data_map_' ),
			'generated_at' => current_time( 'mysql' ),
			'article_30'   => true,
			'site_url'     => home_url(),
			'flows'        => $data_flows,
			'records'      => $records,
		);

		if ( 'json' === $format ) {
			return wp_json_encode( $report );
		}
		if ( 'html' === $format ) {
			return $this->render_data_map_html( $report );
		}

		return $report;
	}

	/**
	 * Render data map as HTML.
	 *
	 * @param array $data_map Data map payload.
	 * @return string
	 */
	private function render_data_map_html( $data_map ) {

		ob_start();
		?>
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>GDPR Data Map Report</title>
			<style>
				body{font-family:Arial,sans-serif;color:#1f2937;padding:20px}
				table{width:100%;border-collapse:collapse}
				th,td{border:1px solid #d1d5db;padding:10px;vertical-align:top}
				th{background:#f3f4f6;text-align:left}
				.meta{margin-bottom:18px}
			</style>
		</head>
		<body>
			<h1>GDPR Article 30 Data Map</h1>
			<div class="meta">
				<p><strong>Generated:</strong> <?php echo esc_html( $data_map['generated_at'] ?? '' ); ?></p>
				<p><strong>Site:</strong> <?php echo esc_html( $data_map['site_url'] ?? '' ); ?></p>
				<p><strong>Report ID:</strong> <?php echo esc_html( $data_map['report_id'] ?? '' ); ?></p>
			</div>
			<table>
				<thead>
					<tr>
						<th>Data Element</th>
						<th>Location</th>
						<th>Purpose</th>
						<th>Retention</th>
						<th>Third-Party Sharing</th>
						<th>Legal Basis</th>
					</tr>
				</thead>
				<tbody>
				<?php
				if ( ! empty( $data_map['records'] ) ) :
					?>
					<?php
					foreach ( $data_map['records'] as $record ) :
						?>
						<tr>
							<td><?php echo esc_html( $record['data_element'] ?? '' ); ?></td>
							<td><?php echo esc_html( $record['location'] ?? '' ); ?></td>
							<td><?php echo esc_html( $record['purpose'] ?? '' ); ?></td>
							<td><?php echo esc_html( $record['retention'] ?? '' ); ?></td>
							<td><?php echo esc_html( $record['third_party_sharing'] ?? '' ); ?></td>
							<td><?php echo esc_html( $record['legal_basis'] ?? '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					<?php
				else :
					?>
					<tr>
						<td colspan="6">No PII records detected.</td>
					</tr>
				<?php endif; ?>
				</tbody>
			</table>
		</body>
		</html>
		<?php

		return (string) ob_get_clean();
	}

	/**
	 * Export the current data map to file.
	 *
	 * @param string $format json|html|pdf.
	 * @return array
	 */
	public function export_data_map_report( $format = 'pdf' ) {

		$data_map    = $this->generate_data_map_report( 'array' );
		$reports_dir = $this->get_reports_directory();

		if ( ! $this->ensure_reports_directory_security( $reports_dir ) ) {
			return array(
				'format'   => $format,
				'file'     => '',
				'url'      => '',
				'mime'     => 'text/html',
				'fallback' => false,
				'error'    => 'Unable to prepare reports directory.',
			);
		}

		$result    = array(
			'format'   => $format,
			'file'     => '',
			'url'      => '',
			'mime'     => 'text/html',
			'fallback' => false,
		);

		if ( 'json' === $format ) {
			$filename = $this->generate_secure_report_filename( 'gdpr-data-map', 'json' );
			$filepath = trailingslashit( $reports_dir ) . $filename;
			file_put_contents( $filepath, wp_json_encode( $data_map, JSON_PRETTY_PRINT ) );
			$result['file'] = $filepath;
			$result['url']  = $this->build_authenticated_report_url( array( 'filename' => $filename ) );
			$result['mime'] = 'application/json';
		} else {
			$html     = $this->render_data_map_html( $data_map );
			$filename = $this->generate_secure_report_filename( 'gdpr-data-map', 'html' );
			$filepath = trailingslashit( $reports_dir ) . $filename;
			file_put_contents( $filepath, $html );

			$result['file'] = $filepath;
			$result['url']  = $this->build_authenticated_report_url( array( 'filename' => $filename ) );
			$result['mime'] = 'text/html';

			if ( 'pdf' === $format ) {
				$result['fallback'] = true;
				$result['format']   = 'html';
			}
		}

		$this->save_structured_report( $data_map['report_id'], 'data_map', $data_map, 0, $result['file'] );

		return $result;
	}

	/**
	 * Save structured report payload into compliance table.
	 *
	 * @param string $report_id Report ID.
	 * @param string $report_type Report type.
	 * @param array  $data Report payload.
	 * @param int    $score Optional score.
	 * @param string $file_path Optional file path.
	 * @return void
	 */
	private function save_structured_report( $report_id, $report_type, $data, $score = 0, $file_path = '' ) {

		global $wpdb;

		$table_name = $wpdb->prefix . self::COMPLIANCE_REPORTS_TABLE;
		if ( ! $this->table_exists( $table_name ) ) {
			return;
		}

		$wpdb->insert(
			$table_name,
			array(
				'report_id'     => (string) $report_id,
				'report_type'   => (string) $report_type,
				'generated_at'  => current_time( 'mysql' ),
				'generated_by'  => get_current_user_id(),
				'summary_score' => (int) $score,
				'report_data'   => wp_json_encode( $data ),
				'file_path'     => (string) $file_path,
			)
		);
	}

	/**
	 * Generate scheduled data map report (monthly).
	 *
	 * @return void
	 */
	public function generate_scheduled_data_map_report() {

		$data_map = $this->generate_data_map_report( 'array' );
		$this->save_structured_report( $data_map['report_id'], 'data_map', $data_map );
	}

	/**
	 * Register custom GDPR eraser in WP privacy tools.
	 *
	 * @param array $erasers Eraser callbacks.
	 * @return array
	 */
	public function register_privacy_erasers( $erasers ) {

		$erasers['nexifymy_security_logs_eraser'] = array(
			'eraser_friendly_name' => __( 'NexifyMy Security Logs', 'nexifymy-security' ),
			'callback'             => array( $this, 'nexifymy_security_logs_eraser' ),
		);

		return $erasers;
	}

	/**
	 * WP privacy eraser callback.
	 *
	 * @param string $email_address User email.
	 * @param int    $page Page number.
	 * @return array
	 */
	public function nexifymy_security_logs_eraser( $email_address, $page = 1 ) {

		$user_id = $this->resolve_user_by_email( $email_address );
		if ( $user_id <= 0 ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array( __( 'No matching user found.', 'nexifymy-security' ) ),
				'done'           => true,
			);
		}

		$result = $this->erase_user_data( $user_id, true );

		return array(
			'items_removed'  => ! empty( $result['success'] ),
			'items_retained' => false,
			'messages'       => array( __( 'Security logs and related PII were anonymized.', 'nexifymy-security' ) ),
			'done'           => true,
		);
	}

	/**
	 * Resolve user ID from email.
	 *
	 * @param string $email_address Email.
	 * @return int
	 */
	private function resolve_user_by_email( $email_address ) {

		$user = function_exists( 'get_user_by' ) ? get_user_by( 'email', $email_address ) : null;
		if ( $user && ! empty( $user->ID ) ) {
			return (int) $user->ID;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'users';
		if ( ! $this->table_exists( $table ) ) {
			return 0;
		}

		$email = esc_sql( sanitize_email( $email_address ) );
		$query = "SELECT ID FROM {$this->escape_identifier( $table )} WHERE user_email = '{$email}' LIMIT 1";
		return (int) $wpdb->get_var( $query );
	}

	/**
	 * Erase/anonymize user data across core/plugin tables.
	 *
	 * @param int  $user_id User ID.
	 * @param bool $include_comments Delete comments when true.
	 * @return array
	 */
	public function erase_user_data( $user_id, $include_comments = false ) {

		global $wpdb;

		$user_id = absint( $user_id );
		if ( $user_id <= 0 ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid user ID.', 'nexifymy-security' ),
			);
		}

		$users_table    = $wpdb->prefix . 'users';
		$usermeta_table = $wpdb->prefix . 'usermeta';
		$comments_table = $wpdb->prefix . 'comments';
		$activity_table = $wpdb->prefix . 'nexifymy_activity_log';
		$threat_table   = $wpdb->prefix . 'nexifymy_threat_log';

		$placeholder_email = 'user' . $user_id . '@deleted.local';
		$placeholder_name  = 'Deleted User #' . $user_id;
		$deleted_ip        = '0.0.0.0';

		$original_email = '';
		if ( $this->table_exists( $users_table ) ) {
			$original_email = (string) $wpdb->get_var(
				"SELECT user_email FROM {$this->escape_identifier( $users_table )} WHERE ID = {$user_id} LIMIT 1"
			);
		}

		if ( $this->table_exists( $users_table ) ) {
				$wpdb->query(
					"UPDATE {$this->escape_identifier( $users_table )}
				SET user_email = '" . esc_sql( $placeholder_email ) . "',
					user_login = '" . esc_sql( 'deleted_user_' . $user_id ) . "',
					display_name = '" . esc_sql( $placeholder_name ) . "',
					user_nicename = '" . esc_sql( 'deleted-user-' . $user_id ) . "',
					user_url = ''
				WHERE ID = {$user_id}"
				);
		}

		if ( $this->table_exists( $usermeta_table ) ) {
			$wpdb->query(
				"UPDATE {$this->escape_identifier( $usermeta_table )}
				SET meta_value = ''
				WHERE user_id = {$user_id}
					AND meta_key REGEXP 'first_name|last_name|nickname|description|billing_|shipping_|phone|address'"
			);
		}

		if ( $this->table_exists( $comments_table ) ) {
			if ( $include_comments ) {
				$wpdb->query(
					"DELETE FROM {$this->escape_identifier( $comments_table )} WHERE user_id = {$user_id}"
				);
			} else {
					$wpdb->query(
						"UPDATE {$this->escape_identifier( $comments_table )}
					SET comment_author = '" . esc_sql( $placeholder_name ) . "',
						comment_author_email = '" . esc_sql( $placeholder_email ) . "',
						comment_author_IP = '" . esc_sql( $deleted_ip ) . "',
						comment_author_url = ''
					WHERE user_id = {$user_id}"
					);
			}
		}

		if ( $this->table_exists( $activity_table ) ) {
			$wpdb->query(
				"UPDATE {$this->escape_identifier( $activity_table )}
				SET ip_address = '" . esc_sql( $deleted_ip ) . "',
					user_agent = 'deleted',
					details = REPLACE(details, '" . esc_sql( $original_email ) . "', '" . esc_sql( $placeholder_email ) . "')
				WHERE user_id = {$user_id}"
			);
		}

		if ( $this->table_exists( $threat_table ) ) {
			$wpdb->query(
				"UPDATE {$this->escape_identifier( $threat_table )}
				SET ip_address = '" . esc_sql( $deleted_ip ) . "',
					user_agent = 'deleted'
				WHERE user_id = {$user_id}"
			);
		}

		$this->anonymize_woocommerce_data( $user_id, $placeholder_email, $placeholder_name );
		update_option( 'nexifymy_backup_exclusions_pending', true, false );

		$verification = $this->verify_erasure( $user_id );
		$certificate  = $this->generate_erasure_certificate( $user_id, $verification );
		$third_party  = array();

		if ( ! empty( $original_email ) ) {
			foreach ( array( 'mailchimp', 'google_analytics', 'stripe' ) as $service ) {
				$third_party[ $service ] = $this->request_third_party_erasure( $original_email, $service );
			}
		}

		$this->log_gdpr_request(
			$user_id,
			'erasure',
			'completed',
			array(
				'include_comments' => (bool) $include_comments,
				'verification'     => $verification,
				'certificate'      => $certificate,
				'third_party'      => $third_party,
			),
			get_current_user_id()
		);

		if ( ! empty( $original_email ) ) {
			$this->notify_erasure_completion( $original_email, $certificate );
		}

		return array(
			'success'      => true,
			'user_id'      => $user_id,
			'verification' => $verification,
			'certificate'  => $certificate,
		);
	}

	/**
	 * Anonymize common WooCommerce user fields.
	 *
	 * @param int    $user_id User ID.
	 * @param string $placeholder_email Placeholder email.
	 * @param string $placeholder_name Placeholder name.
	 * @return void
	 */
	private function anonymize_woocommerce_data( $user_id, $placeholder_email, $placeholder_name ) {

		global $wpdb;

		$user_id        = absint( $user_id );
		$postmeta_table = $wpdb->prefix . 'postmeta';
		$posts_table    = $wpdb->prefix . 'posts';

		if ( ! $this->table_exists( $postmeta_table ) || ! $this->table_exists( $posts_table ) ) {
			return;
		}

		$placeholder_email = esc_sql( $placeholder_email );
		$placeholder_name  = esc_sql( $placeholder_name );
		$postmeta_sql      = $this->escape_identifier( $postmeta_table );
		$posts_sql         = $this->escape_identifier( $posts_table );

		$wpdb->query(
			"UPDATE {$postmeta_sql}
			SET meta_value = '{$placeholder_email}'
			WHERE meta_key IN ('_billing_email')
				AND post_id IN (
					SELECT ID FROM {$posts_sql}
					WHERE post_type = 'shop_order' AND post_author = {$user_id}
				)"
		);

		$wpdb->query(
			"UPDATE {$postmeta_sql}
			SET meta_value = '{$placeholder_name}'
			WHERE meta_key IN ('_billing_first_name', '_billing_last_name', '_shipping_first_name', '_shipping_last_name')
				AND post_id IN (
					SELECT ID FROM {$posts_sql}
					WHERE post_type = 'shop_order' AND post_author = {$user_id}
				)"
		);
	}

	/**
	 * Request erasure from third-party service.
	 *
	 * @param string $user_email User email.
	 * @param string $service Service key.
	 * @return array
	 */
	public function request_third_party_erasure( $user_email, $service ) {

		$service  = sanitize_key( $service );
		$email    = sanitize_email( $user_email );
		$settings = $this->get_integrations_settings();

		$result = array(
			'service' => $service,
			'email'   => $email,
			'status'  => 'queued',
			'message' => __( 'Manual or webhook-based erasure request queued.', 'nexifymy-security' ),
		);

		if ( 'mailchimp' === $service && ! empty( $settings['mailchimp_api_key'] ) && ! empty( $settings['mailchimp_audience_id'] ) ) {
			$dc = '';
			if ( false !== strpos( $settings['mailchimp_api_key'], '-' ) ) {
				$parts = explode( '-', $settings['mailchimp_api_key'] );
				$dc    = end( $parts );
			}

			if ( ! empty( $dc ) ) {
				$subscriber_hash = md5( strtolower( $email ) );
				$url             = sprintf(
					'https://%s.api.mailchimp.com/3.0/lists/%s/members/%s/actions/delete-permanent',
					rawurlencode( $dc ),
					rawurlencode( $settings['mailchimp_audience_id'] ),
					rawurlencode( $subscriber_hash )
				);

					wp_remote_post(
						$url,
						array(
							'timeout' => 15,
							'headers' => array(
								'Authorization' => 'apikey ' . $settings['mailchimp_api_key'],
							),
						)
					);

					$result['status'] = 'requested';
				$result['message']    = __( 'Mailchimp deletion request sent.', 'nexifymy-security' );
			}
		} elseif ( 'stripe' === $service && ! empty( $settings['stripe_secret_key'] ) ) {
					// Stripe does not support hard customer deletion for all records; this request is logged for manual follow-up.
			$result['status']          = 'manual_review';
					$result['message'] = __( 'Stripe erasure requires manual API follow-up for compliance records.', 'nexifymy-security' );
		} elseif ( 'google_analytics' === $service ) {
			$result['status']  = 'manual_review';
			$result['message'] = __( 'Google Analytics user deletion API request must be configured externally.', 'nexifymy-security' );
		}

		do_action( 'nexifymy_third_party_erasure_request', $email, $service, $result );

		return $result;
	}

	/**
	 * Pull integrations settings.
	 *
	 * @return array
	 */
	private function get_integrations_settings() {

		$settings = get_option( 'nexifymy_security_settings', array() );
		return isset( $settings['integrations'] ) && is_array( $settings['integrations'] )
		? $settings['integrations']
			: array();
	}

	/**
	 * Verify user erasure across core/plugin data stores.
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public function verify_erasure( $user_id ) {

		global $wpdb;

		$user_id    = absint( $user_id );
		$user_table = $wpdb->prefix . 'users';
		$user_email = '';

		if ( $this->table_exists( $user_table ) ) {
			$user_email = (string) $wpdb->get_var(
				"SELECT user_email FROM {$this->escape_identifier( $user_table )} WHERE ID = {$user_id} LIMIT 1"
			);
		}

		$checks = array(
			'users_table_anonymized' => ( false !== strpos( $user_email, '@deleted.local' ) ),
			'activity_log_entries'   => 0,
			'threat_log_entries'     => 0,
			'comment_pii_remaining'  => 0,
		);

		$activity_table = $wpdb->prefix . 'nexifymy_activity_log';
		if ( $this->table_exists( $activity_table ) ) {
			$checks['activity_log_entries'] = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$this->escape_identifier( $activity_table )} WHERE user_id = {$user_id}"
			);
		}

		$threat_table = $wpdb->prefix . 'nexifymy_threat_log';
		if ( $this->table_exists( $threat_table ) ) {
			$checks['threat_log_entries'] = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$this->escape_identifier( $threat_table )} WHERE user_id = {$user_id}"
			);
		}

		$comments_table = $wpdb->prefix . 'comments';
		if ( $this->table_exists( $comments_table ) ) {
			$checks['comment_pii_remaining'] = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$this->escape_identifier( $comments_table )}
				WHERE user_id = {$user_id} AND comment_author_email NOT LIKE '%@deleted.local'"
			);
		}

		$is_clean = ! empty( $checks['users_table_anonymized'] )
			&& 0 === (int) $checks['comment_pii_remaining'];

		return array(
			'user_id'     => $user_id,
			'verified_at' => current_time( 'mysql' ),
			'is_clean'    => $is_clean,
			'checks'      => $checks,
		);
	}

	/**
	 * Generate erasure certificate file.
	 *
	 * @param int   $user_id User ID.
	 * @param array $verification Verification details.
	 * @return string
	 */
	private function generate_erasure_certificate( $user_id, $verification ) {

		$reports_dir = $this->get_reports_directory();
		if ( ! $this->ensure_reports_directory_security( $reports_dir ) ) {
			return '';
		}

		$filename = $this->generate_secure_report_filename( 'gdpr-erasure-certificate-' . absint( $user_id ), 'html' );
		$filepath = trailingslashit( $reports_dir ) . $filename;

		ob_start();
		?>
		<!DOCTYPE html>
		<html lang="en">
		<head><meta charset="UTF-8"><title>GDPR Erasure Certificate</title></head>
		<body>
			<h1>GDPR Erasure Certificate</h1>
			<p><strong>User ID:</strong> <?php echo esc_html( $user_id ); ?></p>
			<p><strong>Completed:</strong> <?php echo esc_html( $verification['verified_at'] ?? '' ); ?></p>
			<p><strong>Status:</strong> <?php echo ! empty( $verification['is_clean'] ) ? 'Verified' : 'Pending Review'; ?></p>
			<pre><?php echo esc_html( wp_json_encode( $verification['checks'] ?? array(), JSON_PRETTY_PRINT ) ); ?></pre>
		</body>
		</html>
		
		<?php
		file_put_contents( $filepath, (string) ob_get_clean() );

		return $filepath;
	}

	/**
	 * Notify user erasure completion.
	 *
	 * @param string $to_email Recipient email.
	 * @param string $certificate_path Optional certificate attachment.
	 * @return void
	 */
	private function notify_erasure_completion( $to_email, $certificate_path = '' ) {

		$subject  = sprintf( '[%s] Data Erasure Completed', get_bloginfo( 'name' ) );
		$message  = "Your personal data erasure request has been completed.\n\n";
		$message .= 'If you need additional verification, reply to this message.';

		$attachments = array();
		if ( ! empty( $certificate_path ) && file_exists( $certificate_path ) ) {
			$attachments[] = $certificate_path;
		}

		wp_mail( $to_email, $subject, $message, array( 'Content-Type: text/plain; charset=UTF-8' ), $attachments );
	}

	/**
	 * Log GDPR request in dedicated table.
	 *
	 * @param int    $user_id User ID.
	 * @param string $request_type Request type.
	 * @param string $status Status.
	 * @param array  $details Request details.
	 * @param int    $completed_by Completed by user.
	 * @param string $requested_at Custom request timestamp.
	 * @return void
	 */
	private function log_gdpr_request( $user_id, $request_type, $status = 'pending', $details = array(), $completed_by = 0, $requested_at = '' ) {

		global $wpdb;

		$table_name = $wpdb->prefix . self::GDPR_REQUESTS_TABLE;
		if ( ! $this->table_exists( $table_name ) ) {
			return;
		}

		$now = current_time( 'mysql' );
		$wpdb->insert(
			$table_name,
			array(
				'user_id'      => absint( $user_id ),
				'request_type' => sanitize_key( $request_type ),
				'requested_at' => ! empty( $requested_at ) ? sanitize_text_field( $requested_at ) : $now,
				'completed_at' => ( 'completed' === $status ) ? $now : null,
				'completed_by' => absint( $completed_by ),
				'status'       => sanitize_key( $status ),
				'details'      => wp_json_encode( $details ),
			)
		);
	}

	/**
	 * Get recent GDPR requests for admin UI.
	 *
	 * @param int $limit Row limit.
	 * @return array
	 */
	public function get_recent_gdpr_requests( $limit = 50 ) {

		global $wpdb;

		$table_name = $wpdb->prefix . self::GDPR_REQUESTS_TABLE;
		if ( ! $this->table_exists( $table_name ) ) {
			return array();
		}

		$limit = max( 1, absint( $limit ) );
		return $wpdb->get_results(
			"SELECT * FROM {$this->escape_identifier( $table_name )}
			ORDER BY requested_at DESC
			LIMIT {$limit}",
			ARRAY_A
		);
	}
	/*
	 * =========================================================================
	 * REPORT GENERATION
	 * =========================================================================
	 */

	/**
	 * Generate a comprehensive security audit report.
	 *
	 * @return array Report data.
	 */
	public function generate_report() {
		$settings = $this->get_settings();
		$report   = array(
			'id'           => uniqid( 'report_' ),
			'generated_at' => current_time( 'mysql' ),
			'site_url'     => home_url(),
			'site_name'    => get_bloginfo( 'name' ),
			'wp_version'   => get_bloginfo( 'version' ),
			'php_version'  => PHP_VERSION,
			'sections'     => array(),
			'summary'      => array(
				'total_checks' => 0,
				'passed'       => 0,
				'failed'       => 0,
				'warnings'     => 0,
				'score'        => 0,
				'grade'        => 'F',
			),
		);

		// Run compliance checks.
		$total_weight  = 0;
		$earned_weight = 0;

		foreach ( $this->compliance_checks as $category_key => $category ) {
			$section = array(
				'name'   => $category['name'],
				'checks' => array(),
				'passed' => 0,
				'failed' => 0,
			);

			foreach ( $category['checks'] as $check_key => $check ) {
				$passed = call_user_func( $check['check'] );
				$weight = $this->get_weight_value( $check['weight'] );

				$total_weight += $weight;
				if ( $passed ) {
					$earned_weight += $weight;
					++$section['passed'];
					++$report['summary']['passed'];
				} else {
					++$section['failed'];
					if ( $check['weight'] === 'critical' ) {
						++$report['summary']['failed'];
					} else {
						++$report['summary']['warnings'];
					}
				}

				$section['checks'][] = array(
					'name'        => $check['name'],
					'description' => $check['description'],
					'passed'      => $passed,
					'weight'      => $check['weight'],
				);

				++$report['summary']['total_checks'];
			}

			$report['sections'][ $category_key ] = $section;
		}

		// Calculate score.
		if ( $total_weight > 0 ) {
			$report['summary']['score'] = round( ( $earned_weight / $total_weight ) * 100 );
		}
		$report['summary']['grade'] = $this->score_to_grade( $report['summary']['score'] );

		// Add threat summary if enabled.
		if ( ! empty( $settings['include_threats'] ) ) {
			$report['threats'] = $this->get_threat_summary();
		}

		// Add performance metrics if enabled.
		if ( ! empty( $settings['include_performance'] ) ) {
				$report['performance'] = $this->get_performance_metrics();
		}

		// Add GDPR data map section when enabled.
		if ( ! empty( $settings['include_gdpr'] ) ) {
			$report['data_map'] = $this->generate_data_map_report( 'array' );
		}

		// Save report.
		$this->save_report( $report );
		$this->save_structured_report( $report['id'], 'security_audit', $report, (int) ( $report['summary']['score'] ?? 0 ) );

		return $report;
	}
	/**
	 * Get weight value for scoring.
	 *
	 * @param string $weight Weight level.
	 * @return int
	 */
	private function get_weight_value( $weight ) {
		switch ( $weight ) {
			case 'critical':
				return 15;
			case 'high':
				return 10;
			case 'medium':
				return 5;
			default:
				return 3;
		}
	}

	/**
	 * Convert score to grade.
	 *
	 * @param int $score Score.
	 * @return string Grade.
	 */
	private function score_to_grade( $score ) {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 80 ) {
			return 'B';
		}
		if ( $score >= 70 ) {
			return 'C';
		}
		if ( $score >= 60 ) {
			return 'D';
		}
		return 'F';
	}

	/**
	 * Get threat summary from AI detection.
	 *
	 * @return array
	 */
	private function get_threat_summary() {

		global $wpdb;
		$table        = $wpdb->prefix . 'nexifymy_behavior_log';
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) === $table;

		if ( ! $table_exists ) {
			return array( 'available' => false );
		}

		$last_30_days = $wpdb->get_row(
			"SELECT 
				COUNT(*) as total_requests,
				SUM(CASE WHEN threat_score >= 75 THEN 1 ELSE 0 END) as high_threats,
				SUM(CASE WHEN threat_score >= 50 AND threat_score < 75 THEN 1 ELSE 0 END) as medium_threats,
				SUM(CASE WHEN is_login_attempt = 1 AND is_successful = 0 THEN 1 ELSE 0 END) as failed_logins
			FROM {$table}
			WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)",
			ARRAY_A
		);

		$summary = array(
			'available'      => true,
			'period'         => '30 days',
			'total_requests' => (int) ( $last_30_days['total_requests'] ?? 0 ),
			'high_threats'   => (int) ( $last_30_days['high_threats'] ?? 0 ),
			'medium_threats' => (int) ( $last_30_days['medium_threats'] ?? 0 ),
			'failed_logins'  => (int) ( $last_30_days['failed_logins'] ?? 0 ),
		);

		if (
			isset( $GLOBALS['nexifymy_predictive_hunting'] )
			&& is_object( $GLOBALS['nexifymy_predictive_hunting'] )
			&& method_exists( $GLOBALS['nexifymy_predictive_hunting'], 'get_compliance_snapshot' )
		) {
			$predictive_snapshot = $GLOBALS['nexifymy_predictive_hunting']->get_compliance_snapshot();
			if ( is_array( $predictive_snapshot ) ) {
				$summary['forecast']          = $predictive_snapshot;
				$summary['latest_simulation'] = $predictive_snapshot['latest_simulation'] ?? array();
			}
		}

		return $summary;
	}
	/**
	 * Get performance metrics.
	 *
	 * @return array
	 */
	private function get_performance_metrics() {
		$stats = get_option( 'nexifymy_performance_stats', array() );

		return array(
			'avg_response_time' => round( $stats['avg_time_ms'] ?? 0, 2 ) . 'ms',
			'avg_memory_usage'  => round( ( $stats['avg_memory_kb'] ?? 0 ) / 1024, 2 ) . 'MB',
			'requests_tracked'  => $stats['requests_tracked'] ?? 0,
		);
	}

	/**
	 * Get absolute reports directory path.
	 *
	 * @return string
	 */
	private function get_reports_directory() {
		$upload_dir = wp_upload_dir();
		return trailingslashit( $upload_dir['basedir'] ) . self::REPORTS_DIR;
	}

	/**
	 * Generate unguessable report filename.
	 *
	 * @param string $prefix Filename prefix.
	 * @param string $extension File extension.
	 * @return string
	 */
	private function generate_secure_report_filename( $prefix, $extension ) {
		$prefix    = sanitize_file_name( (string) $prefix );
		$extension = ltrim( sanitize_key( (string) $extension ), '.' );
		$token     = strtolower( wp_generate_password( 16, false, false ) );
		return sprintf( '%1$s-%2$s-%3$s.%4$s', $prefix, gmdate( 'YmdHis' ), $token, $extension );
	}

	/**
	 * Build authenticated admin-ajax download URL.
	 *
	 * @param array $args URL arguments.
	 * @return string
	 */
	private function build_authenticated_report_url( $args = array() ) {
		$args = wp_parse_args(
			(array) $args,
			array(
				'action'   => 'nexifymy_download_report',
				'nonce'    => wp_create_nonce( 'nexifymy_security_nonce' ),
				'download' => 1,
			)
		);

		return add_query_arg( $args, admin_url( 'admin-ajax.php' ) );
	}

	/**
	 * Resolve a report filename to a safe absolute path.
	 *
	 * @param string $filename Filename to resolve.
	 * @return string
	 */
	private function get_report_filepath( $filename ) {
		$filename = sanitize_file_name( (string) $filename );
		if ( '' === $filename ) {
			return '';
		}
		$extension = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( ! in_array( $extension, array( 'html', 'json', 'pdf' ), true ) ) {
			return '';
		}

		$reports_dir = $this->get_reports_directory();
		$filepath    = trailingslashit( $reports_dir ) . $filename;
		if ( ! file_exists( $filepath ) ) {
			return '';
		}

		$real_dir  = realpath( $reports_dir );
		$real_file = realpath( $filepath );
		if ( false === $real_dir || false === $real_file ) {
			return '';
		}

		$real_dir  = trailingslashit( wp_normalize_path( $real_dir ) );
		$real_file = wp_normalize_path( $real_file );
		if ( 0 !== strpos( $real_file, $real_dir ) ) {
			return '';
		}

		return $real_file;
	}

	/**
	 * Stream report file to browser.
	 *
	 * @param string $filepath Absolute file path.
	 * @return void
	 */
	private function stream_report_file( $filepath ) {
		$filepath = (string) $filepath;
		if ( '' === $filepath || ! file_exists( $filepath ) ) {
			wp_die( esc_html__( 'Report file not found.', 'nexifymy-security' ), 404 );
		}

		$filename = basename( $filepath );
		$mime     = 'text/html';
		if ( function_exists( 'mime_content_type' ) ) {
			$detected = mime_content_type( $filepath );
			if ( is_string( $detected ) && '' !== $detected ) {
				$mime = $detected;
			}
		} elseif ( function_exists( 'wp_check_filetype' ) ) {
			$type = wp_check_filetype( $filename );
			if ( ! empty( $type['type'] ) ) {
				$mime = $type['type'];
			}
		}

		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Content-Description: File Transfer' );
		header( 'Content-Type: ' . $mime );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . filesize( $filepath ) );
		readfile( $filepath );
		exit;
	}

	/**
	 * Save report to file and database.
	 *
	 * @param array $report Report data.
	 */
	private function save_report( $report ) {

		$reports_dir = $this->get_reports_directory();

		if ( ! $this->ensure_reports_directory_security( $reports_dir ) ) {
			return;
		}
		$filename = $this->generate_secure_report_filename( 'security-audit', 'html' );
		$filepath = trailingslashit( $reports_dir ) . $filename;

		// Generate HTML report.
		$html = $this->generate_html_report( $report );
		file_put_contents( $filepath, $html );

		// Store report metadata.
		$reports                  = get_option( self::REPORTS_OPTION, array() );
		$reports[ $report['id'] ] = array(
			'id'           => $report['id'],
			'filename'     => $filename,
			'generated_at' => $report['generated_at'],
			'score'        => $report['summary']['score'],
			'grade'        => $report['summary']['grade'],
		);

		// Keep last 50 reports.
		if ( count( $reports ) > 50 ) {
			$reports = array_slice( $reports, -50, 50, true );
		}

		update_option( self::REPORTS_OPTION, $reports, false );
		// Email if enabled.
		$settings = $this->get_settings();
		if ( ! empty( $settings['email_reports'] ) ) {
			$this->email_report( $report, $filepath );
		}
	}

	/**
	 * Ensure report directory exists and includes basic deny guards.
	 *
	 * @param string $reports_dir Reports directory absolute path.
	 * @return bool
	 */
	private function ensure_reports_directory_security( $reports_dir ) {

		$reports_dir = (string) $reports_dir;
		if ( '' === $reports_dir ) {
			return false;
		}

		if ( ! is_dir( $reports_dir ) && ! wp_mkdir_p( $reports_dir ) ) {
			return false;
		}

		$htaccess_path   = trailingslashit( $reports_dir ) . '.htaccess';
		$web_config_path = trailingslashit( $reports_dir ) . 'web.config';
		$index_path      = trailingslashit( $reports_dir ) . 'index.php';

		if ( ! file_exists( $htaccess_path ) ) {
			file_put_contents( $htaccess_path, "Deny from all\n" );
		}
		if ( ! file_exists( $web_config_path ) ) {
			$web_config = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n\t<system.webServer>\n\t\t<authorization>\n\t\t\t<deny users=\"*\" />\n\t\t</authorization>\n\t</system.webServer>\n</configuration>\n";
			file_put_contents( $web_config_path, $web_config );
		}
		if ( ! file_exists( $index_path ) ) {
			file_put_contents( $index_path, "<?php // Silence is golden\n" );
		}

		return true;
	}
	/**
	 * Generate HTML report.
	 *
	 * @param array $report Report data.
	 * @return string HTML content.
	 */
	private function generate_html_report( $report ) {
		$compliance_css_url = esc_url( NEXIFYMY_SECURITY_URL . 'assets/css/compliance-report.css' );
		ob_start();
		?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Audit Report - <?php echo esc_html( $report['site_name'] ); ?></title>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
	<link rel="stylesheet" href="<?php echo $compliance_css_url; ?>">
</head>
<body>
	<div class="container">
		<div class="header">
			<h1><i class="fas fa-shield-alt"></i> Security Audit Report</h1>
			<p><?php echo esc_html( $report['site_name'] ); ?> — <?php echo esc_html( $report['site_url'] ); ?></p>
			<p class="generated-at">Generated: <?php echo esc_html( $report['generated_at'] ); ?></p>
		</div>
		
		<div class="content">
			<div class="score-card">
				<div class="grade grade-<?php echo esc_attr( strtolower( $report['summary']['grade'] ) ); ?>"><?php echo esc_html( $report['summary']['grade'] ); ?></div>
				<div class="score-details">
					<h2>Security Score: <?php echo esc_html( $report['summary']['score'] ); ?>%</h2>
					<p>Based on <?php echo esc_html( $report['summary']['total_checks'] ); ?> compliance and security checks.</p>
					<div class="stats">
						<div class="stat">
							<div class="stat-value stat-value-pass"><?php echo esc_html( $report['summary']['passed'] ); ?></div>
							<div class="stat-label">Passed</div>
						</div>
						<div class="stat">
							<div class="stat-value stat-value-fail"><?php echo esc_html( $report['summary']['failed'] ); ?></div>
							<div class="stat-label">Critical</div>
						</div>
						<div class="stat">
							<div class="stat-value stat-value-warning"><?php echo esc_html( $report['summary']['warnings'] ); ?></div>
							<div class="stat-label">Warnings</div>
						</div>
					</div>
				</div>
			</div>

			<?php foreach ( $report['sections'] as $section ) : ?>
			<div class="section">
				<h3><?php echo esc_html( $section['name'] ); ?> (<?php echo esc_html( $section['passed'] ); ?>/<?php echo esc_html( $section['passed'] + $section['failed'] ); ?>)</h3>
				<ul class="check-list">
					<?php foreach ( $section['checks'] as $check ) : ?>
					<li class="check-item">
						<div class="check-status <?php echo $check['passed'] ? 'pass' : 'fail'; ?>">
							<?php echo $check['passed'] ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>'; ?>
						</div>
						<div class="check-info">
							<h4>
								<?php echo esc_html( $check['name'] ); ?>
								<span class="weight-badge weight-<?php echo esc_attr( $check['weight'] ); ?>"><?php echo esc_html( $check['weight'] ); ?></span>
							</h4>
							<p><?php echo esc_html( $check['description'] ); ?></p>
						</div>
					</li>
					<?php endforeach; ?>
				</ul>
			</div>
			<?php endforeach; ?>

			<?php
			if ( ! empty( $report['threats']['available'] ) ) :
				?>
			<div class="section">
				<h3>Threat Summary (Last 30 Days)</h3>
				<div class="metrics">
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( number_format( $report['threats']['total_requests'] ) ); ?></div>
						<div class="metric-label">Total Requests</div>
					</div>
					<div class="metric">
						<div class="metric-value metric-value-danger"><?php echo esc_html( $report['threats']['high_threats'] ); ?></div>
						<div class="metric-label">High Threats</div>
					</div>
					<div class="metric">
						<div class="metric-value metric-value-warning"><?php echo esc_html( $report['threats']['failed_logins'] ); ?></div>
						<div class="metric-label">Failed Logins</div>
					</div>
				</div>
			</div>
			<?php endif; ?>

			<?php
			if ( ! empty( $report['threats']['forecast']['predictions'] ) ) :
				?>
			<div class="section">
				<h3>Threat Forecast (Predictive Hunting)</h3>
				<?php
				$forecast_profile     = $report['threats']['forecast']['profile'] ?? array();
				$forecast_predictions = (array) ( $report['threats']['forecast']['predictions'] ?? array() );
				$forecast_risk        = (array) ( $report['threats']['forecast']['risk_assessment'] ?? array() );
				?>
				<p>
					Site Profile:
					<strong>
						<?php
						echo esc_html(
							ucfirst( str_replace( '-', ' ', (string) ( $forecast_profile['industry'] ?? 'general' ) ) )
							. ', '
							. ucfirst( (string) ( $forecast_profile['size'] ?? 'unknown' ) )
						);
						?>
					</strong>
				</p>
				<?php
				if ( ! empty( $forecast_risk['risk_score'] ) ) :
					?>
					<p>
						Risk Score:
						<strong><?php echo esc_html( (int) $forecast_risk['risk_score'] ); ?>/100</strong>
						(<?php echo esc_html( ucfirst( (string) ( $forecast_risk['risk_level'] ?? 'unknown' ) ) ); ?>)
					</p>
				<?php endif; ?>
				<ol>
					<?php
					foreach ( array_slice( $forecast_predictions, 0, 3 ) as $prediction ) :
						?>
						<li>
							<?php
							echo esc_html(
								(string) ( $prediction['vector'] ?? 'Unknown vector' )
								. ' (' . (int) ( $prediction['probability'] ?? 0 ) . '%)'
							);
							?>
						</li>
					<?php endforeach; ?>
				</ol>
			</div>
			<?php endif; ?>

			<?php
			if ( ! empty( $report['threats']['latest_simulation']['analysis'] ) ) :
				?>
			<div class="section">
				<h3>Latest Simulated Attack Report</h3>
				<?php
				$sim_analysis = (array) ( $report['threats']['latest_simulation']['analysis'] ?? array() );
				$sim_failed   = (array) ( $sim_analysis['defenses_failed'] ?? array() );
				$sim_success  = (array) ( $sim_analysis['attacks_succeeded'] ?? array() );
				?>
				<p>Scenarios Tested: <?php echo esc_html( (int) ( $sim_analysis['total_scenarios'] ?? 0 ) ); ?></p>
				<p>Average Detection Time: <?php echo esc_html( (int) ( $sim_analysis['average_detection_time'] ?? 0 ) ); ?> ms</p>
				<p>Succeeded Attacks: <?php echo esc_html( empty( $sim_success ) ? 'None' : implode( ', ', $sim_success ) ); ?></p>
				<p>Failed Defenses: <?php echo esc_html( empty( $sim_failed ) ? 'None' : implode( ', ', $sim_failed ) ); ?></p>
			</div>
			<?php endif; ?>

			<?php
			if ( ! empty( $report['performance'] ) ) :
				?>
			<div class="section">
				<h3>Performance Metrics</h3>
				<div class="metrics">
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( $report['performance']['avg_response_time'] ); ?></div>
						<div class="metric-label">Avg Response Time</div>
					</div>
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( $report['performance']['avg_memory_usage'] ); ?></div>
						<div class="metric-label">Avg Memory Usage</div>
					</div>
					<div class="metric">
						<div class="metric-value"><?php echo esc_html( number_format( $report['performance']['requests_tracked'] ) ); ?></div>
						<div class="metric-label">Requests Tracked</div>
					</div>
				</div>
			</div>
			<?php endif; ?>

			<?php
			if ( ! empty( $report['data_map']['records'] ) ) :
				?>
			<div class="section">
				<h3>Data Map Snapshot (GDPR Article 30)</h3>
				<table class="system-table">
					<tr>
						<th class="system-cell system-cell-border">Data Element</th>
						<th class="system-cell system-cell-border">Location</th>
						<th class="system-cell system-cell-border">Legal Basis</th>
					</tr>
					<?php
					foreach ( array_slice( $report['data_map']['records'], 0, 8 ) as $data_row ) :
						?>
					<tr>
						<td class="system-cell system-cell-border"><?php echo esc_html( $data_row['data_element'] ?? '' ); ?></td>
						<td class="system-cell system-cell-border"><?php echo esc_html( $data_row['location'] ?? '' ); ?></td>
						<td class="system-cell system-cell-border"><?php echo esc_html( $data_row['legal_basis'] ?? '' ); ?></td>
					</tr>
					<?php endforeach; ?>
				</table>
			</div>
			<?php endif; ?>

			<div class="section">
				<h3>System Information</h3>
				<table class="system-table">
					<tr><td class="system-cell system-cell-border"><strong>WordPress Version</strong></td><td class="system-cell system-cell-border"><?php echo esc_html( $report['wp_version'] ); ?></td></tr>
					<tr><td class="system-cell system-cell-border"><strong>PHP Version</strong></td><td class="system-cell system-cell-border"><?php echo esc_html( $report['php_version'] ); ?></td></tr>
					<tr><td class="system-cell"><strong>Report ID</strong></td><td class="system-cell"><?php echo esc_html( $report['id'] ); ?></td></tr>
				</table>
			</div>

			<div class="footer">
				<p>Generated by NexifyMy Security</p>
				<p class="footer-note">This report is confidential and intended for security assessment purposes only.</p>
			</div>
		</div>
	</div>
</body>
</html>
		<?php
		return ob_get_clean();
	}

	/**
	 * Email report to admin.
	 *
	 * @param array  $report Report data.
	 * @param string $filepath Path to report file.
	 */
	private function email_report( $report, $filepath ) {
		$to      = get_option( 'admin_email' );
		$subject = sprintf( '[%s] Security Audit Report - Grade: %s', get_bloginfo( 'name' ), $report['summary']['grade'] );

		$message  = "Security Audit Report\n\n";
		$message .= sprintf( "Site: %s\n", $report['site_url'] );
		$message .= sprintf( "Generated: %s\n\n", $report['generated_at'] );
		$message .= sprintf( "Security Grade: %s\n", $report['summary']['grade'] );
		$message .= sprintf( "Security Score: %d%%\n\n", $report['summary']['score'] );
		$message .= sprintf(
			"Passed: %d | Critical: %d | Warnings: %d\n\n",
			$report['summary']['passed'],
			$report['summary']['failed'],
			$report['summary']['warnings']
		);
		$message .= "The full HTML report is attached to this email.\n";
		$message .= 'You can open it in any web browser or print it to PDF.';

		$headers     = array( 'Content-Type: text/plain; charset=UTF-8' );
		$attachments = array( $filepath );

		wp_mail( $to, $subject, $message, $headers, $attachments );
	}

	/**
	 * Generate scheduled report.
	 */
	public function generate_scheduled_report() {
		$this->generate_report();
	}

	/**
	 * Cleanup old reports.
	 */
	public function cleanup_old_reports() {
		$settings       = $this->get_settings();
		$retention_days = $settings['retention_days'];

		$reports_dir = $this->get_reports_directory();

		if ( ! is_dir( $reports_dir ) ) {
			return;
		}

		$cutoff = time() - ( $retention_days * DAY_IN_SECONDS );

		foreach ( array( '*.html', '*.json', '*.pdf' ) as $pattern ) {
			foreach ( glob( $reports_dir . '/' . $pattern ) as $file ) {
				if ( filemtime( $file ) < $cutoff ) {
					unlink( $file );
				}
			}
		}
	}

	/**
	 * Get all reports.
	 *
	 * @return array
	 */
	public function get_reports() {
		return get_option( self::REPORTS_OPTION, array() );
	}

	/*
	 * =========================================================================
	 * AJAX HANDLERS
	 * =========================================================================
	 */

	public function ajax_generate_report() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$report = $this->generate_report();
		wp_send_json_success( $report );
	}

	public function ajax_get_reports() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->get_reports() );
	}

	public function ajax_download_report() {
		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$is_download = isset( $_REQUEST['download'] ) && '1' === (string) sanitize_text_field( wp_unslash( $_REQUEST['download'] ) );
		$report_id   = isset( $_REQUEST['report_id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['report_id'] ) ) : '';
		$filename    = isset( $_REQUEST['filename'] ) ? sanitize_file_name( wp_unslash( $_REQUEST['filename'] ) ) : '';

		if ( '' !== $report_id ) {
			$reports = $this->get_reports();
			if ( ! isset( $reports[ $report_id ]['filename'] ) ) {
				if ( $is_download ) {
					wp_die( esc_html__( 'Report not found.', 'nexifymy-security' ), 404 );
				}
				wp_send_json_error( 'Report not found.' );
			}
			$filename = sanitize_file_name( $reports[ $report_id ]['filename'] );
		}

		$filepath = $this->get_report_filepath( $filename );

		if ( '' === $filepath ) {
			if ( $is_download ) {
				wp_die( esc_html__( 'Report file not found.', 'nexifymy-security' ), 404 );
			}
			wp_send_json_error( 'Report file not found.' );
		}

		if ( $is_download ) {
			$this->stream_report_file( $filepath );
		}

		$url_args = '' !== $report_id ? array( 'report_id' => $report_id ) : array( 'filename' => $filename );
		wp_send_json_success(
			array(
				'url' => $this->build_authenticated_report_url( $url_args ),
			)
		);
	}

	public function ajax_run_compliance_check() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$results = array();

		foreach ( $this->compliance_checks as $category_key => $category ) {
			$results[ $category_key ] = array(
				'name'   => $category['name'],
				'checks' => array(),
			);

			foreach ( $category['checks'] as $check_key => $check ) {
				$passed = call_user_func( $check['check'] );
				$results[ $category_key ]['checks'][ $check_key ] = array(
					'name'   => $check['name'],
					'passed' => $passed,
					'weight' => $check['weight'],
				);
			}
		}

		wp_send_json_success( $results );
	}

	/**
	 * AJAX: Return current data map report.
	 *
	 * @return void
	 */
	public function ajax_get_data_map() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		wp_send_json_success( $this->generate_data_map_report( 'array' ) );
	}

	/**
	 * AJAX: Export data map report.
	 *
	 * @return void
	 */
	public function ajax_export_data_map() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$format = isset( $_POST['format'] ) ? sanitize_key( wp_unslash( $_POST['format'] ) ) : 'pdf';
		if ( ! in_array( $format, array( 'pdf', 'html', 'json' ), true ) ) {
			$format = 'pdf';
		}

		$result = $this->export_data_map_report( $format );
		wp_send_json_success( $result );
	}

	/**
	 * AJAX: Handle RTBF erasure request.
	 *
	 * @return void
	 */
	public function ajax_erase_user_data() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$user_id          = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		$include_comments = ! empty( $_POST['include_comments'] );

		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid user ID.' );
		}

		$this->log_gdpr_request( $user_id, 'erasure', 'pending', array(), 0 );
		$result = $this->erase_user_data( $user_id, $include_comments );

		if ( ! empty( $result['success'] ) ) {
			wp_send_json_success( $result );
		}

		wp_send_json_error( $result['message'] ?? 'Erasure failed.' );
	}

	/**
	 * AJAX: Verify erasure status.
	 *
	 * @return void
	 */
	public function ajax_verify_erasure() {

		check_ajax_referer( 'nexifymy_security_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		if ( $user_id <= 0 ) {
			wp_send_json_error( 'Invalid user ID.' );
		}

		$verification = $this->verify_erasure( $user_id );
		wp_send_json_success( $verification );
	}
}
